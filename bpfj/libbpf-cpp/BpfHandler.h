// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include "bpfj/lib/Fd.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfSkelBase.h"
#include "bpfj/libbpf-cpp/Err.h"
#include "bpfj/libbpf-cpp/RingBuffer.h"

namespace bpfj::libbpf {

class BpfHandler {
 public:
  class BpfMapUpdater {
   public:
    template <typename ResizeFunc, typename UpdateFunc>
    BpfMapUpdater(ResizeFunc&& resizeFunc, UpdateFunc&& updateFunc)
        : resizeFunc_(std::forward<ResizeFunc>(resizeFunc)),
          updateFunc_(std::forward<UpdateFunc>(updateFunc)) {}

    [[nodiscard]] Expected<> resize() noexcept {
      return resizeFunc_();
    }

    [[nodiscard]] Expected<> update() noexcept {
      return updateFunc_();
    }

   private:
    std::function<Expected<>()> resizeFunc_;
    std::function<Expected<>()> updateFunc_;
  };

  struct Timeout {
    template <typename F>
    Timeout(
        F&& f,
        std::chrono::milliseconds timeout,
        BpfHandler& handler) noexcept
        : f(std::forward<F>(f)), timeout(timeout), handler(handler) {}
    ~Timeout() noexcept = default;

    Expected<> init() noexcept {
      auto pipe = Fd::pipe();
      if (!pipe) {
        return makeUnexpected(pipe.error());
      }
      pipe_ = std::move(pipe.value());
      return unit;
    }

    Expected<> run() noexcept {
      struct pollfd pfd = {
          .fd = pipe_[0].get(),
          .events = POLLIN,
      };

      while (handler.isRunning_) {
        int ret = ::poll(&pfd, 1, timeout.count());
        if (ret < 0) {
          if (errno == EINTR) {
            continue;
          }

          return makeUnexpected(Error::fromErrno("Timeout poll failed"));
        }

        if (ret > 0) {
          break;
        }

        // Run the timeout function
        f();
      }

      return unit;
    }

    Timeout(const Timeout&) = delete;
    Timeout& operator=(const Timeout&) = delete;

    Timeout(Timeout&&) = delete;
    Timeout& operator=(Timeout&&) = delete;

    std::function<void()> f;
    std::chrono::milliseconds timeout;
    std::array<Fd, 2> pipe_{};
    BpfHandler& handler;
  };

  struct RbPoller {
    RbPoller(
        BpfMap map,
        std::size_t configured4KPages,
        RingBuffer::EventCallback&& f,
        BpfHandler& h)
        : rb(std::move(map), configured4KPages, std::move(f)), handler(h) {}

    Expected<> init() noexcept {
      auto pipe = Fd::pipe();
      if (!pipe) {
        return makeUnexpected(pipe.error());
      }
      pipe_ = std::move(pipe.value());
      return unit;
    }

    Expected<> run() noexcept {
      int fd = rb.fd();
      struct pollfd pfds[2];

      pfds[0].fd = fd;
      pfds[0].events = POLLIN;

      pfds[1].fd = pipe_[0].get();
      pfds[1].events = POLLIN;

      while (handler.isRunning_) {
        int ret = ::poll(pfds, 2, -1);
        if (ret < 0) {
          if (errno == EINTR) {
            continue;
          }

          return makeUnexpected(Error::fromErrno("poll failed"));
        }

        if (ret == 0) {
          continue;
        }

        if (pfds[0].revents & POLLIN) {
          std::lock_guard<std::mutex> g(consumeMu_);
          auto res = rb.consume();
          if (!res) {
            return makeUnexpected(res.error());
          }
        }

        if (pfds[1].revents & POLLIN) {
          break;
        }
      }

      return unit;
    }

    // Synchronously deliver any records already in the ring buffer, under
    // consumeMu_ since ring_buffer__consume is not concurrency-safe.
    Expected<> drain() noexcept {
      std::lock_guard<std::mutex> g(consumeMu_);
      auto res = rb.consume();
      if (!res) {
        return makeUnexpected(res.error());
      }
      return unit;
    }

    RingBuffer rb;
    std::array<Fd, 2> pipe_{};
    BpfHandler& handler;
    // Serializes rb.consume() between the poller thread and drain().
    std::mutex consumeMu_;
  };

  explicit BpfHandler(std::shared_ptr<BpfSkelBase> obj) noexcept
      : obj_(std::move(obj)) {}

  ~BpfHandler() noexcept {
    stop();
    closePendingInnerMapFds();
    obj_->destroy();
  }

  BpfHandler(const BpfHandler&) = delete;
  BpfHandler& operator=(const BpfHandler&) = delete;
  BpfHandler(BpfHandler&&) = delete;
  BpfHandler& operator=(BpfHandler&&) = delete;

  [[nodiscard]] Expected<> init() noexcept;
  [[nodiscard]] Expected<> start();
  void stop();

  // Register a map-of-maps inner-template fd for deferred close: libbpf
  // stores it raw and never closes it, so it stays ours until the outer map is
  // created at load().
  void trackInnerMapFd(int fd) noexcept;

  // Close every fd registered via trackInnerMapFd(), after load() succeeds and
  // again from the destructor for error and teardown paths.
  void closePendingInnerMapFds() noexcept;

  template <typename F>
  void addPreLoadFunc(F&& func) {
    preLoad_.emplace_back(std::forward<F>(func));
  }

  template <typename F>
  void addPreAttachFunc(F&& func) {
    preAttach_.emplace_back(std::forward<F>(func));
  }

  // Run immediately before and after program attach, then once more after
  // post-attach callbacks.
  template <typename F>
  void addAttachGuardFunc(F&& func) {
    attachGuards_.emplace_back(std::forward<F>(func));
  }

  template <typename F>
  void addPostAttachFunc(F&& func) {
    postAttach_.emplace_back(std::forward<F>(func));
  }

  template <typename F>
  void setOverrideAttachFunc(F&& func) {
    overrideAttach_ = std::forward<F>(func);
  }

  template <typename F>
  void setOverrideDetachFunc(F&& func) {
    overrideDetach_ = std::forward<F>(func);
  }

  template <detail::IsMap T, typename MakeKey, typename MakeVal>
  void
  setUpdater(BpfMap map, T&& cppMap, MakeKey&& makeKey, MakeVal&& makeVal) {
    auto mapSize = static_cast<std::uint32_t>(cppMap.size());
    mapUpdaters_.push_back(
        std::make_unique<BpfMapUpdater>(
            [map, mapSize]() mutable -> Expected<> {
              return map.setMaxEntries(mapSize);
            },
            [map,
             cppMap = std::forward<T>(cppMap),
             makeKey = std::forward<MakeKey>(makeKey),
             makeVal = std::forward<MakeVal>(makeVal)]() mutable -> Expected<> {
              return map.updateBatch(cppMap, makeKey, makeVal);
            }));
  }

  template <detail::IsList T, typename MakeKey, typename MakeVal>
  void
  setUpdater(BpfMap map, T&& cppSet, MakeKey&& makeKey, MakeVal&& makeVal) {
    auto setSize = static_cast<std::uint32_t>(cppSet.size());
    mapUpdaters_.push_back(
        std::make_unique<BpfMapUpdater>(
            [map, setSize]() mutable -> Expected<> {
              return map.setMaxEntries(setSize);
            },
            [map,
             cppSet = std::forward<T>(cppSet),
             makeKey = std::forward<MakeKey>(makeKey),
             makeVal = std::forward<MakeVal>(makeVal)]() mutable -> Expected<> {
              return map.updateBatch(cppSet, makeKey, makeVal);
            }));
  }

  template <typename F>
  void addTimeout(F&& f, std::chrono::milliseconds timeout) {
    timeouts_.emplace_back(
        std::make_shared<Timeout>(std::forward<F>(f), timeout, *this));
  }

  // configured4KPages is measured in 4096-byte units, not native system pages.
  template <typename F>
  void setRingBufferCallback(BpfMap map, std::size_t configured4KPages, F&& f) {
    ringBuffers_.emplace_back(
        std::make_shared<RbPoller>(
            map, configured4KPages, std::forward<F>(f), *this));
  }

  // Synchronously drain every event ring buffer into its callback, so a
  // caller can check without racing the async poller thread.
  Expected<> drainEvents() noexcept {
    for (auto& rb : ringBuffers_) {
      auto res = rb->drain();
      if (!res) {
        return makeUnexpected(res.error());
      }
    }
    return unit;
  }

  std::shared_ptr<BpfSkelBase> obj() const noexcept {
    return obj_;
  }

  bool isRunning() const noexcept {
    return isRunning_.load(std::memory_order_acquire);
  }

  void startRunning() {
    isRunning_.store(true, std::memory_order_release);
  }

  void stopRunning() {
    isRunning_.store(false, std::memory_order_release);
  }

 private:
  std::shared_ptr<BpfSkelBase> obj_;
  std::vector<std::function<Expected<>()>> preLoad_;
  std::vector<std::function<Expected<>()>> preAttach_;
  std::vector<std::function<Expected<>()>> attachGuards_;
  std::vector<std::function<Expected<>()>> postAttach_;
  std::function<Expected<>()> overrideAttach_;
  std::function<Expected<>()> overrideDetach_;
  std::vector<std::unique_ptr<BpfMapUpdater>> mapUpdaters_;
  std::atomic<bool> isRunning_{false};
  std::atomic<bool> isStopped_{false};
  std::vector<std::shared_ptr<Timeout>> timeouts_;
  std::vector<std::thread> timeoutThreads_;
  std::vector<std::shared_ptr<RbPoller>> ringBuffers_;
  std::vector<std::thread> ringBufferThreads_;

  // Inner-template fds awaiting close after load(); see trackInnerMapFd().
  std::vector<int> pendingInnerMapFds_;
};

} // namespace bpfj::libbpf
