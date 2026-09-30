// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include <memory>
#include <mutex>
#include <utility>
#include "bpfj/libbpf-cpp/BpfSkelBase.h"

namespace bpfj::libbpf {

// Serializes the skeleton open phase, libelf not being thread-safe.
// Out-of-line in BpfSkel.cpp so every BpfSkel<T> shares one mutex; a static
// local in the templated open() would be per-type.
std::mutex& skeletonOpenMutex() noexcept;

namespace detail {

template <typename T>
concept HasMaps = requires(T t) { t.maps; };

template <typename T>
concept HasProgs = requires(T t) { t.progs; };

template <typename T>
concept HasLinks = requires(T t) { t.links; };

template <typename T>
concept HasRodata = requires(T t) { t.rodata; };

template <typename T>
concept HasData = requires(T t) { t.data; };

template <typename T>
concept HasBss = requires(T t) { t.bss; };

} // namespace detail

template <typename Skel>
class BpfSkel final : public BpfSkelBase {
 public:
  BpfSkel() noexcept = default;

  ~BpfSkel() noexcept override {
    if (skel_) {
      destroy();
    }
  }

  BpfSkel(const BpfSkel&) = delete;

  BpfSkel& operator=(const BpfSkel&) = delete;

  void swap(BpfSkel& other) noexcept {
    std::swap(skel_, other.skel_);
  }

  BpfSkel(BpfSkel&& other) noexcept {
    swap(other);
  }
  BpfSkel& operator=(BpfSkel&& other) noexcept {
    swap(other);
    return *this;
  }

  [[nodiscard]] Expected<> open(
      const std::optional<OpenOpts>& opts = {}) noexcept override {
    const struct bpf_object_open_opts* optsPtr = nullptr;
    if (opts) {
      optsPtr = &opts->opts_;
    }

    {
      std::lock_guard<std::mutex> guard(skeletonOpenMutex());
      skel_ = Skel::open(optsPtr);
    }
    if (!skel_) {
      return makeUnexpected(Error::fromErrno("failed to open BPF skeleton"));
    }

    return unit;
  }

  [[nodiscard]] Expected<> load() noexcept override {
    if (auto error = Skel::load(skel_)) {
      return makeUnexpected(
          Error(std::errc(-error), "failed to load BPF skeleton"));
    }

    return unit;
  }

  [[nodiscard]] Expected<> openAndLoad() noexcept override {
    // open_and_load() also touches libelf (see skeletonOpenMutex). Unused
    // today, but keeps the invariant if a caller lands.
    std::lock_guard<std::mutex> guard(skeletonOpenMutex());
    if (!(skel_ = Skel::open_and_load())) {
      return makeUnexpected(
          Error::fromErrno("failed to open and load BPF skeleton"));
    }

    return unit;
  }

  [[nodiscard]] Expected<> attach() noexcept override {
    if (auto error = Skel::attach(skel_)) {
      return makeUnexpected(
          Error(std::errc(-error), "failed to attach BPF skeleton"));
    }

    return unit;
  }

  void detach() noexcept override {
    // The generated Skel::detach() dereferences its argument unconditionally,
    // so detaching a never-opened or destroyed skeleton faults. Not a race
    // guard -- skel_ is a plain pointer -- so serializing the two is the
    // caller's job; see T286128772 for the BpfHandler::stop() gap.
    if (!skel_) {
      return;
    }
    Skel::detach(skel_);
  }

  void destroy() noexcept override {
    Skel::destroy(skel_);
    skel_ = nullptr;
  }

  [[nodiscard]] static Expected<std::shared_ptr<BpfSkel>> create(
      const std::optional<OpenOpts>& opts = {}) {
    auto skel = std::make_shared<BpfSkel>();
    if (auto res = skel->open(opts); !res) {
      return makeUnexpected(res.error());
    }

    return skel;
  }

  BpfObject obj() noexcept override {
    return BpfObject(skel_->obj);
  }

  auto get() noexcept {
    return skel_;
  }

  auto skeleton() noexcept {
    return skel_->skeleton;
  }

  template <detail::HasMaps T = Skel>
  auto& maps() noexcept {
    return skel_->maps;
  }

  template <detail::HasProgs T = Skel>
  auto& progs() noexcept {
    return skel_->progs;
  }

  template <detail::HasLinks T = Skel>
  auto& links() noexcept {
    return skel_->links;
  }

  template <detail::HasRodata T = Skel>
  auto& rodata() noexcept {
    return *skel_->rodata;
  }

  template <detail::HasData T = Skel>
  auto& data() noexcept {
    return *skel_->data;
  }

  template <detail::HasBss T = Skel>
  auto& bss() noexcept {
    return *skel_->bss;
  }

 private:
  Skel* skel_ = nullptr;
};

} // namespace bpfj::libbpf

namespace std {

template <typename T>
void swap(
    bpfj::libbpf::BpfSkel<T>& lhs,
    bpfj::libbpf::BpfSkel<T>& rhs) noexcept {
  lhs.swap(rhs);
}

} // namespace std
