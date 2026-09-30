// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/libbpf-cpp/BpfHandler.h"

#include <unistd.h>
#include <iostream>

namespace bpfj::libbpf {

Expected<> BpfHandler::init() noexcept {
  return obj_->open();
}

Expected<> BpfHandler::start() {
  for (auto& rb : ringBuffers_) {
    auto res = rb->init();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  for (auto& t : timeouts_) {
    auto res = t->init();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  for (auto& f : preLoad_) {
    auto res = f();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  for (auto& rb : ringBuffers_) {
    auto res = rb->rb.load();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  for (auto& updater : mapUpdaters_) {
    auto res = updater->resize();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  if (auto res = obj_->load(); !res) {
    return makeUnexpected(res.error());
  }

  // The outer maps exist now, so the inner-template fds registered during setup
  // are done with. libbpf never closes them, so leaving them leaks one bpf-map
  // fd per map-of-maps per load.
  closePendingInnerMapFds();

  for (auto& f : preAttach_) {
    auto res = f();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  for (auto& rb : ringBuffers_) {
    auto res = rb->rb.attach();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  for (auto& updater : mapUpdaters_) {
    auto res = updater->update();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  for (auto& f : attachGuards_) {
    auto res = f();
    if (!res) {
      return makeUnexpected(res.error());
    }
  }

  if (overrideAttach_) {
    auto res = overrideAttach_();
    if (!res) {
      stop();
      return makeUnexpected(res.error());
    }
  } else {
    auto res = obj_->attach();

    if (!res) {
      stop();
      return makeUnexpected(res.error());
    }
  }

  for (auto& f : attachGuards_) {
    auto res = f();
    if (!res) {
      stop();
      return makeUnexpected(res.error());
    }
  }

  for (auto& f : postAttach_) {
    auto res = f();
    if (!res) {
      stop();
      return makeUnexpected(res.error());
    }
  }

  for (auto& f : attachGuards_) {
    auto res = f();
    if (!res) {
      stop();
      return makeUnexpected(res.error());
    }
  }

  startRunning();

  for (auto&& timeout : timeouts_) {
    timeoutThreads_.emplace_back([this, timeout]() { timeout->run(); });
  }

  for (auto& rb : ringBuffers_) {
    ringBufferThreads_.emplace_back([this, rb]() { rb->run(); });
  }

  return unit;
}

void BpfHandler::trackInnerMapFd(int fd) noexcept {
  if (fd < 0) {
    return;
  }
  pendingInnerMapFds_.push_back(fd);
}

void BpfHandler::closePendingInnerMapFds() noexcept {
  for (int fd : pendingInnerMapFds_) {
    ::close(fd);
  }
  pendingInnerMapFds_.clear();
}

void BpfHandler::stop() {
  if (isStopped_.exchange(true)) {
    return;
  }

  stopRunning();

  for (auto& rb : ringBuffers_) {
    rb->pipe_[1].write("", 1);
  }

  for (auto& t : timeouts_) {
    t->pipe_[1].write("", 1);
  }

  for (auto&& t : ringBufferThreads_) {
    t.join();
  }

  for (auto&& t : timeoutThreads_) {
    t.join();
  }

  if (overrideDetach_) {
    overrideDetach_();
  } else {
    obj_->detach();
  }
}

} // namespace bpfj::libbpf
