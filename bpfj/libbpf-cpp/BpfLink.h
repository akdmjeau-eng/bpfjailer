// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <unistd.h>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpfj/libbpf-cpp/Err.h"
#include "bpfj/libbpf-cpp/Util.h"

namespace bpfj::libbpf {

class BpfProgram;

class BpfLink {
 public:
  explicit BpfLink(struct bpf_link* link, bool takeOwnership = false) noexcept
      : link_(link), takeOwnership_(takeOwnership) {}

  ~BpfLink() noexcept {
    if (link_ && takeOwnership_) {
      ::bpf_link__destroy(link_);
    }
  }

  BpfLink(const BpfLink&) = delete;
  BpfLink& operator=(const BpfLink&) = delete;

  void swap(BpfLink& other) noexcept {
    std::swap(link_, other.link_);
  }

  BpfLink(BpfLink&& other) noexcept {
    swap(other);
  }

  BpfLink& operator=(BpfLink&& other) noexcept {
    swap(other);
    return *this;
  }

  struct bpf_link* get() const noexcept {
    return link_;
  }

  static BpfLink open(const char* path) noexcept {
    return BpfLink(::bpf_link__open(path));
  }

  int fd() noexcept {
    return ::bpf_link__fd(link_);
  }

  const char* pinPath() noexcept {
    return ::bpf_link__pin_path(link_);
  }

  [[nodiscard]] Expected<> pin(const char* path) noexcept {
    return detail::call("failed to pin BPF link", ::bpf_link__pin, link_, path);
  }

  [[nodiscard]] Expected<> unpin() noexcept {
    return detail::call("failed to unpin BPF link", ::bpf_link__unpin, link_);
  }

  void disconnect() noexcept {
    ::bpf_link__disconnect(link_);
  }

  [[nodiscard]] Expected<> detach() noexcept {
    return detail::call("failed to detach BPF link", ::bpf_link__detach, link_);
  }

  [[nodiscard]] Expected<> destroy() noexcept {
    auto ret =
        detail::call("failed to destroy BPF link", ::bpf_link__destroy, link_);
    link_ = nullptr;
    return ret;
  }

  [[nodiscard]] Expected<std::vector<char>> iter() noexcept {
    auto fd = ::bpf_iter_create(this->fd());
    if (fd < 0) {
      return makeUnexpected(
          Error(std::errc(-fd), "failed to create BPF iterator"));
    }

    auto result = detail::drainBpfIter(
        [fd](char* buf, size_t len) { return ::read(fd, buf, len); });

    ::close(fd);

    return result;
  }

 private:
  struct bpf_link* link_ = nullptr;
  bool takeOwnership_ = false;
};

} // namespace bpfj::libbpf

namespace std {

inline void swap(
    bpfj::libbpf::BpfLink& lhs,
    bpfj::libbpf::BpfLink& rhs) noexcept {
  lhs.swap(rhs);
}

} // namespace std
