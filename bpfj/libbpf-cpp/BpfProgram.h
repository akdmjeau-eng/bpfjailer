// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/libbpf.h>
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/Err.h"
#include "bpfj/libbpf-cpp/Util.h"

namespace bpfj::libbpf {

class BpfProgram {
 public:
  explicit BpfProgram(struct bpf_program* prog) noexcept : prog_(prog) {}

  void swap(BpfProgram& other) noexcept {
    std::swap(prog_, other.prog_);
  }

  struct bpf_program* get() const noexcept {
    return prog_;
  }

  const char* name() const noexcept {
    return ::bpf_program__name(prog_);
  }

  const char* sectionName() const noexcept {
    return ::bpf_program__section_name(prog_);
  }

  bool autoload() const noexcept {
    return ::bpf_program__autoload(prog_);
  }

  [[nodiscard]] Expected<> setAutoload(bool autoload) noexcept {
    return detail::call(
        "failed to set autoload on BPF program",
        ::bpf_program__set_autoload,
        prog_,
        autoload);
  }

  bool autoattach() const noexcept {
    return ::bpf_program__autoattach(prog_);
  }

  void setAutoattach(bool autoattach) noexcept {
    ::bpf_program__set_autoattach(prog_, autoattach);
  }

  int fd() const noexcept {
    return ::bpf_program__fd(prog_);
  }

  [[nodiscard]] Expected<> pin(const char* path) noexcept {
    return detail::call(
        "failed to pin BPF program", ::bpf_program__pin, prog_, path);
  }

  [[nodiscard]] Expected<> unpin(const char* path) noexcept {
    return detail::call(
        "failed to unpin BPF program", ::bpf_program__unpin, prog_, path);
  }

  void unload() noexcept {
    ::bpf_program__unload(prog_);
  }

  Expected<BpfLink> attach() noexcept {
    return detail::callRet<BpfLink>(
        "failed to attach BPF program", ::bpf_program__attach, prog_);
  }

  /// @brief Attach an iterator program, narrowed by `opts`. A task iterator
  /// attached with `link_info.task.pid` set visits only that process's threads;
  /// left empty, or attached through plain attach(), it visits every task.
  Expected<BpfLink> attachIter(
      const struct bpf_iter_attach_opts* opts) noexcept {
    return detail::callRet<BpfLink>(
        "failed to attach BPF iterator",
        ::bpf_program__attach_iter,
        prog_,
        opts);
  }

  // TODO add other attach functions

 private:
  struct bpf_program* prog_;
};

} // namespace bpfj::libbpf

namespace std {

inline void swap(
    bpfj::libbpf::BpfProgram& lhs,
    bpfj::libbpf::BpfProgram& rhs) noexcept {
  lhs.swap(rhs);
}

} // namespace std
