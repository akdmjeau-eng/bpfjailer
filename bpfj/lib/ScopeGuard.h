// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <type_traits>
#include <utility>

// Run something on the way out of a scope, unless told not to. Stands in for
// folly::makeGuard, covering the one way this tree uses it: a partially built
// object undoes itself unless the build reaches the end.
//
//     auto guard = makeGuard([this] { destroy(); });
//     ... anything here can return early and destroy() still runs ...
//     guard.dismiss();
namespace bpfjailer {

template <typename F>
class ScopeGuard {
 public:
  explicit ScopeGuard(F fn) noexcept : fn_(std::move(fn)) {}

  ScopeGuard(const ScopeGuard&) = delete;
  ScopeGuard& operator=(const ScopeGuard&) = delete;

  ScopeGuard(ScopeGuard&& other) noexcept
      : fn_(std::move(other.fn_)), active_(other.active_) {
    other.active_ = false;
  }
  ScopeGuard& operator=(ScopeGuard&&) = delete;

  // Unwinding out of a destructor terminates, and every use here is a cleanup
  // with nothing to report, so a throwing callable is a bug.
  ~ScopeGuard() noexcept {
    if (active_) {
      fn_();
    }
  }

  void dismiss() noexcept {
    active_ = false;
  }

 private:
  F fn_;
  bool active_ = true;
};

template <typename F>
[[nodiscard]] ScopeGuard<std::decay_t<F>> makeGuard(F&& fn) noexcept {
  return ScopeGuard<std::decay_t<F>>(std::forward<F>(fn));
}

} // namespace bpfjailer
