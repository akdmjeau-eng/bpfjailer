// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

namespace bpfjailer::err {

// Stand-in for folly::Unit: the value type of an Expected that carries no
// value, so `Expected<>` means "succeeded or failed" with no payload.
struct Unit {
  friend constexpr bool operator==(Unit, Unit) noexcept {
    return true;
  }

  friend constexpr bool operator!=(Unit, Unit) noexcept {
    return false;
  }
};

inline constexpr Unit unit{};

} // namespace bpfjailer::err
