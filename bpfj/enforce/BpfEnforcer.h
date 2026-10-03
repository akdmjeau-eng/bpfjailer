// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief Loads, attaches and pins the BPF object ownership enforcer: every
/// map and program created by a role allowed to use bpf(2) is recorded with
/// its role and pod, and opening one afterwards is checked against the
/// opener's deny, pod, role-list or any policy.
class BpfEnforcer {
 public:
  /// @brief Load and attach the enforcer, keying it from `policy`. Attached
  /// last, because pinning a link is itself a bpf(2) call and `lsm/bpf` going
  /// live stops a caller whose role denies the syscall from pinning anything
  /// else -- the one configuration that can fail partway, which `bpfjctl
  /// unload` still clears by unlink().
  [[nodiscard]] static Expected<> load(
      const PinConfig& cfg,
      const Policy& policy) noexcept;
};

} // namespace bpfjailer
