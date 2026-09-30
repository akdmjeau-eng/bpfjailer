// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief Loads, attaches and pins the BPF object ownership enforcer: every
/// map and program a role that wrote `bpf` creates is recorded as belonging to
/// it, and opening one afterwards is checked against the opener's policy. An
/// unconfigured role may still call bpf(2), has what it creates left untracked
/// and reaches nothing another role owns, so the scheme can go on one role at
/// a time.
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
