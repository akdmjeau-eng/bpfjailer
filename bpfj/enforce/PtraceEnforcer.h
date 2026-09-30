// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief Loads, attaches and pins the ptrace enforcer: a role that writes
/// `ptrace` may attach only inside its own pod and to processes whose every
/// role it named, while one that does not write it is unrestricted, so the
/// rule can go on one role at a time. As with the others, the pins own the
/// programs once load() returns.
class PtraceEnforcer {
 public:
  /// @brief Load and attach the enforcer, keying it from `policy`. Expects
  /// Jailer::load() to have run first, so the jail membership maps exist and
  /// this adopts them.
  [[nodiscard]] static Expected<> load(
      const PinConfig& cfg,
      const Policy& policy) noexcept;
};

} // namespace bpfjailer
