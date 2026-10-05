// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief Loads, attaches and pins the proc enforcer, which resolves the pid
/// named by a proc path in that mount's pid namespace before applying the
/// actor role's proc-pod, proc-roles or proc-any policy.
class ProcEnforcer {
 public:
  /// @brief Load and attach the enforcer after Jailer::load() has created the
  /// shared membership maps.
  [[nodiscard]] static Expected<> load(
      const PinConfig& cfg,
      const Policy& policy) noexcept;
};

} // namespace bpfjailer
