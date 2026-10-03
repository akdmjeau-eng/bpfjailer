// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// Enforces per-role executable-code permissions by path.
class ExecEnforcer {
 public:
  [[nodiscard]] static Expected<> load(
      const PinConfig& cfg,
      const Policy& policy) noexcept;
};

} // namespace bpfjailer
