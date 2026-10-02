// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/types.h>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/StdExpected.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

class ShmEnforcer {
 public:
  [[nodiscard]] static Expected<> load(
      const PinConfig& cfg,
      const Policy& policy) noexcept;
};

/// Publish `pid`'s /dev/shm mount to a running SHM enforcer. This is a no-op
/// when that enforcer is not attached, so every enrollment path can call it.
[[nodiscard]] Expected<> registerPosixShmMount(
    const PinConfig& cfg,
    pid_t pid) noexcept;

} // namespace bpfjailer
