// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstddef>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief What a replace carried across.
struct ReplaceStats {
  std::size_t pods = 0;
  std::size_t tasks = 0;

  /// Records in the two BPF owner maps, which the new tree cannot rebuild for
  /// itself and so are copied rather than recovered.
  std::size_t owners = 0;
};

/// @brief Reload the jailer under `cfg` without releasing the tasks it jails,
/// unlike the destructive Jailer::load(): a second jailer is loaded into a
/// tree beside the running one, the membership copied across, and only then is
/// the old tree removed and the new one renamed over it. Both are attached
/// until the swap, so enforcement never lapses. With nothing attached under
/// `cfg` this amounts to Attach.
[[nodiscard]] Expected<ReplaceStats> replaceJailer(
    const PinConfig& cfg,
    const Policy& policy) noexcept;

} // namespace bpfjailer
