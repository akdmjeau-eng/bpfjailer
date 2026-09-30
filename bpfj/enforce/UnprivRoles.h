// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <string_view>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief Publish the roles policy opens to unprivileged callers: one entry
/// in the pinned bpfj_unpriv_enroll_map per role carrying `unpriv-enroll:
/// true`, and the removal of any entry policy no longer names, or taking the
/// flag back out and re-attaching would leave the grant behind. Added before
/// the stale ones are dropped, so a role policy still allows is never briefly
/// missing.
[[nodiscard]] Expected<> publishUnprivRoles(
    const PinConfig& cfg,
    const Policy& policy) noexcept;

/// @brief Whether `role` may be enrolled by a caller that is not root. False
/// for a role simply absent, which is the common answer; an error means the
/// map could not be consulted at all, which the caller must refuse over rather
/// than read as a no.
[[nodiscard]] Expected<bool> unprivEnrollAllowed(
    const PinConfig& cfg,
    std::string_view role) noexcept;

} // namespace bpfjailer
