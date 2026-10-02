// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <string_view>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"

namespace bpfjailer {

/// @brief Whether `role` may be enrolled by a caller that is not root. False
/// for a role simply absent, which is the common answer; an error means the
/// arena could not be consulted at all, which the caller must refuse over
/// rather than read as a no.
[[nodiscard]] Expected<bool> unprivEnrollAllowed(
    const PinConfig& cfg,
    std::string_view role) noexcept;

} // namespace bpfjailer
