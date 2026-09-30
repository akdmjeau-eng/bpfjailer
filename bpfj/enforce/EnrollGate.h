// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/types.h>

#include <string_view>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"

namespace bpfjailer {

/// @brief Whether `pid` may add a pod of `role` to the ones it already holds:
/// its roles are walked newest first, down to the first `override-stacked`
/// one, and each that wrote `enroll` has to list `role`. An error means a map
/// could not be consulted, which the caller must refuse over rather than
/// guess.
[[nodiscard]] Expected<bool> enrollPermitted(
    const PinConfig& cfg,
    pid_t pid,
    std::string_view role) noexcept;

} // namespace bpfjailer
