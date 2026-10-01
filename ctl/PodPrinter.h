// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <ostream>
#include <span>
#include <string>
#include <vector>

#include "bpfj/enforce/Pins.h"
#include "bpfj/enforce/Pods.h"

namespace bpfjailer::ctl {

/// @brief Write a pod's uuid and details to `os`, one indented field per
/// line, so `show` and `list` render a pod the same way. `nowNs` comes from
/// monotonicNs() and is what the age is measured against, and the last line
/// ends in a newline so a caller can append beneath it. `varNames` is what
/// jailVarNames() read, and a variable it has no name for prints by id.
void printPod(
    std::ostream& os,
    const bpfj_pod& pod,
    std::int64_t nowNs,
    std::span<const std::string> varNames);

/// @brief The running jail's variable names indexed by id, or empty when they
/// cannot be read, which printPod() survives by printing ids.
[[nodiscard]] std::vector<std::string> jailVarNames(
    const PinConfig& cfg) noexcept;

} // namespace bpfjailer::ctl
