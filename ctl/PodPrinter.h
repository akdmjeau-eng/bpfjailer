// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <ostream>

#include "bpfj/enforce/Pods.h"

namespace bpfjailer::ctl {

/// @brief Write a pod's uuid and details to `os`, one indented field per
/// line, so `show` and `list` render a pod the same way. `nowNs` comes from
/// monotonicNs() and is what the age is measured against, and the last line
/// ends in a newline so a caller can append beneath it.
void printPod(std::ostream& os, const bpfj_pod& pod, std::int64_t nowNs);

} // namespace bpfjailer::ctl
