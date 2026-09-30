// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <string_view>

namespace bpfjailer::ctl {

int attachRun(int argc, char** argv);

/// @brief `attach`, against the policy compiled into this binary. Its own
/// command rather than a mode of `attach`, so which of the two a binary
/// enforces is legible in the command it was built with, and it fails rather
/// than falling back to a path when nothing was compiled in.
int attachCompiledRun(int argc, char** argv, std::string_view builtin);

} // namespace bpfjailer::ctl
