// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <string_view>

namespace bpfjailer::ctl {

int replaceRun(int argc, char** argv);

/// @brief `replace`, against the policy compiled into this binary. See
/// attachCompiledRun() for why it is a command of its own.
int replaceCompiledRun(int argc, char** argv, std::string_view builtin);

} // namespace bpfjailer::ctl
