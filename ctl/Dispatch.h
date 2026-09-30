// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <optional>
#include <string_view>

namespace bpfjailer::ctl {

/// @brief Run the subcommand named by `argv[1]`.
/// @param argc argc as `main` received it.
/// @param argv argv as `main` received it, so `argv[0]` is the program.
/// @param compiledPolicy a policy compiled into the binary, or empty; unlike
/// one read from a path it falls under the fs-verity digest the signature is
/// taken over (see compiledPolicy() in Options.h), and only the `-compiled`
/// commands read it.
/// @return the subcommand's exit status, or nullopt when there is no command
/// or it names none that exists, which the caller reports in its own terms.
std::optional<int>
dispatch(int argc, char** argv, std::string_view compiledPolicy = {});

} // namespace bpfjailer::ctl
