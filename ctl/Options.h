// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <argp.h>
#include <sys/types.h>

#include <string_view>

#include "bpfj/enforce/Jailer.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer::ctl {

enum PinOptionKey {
  kBpffsPathKey = 'b',
  kPinDirKey = 'p',
};

// The flags every subcommand takes, zero-terminated so argp can take it as a
// complete option table.
extern const struct argp_option kPinOptions[];

/// @brief Apply one shared pin flag to `cfg`.
/// @return ARGP_ERR_UNKNOWN for keys the shared flags do not own.
error_t parsePinOpt(int key, const char* arg, PinConfig& cfg);

/// @brief Parse a positional PID argument, reporting an error rather than
/// going through argp_usage(), which would only restate the usage line.
[[nodiscard]] Expected<pid_t> parsePid(const char* arg) noexcept;

/// @brief Parse a command whose only arguments are the shared pin flags,
/// exiting through argp_usage() on a positional; `doc` is the one-line
/// description the command shows for --help.
void parsePinOnly(int argc, char** argv, const char* doc, PinConfig& cfg);

/// @brief How the `-compiled` commands name their policy in their output.
inline constexpr std::string_view kCompiledSource = "the compiled-in policy";

/// @brief Parse the policy compiled into this binary, which unlike one read
/// from a path falls under the fs-verity digest the signature is taken over --
/// signing a command that names /etc/bpfj/policy.toml fixes the path and not
/// its contents. The `-compiled` commands take no path, so an empty `builtin`
/// is an error rather than a fallback to one.
[[nodiscard]] Expected<Policy> compiledPolicy(
    std::string_view builtin) noexcept;

} // namespace bpfjailer::ctl
