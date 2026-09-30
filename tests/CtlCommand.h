// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace bpfjailer::test {

/// @brief What a bpfjctl command did.
struct CommandResult {
  /// The command's exit status, or -1 when it died on a signal.
  int status = 0;

  /// The signal that killed it, or 0.
  int signal = 0;

  /// False when dispatch() knew no command by that name.
  bool dispatched = true;

  std::string out;
  std::string err;

  [[nodiscard]] bool outHas(std::string_view needle) const {
    return out.find(needle) != std::string::npos;
  }

  [[nodiscard]] bool errHas(std::string_view needle) const {
    return err.find(needle) != std::string::npos;
  }

  /// @brief How many times `needle` appears in stdout, for output that lists
  /// one entry per pod.
  [[nodiscard]] std::size_t outCount(std::string_view needle) const {
    std::size_t count = 0;
    for (std::size_t at = out.find(needle); at != std::string::npos;
         at = out.find(needle, at + needle.size())) {
      ++count;
    }
    return count;
  }
};

/// @brief Run a bpfjctl command, with `args` starting at the command name,
/// through the ctl::dispatch() seam both bpfjctl and bpfjcmd use. In a child
/// of the test, because argp calls exit() on a usage error and `wrap` execs;
/// the child inherits the test's mount namespace and so its bpffs.
[[nodiscard]] CommandResult runCtl(const std::vector<std::string>& args);

/// @brief Run a command as a binary carrying `compiledPolicy`, what `make cmd
/// CMD_POLICY=...` builds, through the same dispatch() parameter bpfjcmd uses.
/// Only the `-compiled` commands read it.
[[nodiscard]] CommandResult runCtl(
    const std::vector<std::string>& args,
    std::string_view compiledPolicy);

} // namespace bpfjailer::test
