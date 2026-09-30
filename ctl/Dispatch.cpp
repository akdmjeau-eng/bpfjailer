// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/Dispatch.h"

#include <cstring>
#include <string_view>

#include "ctl/commands/Attach.h"
#include "ctl/commands/Check.h"
#include "ctl/commands/Detach.h"
#include "ctl/commands/Enroll.h"
#include "ctl/commands/List.h"
#include "ctl/commands/Replace.h"
#include "ctl/commands/Show.h"
#include "ctl/commands/Wrap.h"

namespace bpfjailer::ctl {

std::optional<int>
dispatch(int argc, char** argv, std::string_view compiledPolicy) {
  if (argc < 2) {
    return std::nullopt;
  }

  const char* cmd = argv[1];
  const int subArgc = argc - 1;
  char** subArgv = argv + 1;

  // Each `-compiled` command is its path-taking twin run against the policy
  // compiled into the binary, and the only place that policy is read.
  if (std::strcmp(cmd, "attach") == 0) {
    return attachRun(subArgc, subArgv);
  }
  if (std::strcmp(cmd, "attach-compiled") == 0) {
    return attachCompiledRun(subArgc, subArgv, compiledPolicy);
  }
  if (std::strcmp(cmd, "replace") == 0) {
    return replaceRun(subArgc, subArgv);
  }
  if (std::strcmp(cmd, "replace-compiled") == 0) {
    return replaceCompiledRun(subArgc, subArgv, compiledPolicy);
  }
  if (std::strcmp(cmd, "check") == 0) {
    return checkRun(subArgc, subArgv);
  }
  if (std::strcmp(cmd, "check-compiled") == 0) {
    return checkCompiledRun(subArgc, subArgv, compiledPolicy);
  }
  if (std::strcmp(cmd, "detach") == 0) {
    return detachRun(subArgc, subArgv);
  }
  if (std::strcmp(cmd, "enroll") == 0) {
    return enrollRun(subArgc, subArgv);
  }
  if (std::strcmp(cmd, "wrap") == 0) {
    return wrapRun(subArgc, subArgv);
  }
  if (std::strcmp(cmd, "show") == 0) {
    return showRun(subArgc, subArgv);
  }
  if (std::strcmp(cmd, "list") == 0) {
    return listRun(subArgc, subArgv);
  }
  return std::nullopt;
}

} // namespace bpfjailer::ctl
