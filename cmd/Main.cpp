// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <array>
#include <cstddef>
#include <iostream>
#include <iterator>

#include "cmd/Args.h"
#include "cmd/Policy.h"
#include "ctl/Dispatch.h"

const char* argp_program_version = "bpfjcmd 0.1";

// bpfjcmd runs one command, fixed at build time, and ignores argc and argv.
// The command sits in the binary's rodata, so it falls under the fs-verity
// digest the signature is taken over.
//
// A policy built in with CMD_POLICY sits there on the same terms, and closes
// what the command alone leaves open: signing `attach /etc/bpfj/policy.yaml`
// fixes the path and not its contents, so anyone able to write that file
// rewrites the policy -- trust store included -- against a signature that
// still verifies. Only the -compiled commands read it.
int main() {
  // argp reorders the array rather than the strings, so aiming it at the
  // generated literals is safe; one longer for argv's null terminator.
  std::array<char*, std::size(kBpfjcmdArgv) + 1> argv{};
  for (std::size_t i = 0; i < std::size(kBpfjcmdArgv); ++i) {
    argv[i] = const_cast<char*>(kBpfjcmdArgv[i]);
  }

  // sizeof less the terminator the generator appends, which is zero for a
  // build with no policy in it.
  if (auto rc = bpfjailer::ctl::dispatch(
          static_cast<int>(std::size(kBpfjcmdArgv)),
          argv.data(),
          {kBpfjcmdPolicy, sizeof(kBpfjcmdPolicy) - 1})) {
    return *rc;
  }

  std::cerr << "bpfjcmd: built with no command to run" << std::endl;
  return 1;
}
