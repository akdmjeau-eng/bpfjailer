// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string_view>

#include "tests/Harness.h"

int main(int argc, char** argv) {
  // Checked here rather than left to the first test so the whole run fails
  // with the reason rather than every test failing with EPERM. bpffs is not
  // FS_USERNS_MOUNT, so a user namespace is no way around it.
  if (::geteuid() != 0) {
    std::cerr << "bpfjtest must run as root: every test gets its own mount "
                 "namespace and a private bpffs, and neither is permitted "
                 "unprivileged."
              << std::endl;
    return 1;
  }

  int jobs = bpfjailer::test::defaultJobs();
  for (int at = 1; at < argc; ++at) {
    const std::string_view arg = argv[at];
    if (arg == "-j" && at + 1 < argc) {
      jobs = std::atoi(argv[++at]);
    } else if (arg.substr(0, 2) == "-j") {
      jobs = std::atoi(argv[at] + 2);
    } else {
      std::cerr << "usage: bpfjtest [-j jobs]\n"
                   "  -j   tests to run at once, BPFJTEST_JOBS otherwise.\n"
                   "       -j1 for the serial order, which is what to reach\n"
                   "       for when a failure might be cross-talk.\n";
      return 1;
    }
  }

  if (jobs < 1) {
    std::cerr << "bpfjtest: -j needs a positive number\n";
    return 1;
  }

  return bpfjailer::test::runAll(jobs);
}
