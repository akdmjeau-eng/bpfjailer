// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <string>

#include "bpfj/policy/Policy.h"

using bpfjailer::FileMode;
using bpfjailer::Policy;

TEST(Policy, ParsesPathModes) {
  auto policy = Policy::parse(
      "roles:\n"
      "  svc:\n"
      "    paths:\n"
      "      /etc/**: RDONLY\n"
      "      /var/lib/svc/**: RDWR\n"
      "      /usr/bin/tool: RDEXEC\n"
      "      /secret: NONE\n");
  ASSERT_OK(policy);

  const auto& paths = policy->roles.at("svc").paths;
  ASSERT(paths.at("/etc/**") == FileMode::ReadOnly);
  ASSERT(paths.at("/var/lib/svc/**") == FileMode::ReadWrite);
  ASSERT(paths.at("/usr/bin/tool") == FileMode::ReadExec);
  ASSERT(paths.at("/secret") == FileMode::None);
}

TEST(Policy, RejectsUnknownPathMode) {
  auto policy =
      Policy::parse("roles:\n  svc:\n    paths:\n      /etc/**: READ_MOSTLY\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("expected NONE, RDONLY, RDWR or RDEXEC") !=
      std::string::npos);
}

TEST(Policy, RejectsPathList) {
  auto policy = Policy::parse("roles:\n  svc:\n    paths:\n      - /etc/**\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be a map of path pattern to mode") !=
      std::string::npos);
}

TEST(Policy, RejectsDuplicatePaths) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    paths:\n      /etc/**: RDONLY\n"
      "      /etc/**: RDWR\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("contains duplicate path '/etc/**'") !=
      std::string::npos);
}
