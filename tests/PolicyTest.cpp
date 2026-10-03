// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <string>

#include "bpfj/policy/Policy.h"

using bpfjailer::AccessMode;
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

TEST(Policy, MissingOperationsDefaultToDeny) {
  auto policy = Policy::parse("roles:\n  sandbox:\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.bpfMode == AccessMode::Deny);
  ASSERT(role.killMode == AccessMode::Deny);
  ASSERT(role.ptraceMode == AccessMode::Deny);
  ASSERT(role.enrollMode == AccessMode::Deny);
  ASSERT(!role.fsAny);
  ASSERT(!role.verityAny);
  ASSERT(!role.lkmAny);
}

TEST(Policy, AnyOpensUnspecifiedOperations) {
  auto policy = Policy::parse("roles:\n  inventory:\n    any: true\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("inventory");
  ASSERT(role.bpfMode == AccessMode::Any);
  ASSERT(role.killMode == AccessMode::Any);
  ASSERT(role.ptraceMode == AccessMode::Any);
  ASSERT(role.enrollMode == AccessMode::Any);
  ASSERT(role.fsAny);
  ASSERT(role.verityAny);
  ASSERT(role.lkmAny);
}

TEST(Policy, ScopedOptionOverridesAny) {
  auto policy = Policy::parse(
      "roles:\n  sandbox:\n    any: true\n    bpf-pod: true\n"
      "    kill-roles:\n      - target\n  target:\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.bpfMode == AccessMode::Pod);
  ASSERT(role.killMode == AccessMode::Roles);
  ASSERT(role.ptraceMode == AccessMode::Any);
}

TEST(Policy, ExplicitFalseOverridesAny) {
  auto policy = Policy::parse(
      "roles:\n  sandbox:\n    any: true\n    bpf-pod: false\n"
      "    lkm-any: false\n    fs-any: false\n    verity-any: false\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.bpfMode == AccessMode::Deny);
  ASSERT(!role.lkmAny);
  ASSERT(!role.fsAny);
  ASSERT(!role.verityAny);
}
