// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <string>
#include <vector>

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

TEST(Policy, ParsesExecPathPermissions) {
  auto policy = Policy::parse(
      "roles:\n"
      "  svc:\n"
      "    exec-paths:\n"
      "      /usr/bin/svc:\n"
      "        allow-exec: true\n"
      "        allow-setuid: false\n"
      "        allow-shared-object: false\n"
      "      /usr/lib/**:\n"
      "        allow-shared-object: true\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("svc");
  ASSERT(role.hasExecPaths);
  ASSERT(role.execPaths.at("/usr/bin/svc").allowExec);
  ASSERT(!role.execPaths.at("/usr/bin/svc").allowSetuid);
  ASSERT(!role.execPaths.at("/usr/bin/svc").allowSharedObject);
  ASSERT(!role.execPaths.at("/usr/lib/**").allowExec);
  ASSERT(role.execPaths.at("/usr/lib/**").allowSharedObject);
}

TEST(Policy, RejectsUnknownExecPathPermission) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    exec-paths:\n      /usr/bin/svc:\n"
      "        allow-jit: true\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("unknown option 'allow-jit'") !=
      std::string::npos);
}

TEST(Policy, RejectsNonBooleanExecPathPermission) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    exec-paths:\n      /usr/bin/svc:\n"
      "        allow-exec: sometimes\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("neither true nor false") !=
      std::string::npos);
}

TEST(Policy, RejectsScalarExecPathEntry) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    exec-paths:\n      /usr/bin/svc: true\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be a permissions map") !=
      std::string::npos);
}

TEST(Policy, RejectsBlankExecPaths) {
  auto policy = Policy::parse("roles:\n  svc:\n    exec-paths:\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must contain at least one path pattern") !=
      std::string::npos);
}

TEST(Policy, RejectsRelativeExecPath) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    exec-paths:\n      usr/bin/svc:\n"
      "        allow-exec: true\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with '/'") !=
      std::string::npos);
}

TEST(Policy, ParsesUnixSocketRules) {
  auto policy = Policy::parse(
      "roles:\n"
      "  svc:\n"
      "    unix-bind:\n"
      "      /run/svc: false\n"
      "      '@svc-*': true\n"
      "    unix-connect:\n"
      "      /run/peer: true\n"
      "    unix-dgram:\n"
      "      '@log-${UUID}': false\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("svc");
  ASSERT_EQ(role.unixBind.at("/run/svc"), false);
  ASSERT_EQ(role.unixBind.at("@svc-*"), true);
  ASSERT_EQ(role.unixConnect.at("/run/peer"), true);
  ASSERT_EQ(role.unixDgram.at("@log-${UUID}"), false);
}

TEST(Policy, RejectsUnixSocketRuleWithoutNameKind) {
  auto policy =
      Policy::parse("roles:\n  svc:\n    unix-bind:\n      relative: false\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with '/' or '@'") !=
      std::string::npos);
}

TEST(Policy, RejectsNonBooleanUnixSocketRule) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    unix-connect:\n      /run/svc: sometimes\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("neither true nor false") !=
      std::string::npos);
}

TEST(Policy, RejectsBlankUnixSocketRule) {
  auto policy =
      Policy::parse("roles:\n  svc:\n    unix-dgram:\n      /dev/log:\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be true or false") !=
      std::string::npos);
}

TEST(Policy, RejectsCollidingUnixRootRules) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    unix-bind:\n      '/': false\n      '/*': true\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("cannot contain both '/' and '/*'") !=
      std::string::npos);
}

TEST(Policy, ParsesMountAndUmountRules) {
  auto policy = Policy::parse(
      "roles:\n"
      "  svc:\n"
      "    mount:\n"
      "      /srv/data:\n"
      "        - ext4\n"
      "        - xfs\n"
      "      /blocked: []\n"
      "    umount: false\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("svc");
  const std::vector<std::string> expected{"ext4", "xfs"};
  ASSERT(role.mount.at("/srv/data") == expected);
  ASSERT(role.mount.at("/blocked").empty());
  ASSERT(role.hasUmount);
  ASSERT(!role.umount);
}

TEST(Policy, RejectsRelativeMountDestination) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    mount:\n      relative:\n        - tmpfs\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be an absolute path") !=
      std::string::npos);
}

TEST(Policy, RejectsScalarMountFilesystemType) {
  auto policy =
      Policy::parse("roles:\n  svc:\n    mount:\n      /run: tmpfs\n");
  ASSERT(!policy);
  ASSERT(policy.error().message().find("must be a list") != std::string::npos);
}

TEST(Policy, RejectsNonBooleanUmount) {
  auto policy = Policy::parse("roles:\n  svc:\n    umount: sometimes\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("neither true nor false") !=
      std::string::npos);
}

TEST(Policy, RejectsCollidingMountRootRules) {
  auto policy = Policy::parse(
      "roles:\n  svc:\n    mount:\n      '/': []\n      '/*': []\n");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("cannot contain both '/' and '/*'") !=
      std::string::npos);
}

TEST(Policy, MissingOperationsDefaultToDeny) {
  auto policy = Policy::parse("roles:\n  sandbox:\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.bpfMode == AccessMode::Deny);
  ASSERT(role.killMode == AccessMode::Deny);
  ASSERT(role.ptraceMode == AccessMode::Deny);
  ASSERT(role.procMode == AccessMode::Deny);
  ASSERT(role.enrollMode == AccessMode::Deny);
  ASSERT(!role.fsAny);
  ASSERT(!role.verityAny);
  ASSERT(!role.execAny);
  ASSERT(!role.lkmAny);
}

TEST(Policy, AnyOpensUnspecifiedOperations) {
  auto policy = Policy::parse("roles:\n  inventory:\n    any: true\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("inventory");
  ASSERT(role.bpfMode == AccessMode::Any);
  ASSERT(role.killMode == AccessMode::Any);
  ASSERT(role.ptraceMode == AccessMode::Any);
  ASSERT(role.procMode == AccessMode::Any);
  ASSERT(role.enrollMode == AccessMode::Any);
  ASSERT(role.fsAny);
  ASSERT(role.verityAny);
  ASSERT(role.execAny);
  ASSERT(role.lkmAny);
}

TEST(Policy, ScopedOptionOverridesAny) {
  auto policy = Policy::parse(
      "roles:\n  sandbox:\n    any: true\n    bpf-pod: true\n"
      "    kill-roles:\n      - target\n    proc-pod: true\n  target:\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.bpfMode == AccessMode::Pod);
  ASSERT(role.killMode == AccessMode::Roles);
  ASSERT(role.ptraceMode == AccessMode::Any);
  ASSERT(role.procMode == AccessMode::Pod);
}

TEST(Policy, ParsesProcRolesAndAnyProc) {
  auto policy = Policy::parse(
      "roles:\n  reader:\n    proc-roles:\n      - target\n"
      "  target:\n  monitor:\n    any-proc: true\n");
  ASSERT_OK(policy);

  const auto& reader = policy->roles.at("reader");
  ASSERT(reader.procMode == AccessMode::Roles);
  ASSERT_EQ(reader.proc.size(), 1);
  ASSERT_EQ(reader.proc[0], "target");
  ASSERT(policy->roles.at("monitor").procMode == AccessMode::Any);
}

TEST(Policy, ProcScopesAreMutuallyExclusive) {
  auto policy = Policy::parse(
      "roles:\n  muddled:\n    any-proc: true\n    proc-roles:\n"
      "      - muddled\n");
  ASSERT(policy.hasError());
  ASSERT(
      policy.error().message().find("mutually exclusive") != std::string::npos);
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

TEST(Policy, ExecPathsOverrideAny) {
  auto policy = Policy::parse(
      "roles:\n  sandbox:\n    any: true\n    exec-paths:\n"
      "      /usr/bin/only:\n        allow-exec: true\n");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.hasExecPaths);
  ASSERT(!role.execAny);
}
