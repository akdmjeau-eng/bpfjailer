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
      R"toml([roles]

[roles.svc]

[roles.svc.paths]
"/etc/**" = "RDONLY"
"/var/lib/svc/**" = "RDWR"
"/usr/bin/tool" = "RDEXEC"
"/secret" = "NONE"
)toml");
  ASSERT_OK(policy);

  const auto& paths = policy->roles.at("svc").paths;
  ASSERT(paths.at("/etc/**") == FileMode::ReadOnly);
  ASSERT(paths.at("/var/lib/svc/**") == FileMode::ReadWrite);
  ASSERT(paths.at("/usr/bin/tool") == FileMode::ReadExec);
  ASSERT(paths.at("/secret") == FileMode::None);
}

TEST(Policy, RejectsUnknownPathMode) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]

[roles.svc.paths]
"/etc/**" = "READ_MOSTLY"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("expected NONE, RDONLY, RDWR or RDEXEC") !=
      std::string::npos);
}

TEST(Policy, RejectsPathList) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]
paths = ["/etc/**"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find(
          "must be a table of path pattern to mode") != std::string::npos);
}

TEST(Policy, RejectsDuplicatePaths) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[roles.svc.paths]
"/etc/**" = "RDWR"
"/etc/**" = "RDONLY"
)toml");
  ASSERT(!policy);
}

TEST(Policy, ParsesExecPathPermissions) {
  auto policy = Policy::parse(
      R"toml([roles.svc.exec-paths."/usr/bin/svc"]
allow-exec = true
allow-setuid = false
allow-shared-object = false

[roles.svc.exec-paths."/usr/lib/**"]
allow-shared-object = true
)toml");
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
      R"toml([roles.svc.exec-paths."/usr/bin/svc"]
allow-jit = true
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("unknown option 'allow-jit'") !=
      std::string::npos);
}

TEST(Policy, RejectsNonBooleanExecPathPermission) {
  auto policy = Policy::parse(
      R"toml([roles.svc.exec-paths."/usr/bin/svc"]
allow-exec = "sometimes"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be true or false") !=
      std::string::npos);
}

TEST(Policy, RejectsScalarExecPathEntry) {
  auto policy = Policy::parse(
      R"toml([roles.svc]
exec-paths = {"/usr/bin/svc" = true}
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be a permissions table") !=
      std::string::npos);
}

TEST(Policy, RejectsBlankExecPaths) {
  auto policy = Policy::parse(R"toml([roles.svc.exec-paths]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must contain at least one path pattern") !=
      std::string::npos);
}

TEST(Policy, RejectsRelativeExecPath) {
  auto policy = Policy::parse(
      R"toml([roles.svc.exec-paths."usr/bin/svc"]
allow-exec = true
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with '/'") !=
      std::string::npos);
}

TEST(Policy, ParsesUnixSocketRules) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[roles.svc.unix-bind]
"/run/svc" = false
"@svc-*" = true

[roles.svc.unix-connect]
"/run/peer" = true

[roles.svc.unix-dgram]
"@log-${UUID}" = false
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("svc");
  ASSERT_EQ(role.unixBind.at("/run/svc"), false);
  ASSERT_EQ(role.unixBind.at("@svc-*"), true);
  ASSERT_EQ(role.unixConnect.at("/run/peer"), true);
  ASSERT_EQ(role.unixDgram.at("@log-${UUID}"), false);
}

TEST(Policy, RejectsUnixSocketRuleWithoutNameKind) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]

[roles.svc.unix-bind]
relative = false
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with '/' or '@'") !=
      std::string::npos);
}

TEST(Policy, RejectsNonBooleanUnixSocketRule) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[roles.svc.unix-connect]
"/run/svc" = "sometimes"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be true or false") !=
      std::string::npos);
}

TEST(Policy, RejectsBlankUnixSocketRule) {
  auto policy = Policy::parse("[roles.svc.unix-dgram]\n\"/dev/log\" =\n");
  ASSERT(!policy);
}

TEST(Policy, RejectsCollidingUnixRootRules) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[roles.svc.unix-bind]
"/" = false
"/*" = true
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("cannot contain both '/' and '/*'") !=
      std::string::npos);
}

TEST(Policy, ParsesMountAndUmountRules) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]
umount = false

[roles.svc.mount]
"/srv/data" = ["ext4", "xfs"]
"/blocked" = []
)toml");
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
      R"toml([roles]

[roles.svc]

[roles.svc.mount]
relative = ["tmpfs"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be an absolute path") !=
      std::string::npos);
}

TEST(Policy, RejectsScalarMountFilesystemType) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]

[roles.svc.mount]
"/run" = "tmpfs"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be an array") != std::string::npos);
}

TEST(Policy, RejectsNonBooleanUmount) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]
umount = "sometimes"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be true or false") !=
      std::string::npos);
}

TEST(Policy, RejectsCollidingMountRootRules) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[roles.svc.mount]
"/" = []
"/*" = []
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("cannot contain both '/' and '/*'") !=
      std::string::npos);
}

TEST(Policy, MissingOperationsDefaultToDeny) {
  auto policy = Policy::parse(R"toml([roles]

[roles.sandbox]
)toml");
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
  auto policy = Policy::parse(R"toml([roles]

[roles.inventory]
any = true
)toml");
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
      R"toml([roles]

[roles.sandbox]
any = true
bpf-pod = true
kill-roles = ["target"]
proc-pod = true

[roles.target]
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.bpfMode == AccessMode::Pod);
  ASSERT(role.killMode == AccessMode::Roles);
  ASSERT(role.ptraceMode == AccessMode::Any);
  ASSERT(role.procMode == AccessMode::Pod);
}

TEST(Policy, ParsesProcRolesAndAnyProc) {
  auto policy = Policy::parse(
      R"toml([roles.reader]
proc-roles = ["target"]

[roles.target]

[roles.monitor]
any-proc = true
)toml");
  ASSERT_OK(policy);

  const auto& reader = policy->roles.at("reader");
  ASSERT(reader.procMode == AccessMode::Roles);
  ASSERT_EQ(reader.proc.size(), 1);
  ASSERT_EQ(reader.proc[0], "target");
  ASSERT(policy->roles.at("monitor").procMode == AccessMode::Any);
}

TEST(Policy, ProcScopesAreMutuallyExclusive) {
  auto policy = Policy::parse(
      R"toml([roles.muddled]
any-proc = true
proc-roles = ["muddled"]
)toml");
  ASSERT(policy.hasError());
  ASSERT(
      policy.error().message().find("mutually exclusive") != std::string::npos);
}

TEST(Policy, ExplicitFalseOverridesAny) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.sandbox]
any = true
bpf-pod = false
lkm-any = false
fs-any = false
verity-any = false
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.bpfMode == AccessMode::Deny);
  ASSERT(!role.lkmAny);
  ASSERT(!role.fsAny);
  ASSERT(!role.verityAny);
}

TEST(Policy, ExecPathsOverrideAny) {
  auto policy = Policy::parse(
      R"toml([roles.sandbox]
any = true

[roles.sandbox.exec-paths."/usr/bin/only"]
allow-exec = true
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.hasExecPaths);
  ASSERT(!role.execAny);
}
