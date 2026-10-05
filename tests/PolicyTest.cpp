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
"/etc" = "RDONLY"
"/var/lib/svc" = "RDWR"
"/secret" = "NONE"
)toml");
  ASSERT_OK(policy);

  const auto& paths = policy->roles.at("svc").paths;
  ASSERT(paths.at("/etc") == FileMode::ReadOnly);
  ASSERT(paths.at("/var/lib/svc") == FileMode::ReadWrite);
  ASSERT(paths.at("/secret") == FileMode::None);
}

TEST(Policy, RejectsUnknownPathMode) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]

[roles.svc.paths]
"/etc" = "RDEXEC"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("expected NONE, RDONLY or RDWR") !=
      std::string::npos);
}

TEST(Policy, RejectsRecursivePathGlob) {
  auto policy = Policy::parse(R"toml([roles.svc.paths]
"/etc/**" = "RDONLY"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("uses unsupported '**'") !=
      std::string::npos);
}

TEST(Policy, RejectsPathList) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]
paths = ["/etc"]
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
"/etc" = "RDWR"
"/etc" = "RDONLY"
)toml");
  ASSERT(!policy);
}

TEST(Policy, ParsesExecPathPermissions) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.exec-paths]]
path = "/usr/bin/svc"
allow = ["exec", "set-id"]

[[roles.svc.exec-paths]]
path = "/usr/lib"
allow = ["shared-object"]
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("svc");
  ASSERT(role.hasExecPaths);
  ASSERT(role.execPaths.at("/usr/bin/svc").allowExec);
  ASSERT(role.execPaths.at("/usr/bin/svc").allowSetuid);
  ASSERT(!role.execPaths.at("/usr/bin/svc").allowSharedObject);
  ASSERT(!role.execPaths.at("/usr/lib").allowExec);
  ASSERT(role.execPaths.at("/usr/lib").allowSharedObject);
}

TEST(Policy, RejectsUnknownExecPathPermission) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.exec-paths]]
path = "/usr/bin/svc"
allow = ["jit"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("unknown permission 'jit'") !=
      std::string::npos);
}

TEST(Policy, RejectsExecPathRuleWithUnknownOption) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.exec-paths]]
path = "/usr/bin/svc"
permissions = ["exec"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("unknown option 'permissions'") !=
      std::string::npos);
}

TEST(Policy, RejectsScalarExecPathEntry) {
  auto policy = Policy::parse(
      R"toml([roles.svc]
exec-paths = {"/usr/bin/svc" = true}
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be an array of rule tables") !=
      std::string::npos);
}

TEST(Policy, RejectsBlankExecPaths) {
  auto policy = Policy::parse(R"toml([roles.svc]
exec-paths = []
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must contain at least one rule") !=
      std::string::npos);
}

TEST(Policy, RejectsRelativeExecPath) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.exec-paths]]
path = "usr/bin/svc"
allow = ["exec"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with '/'") !=
      std::string::npos);
}

TEST(Policy, RejectsRecursiveExecPathGlob) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.exec-paths]]
path = "/usr/lib/**"
allow = ["shared-object"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("uses unsupported '**'") !=
      std::string::npos);
}

TEST(Policy, RejectsSetIdWithoutExec) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.exec-paths]]
path = "/usr/bin/svc"
allow = ["set-id"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("set-id requires exec") !=
      std::string::npos);
}

TEST(Policy, RejectsDuplicateExecPath) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.exec-paths]]
path = "/usr/bin/svc"
allow = ["exec"]

[[roles.svc.exec-paths]]
path = "/usr/bin/svc"
allow = []
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("contains path '/usr/bin/svc' twice") !=
      std::string::npos);
}

TEST(Policy, ExecAnyAndExecPathsAreMutuallyExclusive) {
  auto policy = Policy::parse(
      R"toml([roles.svc]
exec-any = true

[[roles.svc.exec-paths]]
path = "/usr/bin/svc"
allow = ["exec"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find(
          "exec-any and exec-paths are mutually exclusive") !=
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

[roles.svc.mount]
"/srv/data" = ["ext4", "xfs"]
"/any-upper" = ["ANY"]
"/any-lower" = ["any"]
"/blocked" = []

[roles.svc.umount]
"/" = "NONE"
"/srv/data" = "ANY"
"/run" = "none"
"/run/service" = "any"
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("svc");
  const std::vector<std::string> expected{"ext4", "xfs"};
  ASSERT(role.mount.at("/srv/data") == expected);
  const std::vector<std::string> expectedAny{"ANY"};
  ASSERT(role.mount.at("/any-upper") == expectedAny);
  ASSERT(role.mount.at("/any-lower") == expectedAny);
  ASSERT(role.mount.at("/blocked").empty());
  ASSERT(role.hasUmount);
  ASSERT(!role.umount.at("/"));
  ASSERT(role.umount.at("/srv/data"));
  ASSERT(!role.umount.at("/run"));
  ASSERT(role.umount.at("/run/service"));
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

TEST(Policy, RejectsBooleanUmount) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]
umount = false
)toml");
  ASSERT(!policy);
  ASSERT(policy.error().message().find("must be a table") != std::string::npos);
}

TEST(Policy, RejectsRelativeUmountPath) {
  auto policy = Policy::parse(R"toml([roles.svc.umount]
relative = "ANY"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be absolute") != std::string::npos);
}

TEST(Policy, RejectsUnknownUmountPermission) {
  auto policy = Policy::parse(R"toml([roles.svc.umount]
"/srv" = "ALLOW"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("expected NONE or ANY") !=
      std::string::npos);
}

TEST(Policy, MountAndMountAnyAreMutuallyExclusive) {
  auto policy = Policy::parse(R"toml([roles.svc]
mount-any = true

[roles.svc.mount]
"/srv" = ["tmpfs"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("mutually exclusive") != std::string::npos);
}

TEST(Policy, UmountAndUmountAnyAreMutuallyExclusive) {
  auto policy = Policy::parse(R"toml([roles.svc]
umount-any = true

[roles.svc.umount]
"/srv" = "ANY"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("mutually exclusive") != std::string::npos);
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
  ASSERT(!role.mountAny);
  ASSERT(!role.umountAny);
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
  ASSERT(role.mountAny);
  ASSERT(role.umountAny);
  ASSERT_EQ(role.unixBind.at("/"), true);
  ASSERT_EQ(role.unixConnect.at("/"), true);
  ASSERT_EQ(role.unixDgram.at("/"), true);
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
exec-any = false
mount-any = false
umount-any = false
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.bpfMode == AccessMode::Deny);
  ASSERT(!role.lkmAny);
  ASSERT(!role.fsAny);
  ASSERT(!role.verityAny);
  ASSERT(!role.execAny);
  ASSERT(!role.mountAny);
  ASSERT(!role.umountAny);
}

TEST(Policy, MountPathsOverrideAny) {
  auto policy = Policy::parse(R"toml([roles.sandbox]
any = true

[roles.sandbox.mount]
"/srv/only" = ["tmpfs"]

[roles.sandbox.umount]
"/srv/only" = "ANY"
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.hasMount);
  ASSERT(!role.mountAny);
  ASSERT(role.hasUmount);
  ASSERT(!role.umountAny);
}

TEST(Policy, UnixPathRulesOverrideAny) {
  auto policy = Policy::parse(R"toml([roles.sandbox]
any = true

[roles.sandbox.unix-bind]
"/run/only" = true
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT_EQ(role.unixBind.size(), std::size_t{1});
  ASSERT_EQ(role.unixBind.at("/run/only"), true);
  ASSERT_EQ(role.unixConnect.at("/"), true);
  ASSERT_EQ(role.unixDgram.at("/"), true);
}

TEST(Policy, ExecPathsOverrideAny) {
  auto policy = Policy::parse(
      R"toml([roles.sandbox]
any = true

[[roles.sandbox.exec-paths]]
path = "/usr/bin/only"
allow = ["exec"]
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("sandbox");
  ASSERT(role.hasExecPaths);
  ASSERT(!role.execAny);
}
