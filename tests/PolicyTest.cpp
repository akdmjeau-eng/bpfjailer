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

[[roles.svc.paths]]
path = "/etc"
allow = "RDONLY"

[[roles.svc.paths]]
path = "/var/lib/svc"
allow = "RDWR"

[[roles.svc.paths]]
path = "/secret"
allow = "NONE"
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

[[roles.svc.paths]]
path = "/etc"
allow = "RDEXEC"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("expected NONE, RDONLY or RDWR") !=
      std::string::npos);
}

TEST(Policy, RejectsRecursivePathGlob) {
  auto policy = Policy::parse(R"toml([[roles.svc.paths]]
path = "/etc/**"
allow = "RDONLY"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("uses unsupported '**'") !=
      std::string::npos);
}

TEST(Policy, RejectsScalarPathEntry) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]
paths = {"/etc" = "RDONLY"}
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be an array of rule tables") !=
      std::string::npos);
}

TEST(Policy, RejectsDuplicatePaths) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[[roles.svc.paths]]
path = "/etc"
allow = "RDWR"

[[roles.svc.paths]]
path = "/etc"
allow = "RDONLY"
)toml");
  ASSERT(!policy);
}

TEST(Policy, AllowsDistinctRootPathRules) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.paths]]
path = "/"
allow = "NONE"

[[roles.svc.paths]]
path = "/*"
allow = "RDONLY"
)toml");
  ASSERT_OK(policy);

  const auto& paths = policy->roles.at("svc").paths;
  ASSERT(paths.at("/") == FileMode::None);
  ASSERT(paths.at("/*") == FileMode::ReadOnly);
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

TEST(Policy, AllowsDistinctRootExecPathRules) {
  auto policy = Policy::parse(
      R"toml([[roles.svc.exec-paths]]
path = "/"
allow = []

[[roles.svc.exec-paths]]
path = "/*"
allow = ["exec"]
)toml");
  ASSERT_OK(policy);

  const auto& paths = policy->roles.at("svc").execPaths;
  ASSERT(!paths.at("/").allowExec);
  ASSERT(paths.at("/*").allowExec);
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

[[roles.svc.unix-bind]]
path = "/run/svc"
allow = false

[[roles.svc.unix-bind]]
name = "@svc-*"
allow = true

[[roles.svc.unix-connect]]
path = "/run/peer"
allow = true

[[roles.svc.unix-dgram]]
name = "@log-${UUID}"
allow = false
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("svc");
  ASSERT_EQ(role.unixBind.at("/run/svc"), false);
  ASSERT_EQ(role.unixBind.at("@svc-*"), true);
  ASSERT_EQ(role.unixConnect.at("/run/peer"), true);
  ASSERT_EQ(role.unixDgram.at("@log-${UUID}"), false);
}

TEST(Policy, RejectsAbstractUnixSocketNameInPath) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]

[[roles.svc.unix-bind]]
path = "@svc"
allow = false
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with '/'") !=
      std::string::npos);
}

TEST(Policy, RejectsNonBooleanUnixSocketRule) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[[roles.svc.unix-connect]]
path = "/run/svc"
allow = "sometimes"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must be true or false") !=
      std::string::npos);
}

TEST(Policy, RejectsUnixSocketRuleWithBothPathAndName) {
  auto policy = Policy::parse(R"toml([[roles.svc.unix-bind]]
path = "/run/svc"
name = "@svc"
allow = true
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("exactly one of path or name") !=
      std::string::npos);
}

TEST(Policy, ParsesPosixNameRules) {
  auto policy = Policy::parse(R"toml(vars = ["UUID"]

[[roles.svc.mq-posix-pattern]]
name = "/svc-*"
allow = false

[[roles.svc.mq-posix-pattern]]
name = "/svc-${UUID}"
allow = true

[[roles.svc.shm-posix-pattern]]
name = "/cache-*"
allow = true
)toml");
  ASSERT_OK(policy);

  const auto& role = policy->roles.at("svc");
  ASSERT_EQ(role.mqPosixPatterns.at("/svc-*"), false);
  ASSERT_EQ(role.mqPosixPatterns.at("/svc-${UUID}"), true);
  ASSERT_EQ(role.shmPosixPatterns.at("/cache-*"), true);
}

TEST(Policy, RejectsPosixNameWithoutLeadingSlash) {
  auto policy = Policy::parse(R"toml([[roles.svc.mq-posix-pattern]]
name = "svc-*"
allow = true
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with one '/'") !=
      std::string::npos);
}

TEST(Policy, RejectsBlankUnixSocketRule) {
  auto policy =
      Policy::parse("[[roles.svc.unix-dgram]]\npath = \"/dev/log\"\nallow =\n");
  ASSERT(!policy);
}

TEST(Policy, RejectsCollidingUnixRootRules) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[[roles.svc.unix-bind]]
path = "/"
allow = false

[[roles.svc.unix-bind]]
path = "/*"
allow = true
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("cannot contain both '/' and '/*'") !=
      std::string::npos);
}

TEST(Policy, ParsesMountAndUmountRules) {
  auto policy = Policy::parse(
      R"toml([roles]

[[roles.svc.mount]]
path = "/srv/data"
allow = ["ext4", "xfs"]

[[roles.svc.mount]]
path = "/any-upper"
allow = ["ANY"]

[[roles.svc.mount]]
path = "/any-lower"
allow = ["any"]

[[roles.svc.mount]]
path = "/blocked"
allow = []

[[roles.svc.umount]]
path = "/"
allow = "NONE"

[[roles.svc.umount]]
path = "/srv/data"
allow = "ANY"

[[roles.svc.umount]]
path = "/run"
allow = "none"

[[roles.svc.umount]]
path = "/run/service"
allow = "any"
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

[[roles.svc.mount]]
path = "relative"
allow = ["tmpfs"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with '/'") !=
      std::string::npos);
}

TEST(Policy, RejectsScalarMountFilesystemType) {
  auto policy = Policy::parse(R"toml([roles]

[roles.svc]

[[roles.svc.mount]]
path = "/run"
allow = "tmpfs"
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
  ASSERT(
      policy.error().message().find("must be an array of rule tables") !=
      std::string::npos);
}

TEST(Policy, RejectsRelativeUmountPath) {
  auto policy = Policy::parse(R"toml([[roles.svc.umount]]
path = "relative"
allow = "ANY"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("must start with '/'") !=
      std::string::npos);
}

TEST(Policy, RejectsUnknownUmountPermission) {
  auto policy = Policy::parse(R"toml([[roles.svc.umount]]
path = "/srv"
allow = "ALLOW"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("expected NONE or ANY") !=
      std::string::npos);
}

TEST(Policy, MountAndMountAnyAreMutuallyExclusive) {
  auto policy = Policy::parse(R"toml([roles.svc]
mount-any = true

[[roles.svc.mount]]
path = "/srv"
allow = ["tmpfs"]
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("mutually exclusive") != std::string::npos);
}

TEST(Policy, UmountAndUmountAnyAreMutuallyExclusive) {
  auto policy = Policy::parse(R"toml([roles.svc]
umount-any = true

[[roles.svc.umount]]
path = "/srv"
allow = "ANY"
)toml");
  ASSERT(!policy);
  ASSERT(
      policy.error().message().find("mutually exclusive") != std::string::npos);
}

TEST(Policy, RejectsCollidingMountRootRules) {
  auto policy = Policy::parse(
      R"toml([roles]

[roles.svc]

[[roles.svc.mount]]
path = "/"
allow = []

[[roles.svc.mount]]
path = "/*"
allow = []
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

[[roles.sandbox.mount]]
path = "/srv/only"
allow = ["tmpfs"]

[[roles.sandbox.umount]]
path = "/srv/only"
allow = "ANY"
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

[[roles.sandbox.unix-bind]]
path = "/run/only"
allow = true
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
