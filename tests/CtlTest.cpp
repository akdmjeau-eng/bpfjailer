// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/CtlCommand.h"
#include "tests/Harness.h"

#include <unistd.h>

#include <fstream>
#include <string>
#include <string_view>
#include <vector>

using bpfjailer::test::bpffsPath;
using bpfjailer::test::CommandResult;
using bpfjailer::test::exists;
using bpfjailer::test::runCtl;

namespace {

// argp's exit status for a usage error, from argp_err_exit_status.
constexpr int kUsageError = 64;

/// @brief Run a command against this test's own bpffs, the flag going right
/// after the command name so it lands ahead of `wrap`'s `--`.
[[nodiscard]] CommandResult ctl(std::vector<std::string> args) {
  args.insert(args.begin() + 1, {"--bpffs-path", bpffsPath()});
  return runCtl(args);
}

/// @brief A policy of the kind `make cmd CMD_POLICY=...` compiles in.
constexpr std::string_view kCompiledPolicy =
    "base-role: floor\nroles:\n  floor:\n  webserver:\n";

/// @brief Run a command against this test's own bpffs, as a binary carrying
/// `policy` compiled in.
[[nodiscard]] CommandResult ctlCompiled(
    std::vector<std::string> args,
    std::string_view policy = kCompiledPolicy) {
  args.insert(args.begin() + 1, {"--bpffs-path", bpffsPath()});
  return runCtl(args, policy);
}

[[nodiscard]] std::string pinRoot() {
  return bpffsPath() + "/bpfj-pins";
}

[[nodiscard]] std::string selfPid() {
  return std::to_string(::getpid());
}

/// @brief Write `body` to a policy file under the test's own bpffs and return
/// its path, so it goes with the mount namespace.
[[nodiscard]] std::string writePolicy(std::string_view body) {
  const std::string path = bpffsPath() + ".policy.yaml";
  std::ofstream out(path, std::ios::trunc);
  out << body;
  out.close();
  ASSERT(!out.fail());
  return path;
}

/// @brief Bring up a jailer in this test's bpffs, failing the test if it does
/// not come up.
void attach() {
  const CommandResult res = ctl({"attach", "/dev/null"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("Jailer attached"));
}

} // namespace

TEST(Ctl, UnknownCommandIsNotDispatched) {
  const CommandResult res = runCtl({"nonesuch"});
  ASSERT(!res.dispatched);
}

TEST(Ctl, NoCommandAtAllIsNotDispatched) {
  const CommandResult res = runCtl({});
  ASSERT(!res.dispatched);
}

TEST(Ctl, AttachPinsTheMapsAndLinks) {
  attach();

  ASSERT(exists(pinRoot() + "/maps/bpfj_pod_map"));
  ASSERT(exists(pinRoot() + "/maps/bpfj_task_map"));
  ASSERT(exists(pinRoot() + "/links/bpfj_jailer_fork"));
  ASSERT(exists(pinRoot() + "/links/bpfj_jailer_exec"));
}

TEST(Ctl, AttachNeedsAPolicyPath) {
  const CommandResult res = ctl({"attach"});
  ASSERT_EQ(res.status, kUsageError);
}

TEST(Ctl, AttachIgnoresACompiledInPolicy) {
  // `attach` reads its path and nothing else, whatever the binary carries --
  // which is the point of the compiled-in policy being a separate command.
  const std::string policy =
      writePolicy("base-role: fromfile\nroles:\n  fromfile:\n");

  const CommandResult res = ctlCompiled({"attach", policy});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("1 role(s) from " + policy));
  ASSERT(res.outHas("base role fromfile"));
}

TEST(Ctl, AttachCompiledUsesThePolicyCompiledIn) {
  const CommandResult res = ctlCompiled({"attach-compiled"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("2 role(s) from the compiled-in policy"));
  ASSERT(res.outHas("base role floor"));
  ASSERT(exists(pinRoot() + "/maps/bpfj_pod_map"));
}

TEST(Ctl, AttachCompiledTakesNoPath) {
  const std::string policy = writePolicy("roles:\n  other:\n");

  const CommandResult res = ctlCompiled({"attach-compiled", policy});
  ASSERT_EQ(res.status, kUsageError);
  ASSERT(!exists(pinRoot()));
}

TEST(Ctl, AttachCompiledWithNothingCompiledInSaysSo) {
  // What a plain bpfjctl does with it. No fallback to a path: the command
  // exists to name a policy that is under the signature.
  const CommandResult res = ctl({"attach-compiled"});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("no policy was compiled into this binary"));
  ASSERT(!exists(pinRoot()));
}

TEST(Ctl, AttachCompiledRejectsAMalformedPolicy) {
  const CommandResult res = ctlCompiled(
      {"attach-compiled"}, "roles:\n  web:\n    kill:\n      - nosuch\n");
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("which is not in roles"));
  ASSERT(!exists(pinRoot()));
}

TEST(Ctl, AttachRejectsAPathThatIsNotBpffs) {
  const CommandResult res =
      runCtl({"attach", "--bpffs-path", "/tmp", "/dev/null"});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("is not a bpffs mount"));
}

TEST(Ctl, AttachTwiceStartsFresh) {
  attach();
  ASSERT_EQ(ctl({"enroll", "dropped", "owner@meta", selfPid()}).status, 0);

  // Attach is destructive: the second tears the tree down before it loads, so
  // the first's pod does not survive.
  attach();

  const CommandResult res = ctl({"list"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("no pods"));
}

TEST(Ctl, ReplaceWithNothingAttachedActsLikeAttach) {
  const CommandResult res = ctl({"replace", "/dev/null"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("Jailer replaced"));

  ASSERT(exists(pinRoot() + "/maps/bpfj_pod_map"));
  ASSERT(exists(pinRoot() + "/links/bpfj_jailer_fork"));
  ASSERT(!exists(pinRoot() + "-new"));
}

TEST(Ctl, ReplaceKeepsAnEnrolledPod) {
  attach();
  ASSERT_EQ(ctl({"enroll", "carried", "owner@meta", selfPid()}).status, 0);

  // The pod count and not the task count beside it: bpfj_jailer_free runs on
  // task *free*, which lags runCtl's waitpid, so a helper from an earlier
  // ctl() can still be in the task map. The show below proves the rest.
  const CommandResult replaced = ctl({"replace", "/dev/null"});
  ASSERT_EQ(replaced.status, 0);
  ASSERT(replaced.outHas("carried 1 pod(s)"));

  // Membership survives, which is the whole point of the command.
  const CommandResult shown = ctl({"show", selfPid()});
  ASSERT_EQ(shown.status, 0);
  ASSERT(shown.outHas("carried"));
  ASSERT(shown.outHas("owner@meta"));

  // Refs were zeroed on the way across and counted back up. The exact number
  // moves with every process that starts or exits meanwhile; non-zero is the
  // claim, since at zero the next decrement deletes the pod.
  ASSERT(!shown.outHas("refs:    0"));
}

TEST(Ctl, ReplaceKeepsEveryEnforcerAttached) {
  attach();
  ASSERT_EQ(ctl({"replace", "/dev/null"}).status, 0);

  // A replace bringing up only the jailer and the verity enforcer would leave
  // bpf(2), signals and ptrace ungated while still looking attached.
  for (const auto* link :
       {"bpfj_jailer_fork",
        "bpfj_verity_bprm_check",
        "bpfj_kill_check",
        "bpfj_ptrace_check",
        "bpfj_bpf_syscall",
        "bpfj_bpf_map_check"}) {
    ASSERT(exists(pinRoot() + "/links/" + link));
  }

  for (const auto* map :
       {"bpfj_kill_roles",
        "bpfj_ptrace_roles",
        "bpfj_bpf_syscall_roles",
        "bpfj_bpf_map_owners"}) {
    ASSERT(exists(pinRoot() + "/maps/" + map));
  }
}

TEST(Ctl, ReplaceLeavesNoNewTree) {
  attach();

  ASSERT_EQ(ctl({"replace", "/dev/null"}).status, 0);
  ASSERT(exists(pinRoot()));
  ASSERT(!exists(pinRoot() + "-new"));
}

TEST(Ctl, ReplaceClearsATreeLeftBehindByAFailedRun) {
  attach();
  ASSERT_EQ(ctl({"enroll", "carried", "owner@meta", selfPid()}).status, 0);

  // What a replace that died before its swap leaves behind; adopting it would
  // promote a jailer holding stale maps.
  ASSERT_EQ(
      ctl({"attach", "--pin-dir", "bpfj-pins-new", "/dev/null"}).status, 0);
  ASSERT(exists(pinRoot() + "-new"));

  // Pod count only, for the reason ReplaceKeepsAnEnrolledPod gives.
  const CommandResult res = ctl({"replace", "/dev/null"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("carried 1 pod(s)"));
  ASSERT(!exists(pinRoot() + "-new"));
}

TEST(Ctl, ReplaceMergesCarriedPodsOntoTheNewBaseRole) {
  const std::string policy =
      writePolicy("base-role: floor\nroles:\n  floor:\n");

  const CommandResult attached = ctl({"attach", policy});
  ASSERT_EQ(attached.status, 0);

  ASSERT_EQ(ctl({"enroll", "carried", "owner@meta", selfPid()}).status, 0);

  // The new tree seeds its base role before the backfill runs, so the carried
  // pod has to land alongside the one already in the entry.
  const CommandResult replaced = ctl({"replace", policy});
  ASSERT_EQ(replaced.status, 0);

  const CommandResult shown = ctl({"show", selfPid()});
  ASSERT_EQ(shown.status, 0);
  ASSERT(shown.outHas("carried"));
  ASSERT(shown.outHas("floor"));

  // One base role, not two: the pod copy left the old tree's behind.
  ASSERT_EQ(shown.outCount("source:  base-role"), 1);
}

TEST(Ctl, ReplaceFromAnOverrideRoleUnderAConfiguredBaseRole) {
  // examples/signed-attach in miniature: the upgrade binary runs in the base
  // role and an overriding role of its own, and replaces the jailer it is
  // inside. `untracked-bpf` is what makes it work -- without it the attach
  // hands the jailer's own pins to `floor`, which overriding stops the
  // replace's walk from ever reaching.
  const std::string policy = writePolicy(
      "base-role: floor\n"
      "roles:\n"
      "  floor:\n    bpf:\n    untracked-bpf: true\n"
      "  bpfjailer:\n    override-stacked: true\n    bpf:\n");

  ASSERT_EQ(ctl({"attach", policy}).status, 0);
  ASSERT_EQ(ctl({"enroll", "bpfjailer", "signed@meta", selfPid()}).status, 0);

  ASSERT_EQ(ctl({"replace", policy}).status, 0);
}

TEST(Ctl, ReplaceNeedsAPolicyPath) {
  const CommandResult res = ctl({"replace"});
  ASSERT_EQ(res.status, kUsageError);
}

TEST(Ctl, ReplaceCompiledUsesThePolicyCompiledIn) {
  ASSERT_EQ(ctlCompiled({"attach-compiled"}).status, 0);
  ASSERT_EQ(ctl({"enroll", "carried", "owner@meta", selfPid()}).status, 0);

  const CommandResult res = ctlCompiled({"replace-compiled"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("2 role(s) from the compiled-in policy"));

  // Not the pod and task counts: the compiled-in policy names a base role, so
  // both move with whatever else is running on the host.
  const CommandResult shown = ctl({"show", selfPid()});
  ASSERT_EQ(shown.status, 0);
  ASSERT(shown.outHas("carried"));
  ASSERT(shown.outHas("owner@meta"));
}

TEST(Ctl, ReplaceCompiledTakesNoPath) {
  const std::string policy = writePolicy("roles:\n  other:\n");

  const CommandResult res = ctlCompiled({"replace-compiled", policy});
  ASSERT_EQ(res.status, kUsageError);
}

TEST(Ctl, ReplaceCompiledWithNothingCompiledInSaysSo) {
  const CommandResult res = ctl({"replace-compiled"});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("no policy was compiled into this binary"));
}

TEST(Ctl, CheckReportsWhatAPolicyHolds) {
  const std::string policy =
      writePolicy("base-role: floor\nroles:\n  floor:\n  web:\n");

  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("2 role(s), 0 cert(s), base role floor"));
}

TEST(Ctl, CheckRejectsNoBpfAlongsideABpfList) {
  const std::string policy = writePolicy(
      "roles:\n  muddled:\n    no-bpf: true\n    bpf:\n      - muddled\n");

  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("contradict each other"));
}

TEST(Ctl, CheckRejectsUntrackedBpfWithoutABpfList) {
  const std::string policy =
      writePolicy("roles:\n  exempt:\n    untracked-bpf: true\n");

  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("only a role configured for bpf(2) takes ownership"));
}

TEST(Ctl, CheckRejectsAnEnrollTargetNotInRoles) {
  const std::string policy =
      writePolicy("roles:\n  sandbox:\n    enroll:\n      - missing\n");

  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("role 'sandbox' allows enrolling in 'missing'"));
}

TEST(Ctl, CheckRejectsANoBpfThatIsNotABoolean) {
  const std::string policy =
      writePolicy("roles:\n  muddled:\n    no-bpf: maybe\n");

  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("neither true nor false"));
}

TEST(Ctl, CheckRejectsAMinSeqThatIsNotAnInteger) {
  const std::string policy = writePolicy("roles:\n  svc:\n    min-seq: 8x\n");

  // strtoull would read this as 8 and stop. A floor the author did not write
  // is worse than no floor, so the whole value has to be digits.
  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("is '8x', which is not a non-negative integer"));
}

TEST(Ctl, CheckRejectsAMinSeqThatDoesNotFit) {
  const std::string policy =
      writePolicy("roles:\n  svc:\n    min-seq: 99999999999999999999999999\n");

  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("does not fit"));
}

TEST(Ctl, CheckRejectsAMinSeqWithNoCertificateToCheckIt) {
  const std::string policy = writePolicy("roles:\n  svc:\n    min-seq: 5\n");

  // A sequence number is only trustworthy because a signature covers it, so a
  // floor on a role that verifies nothing would gate on an unsigned number.
  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("min-seq needs enforce-binary-certs"));
}

TEST(Ctl, CheckRejectsAPolicyThatDoesNotParse) {
  const std::string policy = writePolicy("base-role: nosuch\nroles:\n  web:\n");

  const CommandResult res = runCtl({"check", policy});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("base-role 'nosuch' is not in roles"));
}

TEST(Ctl, CheckCompiledReadsThePolicyCompiledIn) {
  const CommandResult res = runCtl({"check-compiled"}, kCompiledPolicy);
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas(
      "the compiled-in policy: 2 role(s), 0 cert(s), base role floor"));
}

TEST(Ctl, CheckCompiledWithNothingCompiledInSaysSo) {
  const CommandResult res = runCtl({"check-compiled"});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("no policy was compiled into this binary"));
}

TEST(Ctl, CheckNeedsAPolicyPath) {
  const CommandResult res = runCtl({"check"});
  ASSERT_EQ(res.status, kUsageError);
}

TEST(Ctl, AttachCompiledAppliesTheBaseRoleFromTheCompiledInPolicy) {
  ASSERT_EQ(ctlCompiled({"attach-compiled"}).status, 0);

  // The line the command prints only says what parsed; this is the base role
  // those bytes name having actually put this process in a pod.
  const CommandResult shown = ctl({"show", selfPid()});
  ASSERT_EQ(shown.status, 0);
  ASSERT(shown.outHas("floor"));
  ASSERT_EQ(shown.outCount("source:  base-role"), 1);
}

TEST(Ctl, CheckCompiledAgreesWithCheckOnTheSamePolicy) {
  const std::string path = writePolicy(kCompiledPolicy);

  const CommandResult fromPath = runCtl({"check", path});
  const CommandResult fromBinary = runCtl({"check-compiled"}, kCompiledPolicy);
  ASSERT_EQ(fromPath.status, 0);
  ASSERT_EQ(fromBinary.status, 0);

  // One policy, two sources: only the name before the colon may differ.
  ASSERT_EQ(
      fromPath.out.substr(fromPath.out.find(':')),
      fromBinary.out.substr(fromBinary.out.find(':')));
}

TEST(Ctl, ACompiledInPolicyCarriesItsCertificates) {
  // The trust store is the part of a policy worth signing over, so it has to
  // survive the trip through rodata and still base64-decode.
  const CommandResult res = runCtl(
      {"check-compiled"},
      "certs:\n  corp-ca: |\n    aGVsbG8gd29ybGQ=\n"
      "roles:\n  web:\n    enforce-binary-certs:\n      - corp-ca\n");
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("the compiled-in policy: 1 role(s), 1 cert(s)"));
}

TEST(Ctl, ACompiledInPolicyMayHoldQuotesAndBackslashes) {
  // Why the generated header is a byte array and not a string literal: a
  // policy holding either has to arrive as the bytes that were signed.
  const CommandResult res = runCtl(
      {"check-compiled"},
      "# a comment with \"quotes\" and a backslash \\\nroles:\n  web:\n");
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("1 role(s)"));
}

TEST(Ctl, DetachRemovesThePinTree) {
  attach();
  ASSERT(exists(pinRoot()));

  const CommandResult res = ctl({"detach"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("Jailer detached"));
  ASSERT(!exists(pinRoot()));
}

TEST(Ctl, DetachWithNothingAttachedSucceeds) {
  const CommandResult res = ctl({"detach"});
  ASSERT_EQ(res.status, 0);
}

TEST(Ctl, CommandsFailWithNoJailerAttached) {
  const CommandResult res = ctl({"list"});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("failed to open pinned map"));
}

TEST(Ctl, EnrollThenShowNamesTheRole) {
  attach();

  const CommandResult enrolled =
      ctl({"enroll", "testrole", "tester@meta", selfPid()});
  ASSERT_EQ(enrolled.status, 0);
  ASSERT(enrolled.outHas("Enrolled pid " + selfPid()));

  const CommandResult shown = ctl({"show", selfPid()});
  ASSERT_EQ(shown.status, 0);
  ASSERT(shown.outHas("testrole"));
  ASSERT(shown.outHas("tester@meta"));
  ASSERT(shown.outHas("source:  client"));
}

TEST(Ctl, ShowOnAnUnjailedPidSaysSo) {
  attach();

  // The harness itself, which nothing has enrolled.
  const CommandResult res = ctl({"show", std::to_string(::getppid())});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("is not jailed"));
}

TEST(Ctl, EnrollRejectsABadPid) {
  attach();

  const CommandResult res = ctl({"enroll", "role", "user", "abc"});
  ASSERT_EQ(res.status, 1);
  ASSERT(res.errHas("bad pid: abc"));
}

TEST(Ctl, ListWithNothingEnrolled) {
  attach();

  const CommandResult res = ctl({"list"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("no pods"));
}

TEST(Ctl, ListReportsAnEnrolledPod) {
  attach();
  ASSERT_EQ(ctl({"enroll", "listed", "owner@meta", selfPid()}).status, 0);

  const CommandResult res = ctl({"list"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("1 pod(s)"));
  ASSERT(res.outHas("listed"));
  ASSERT(res.outHas("pids:    " + selfPid()));
}

TEST(Ctl, ListRejectsAPositionalArgument) {
  const CommandResult res = ctl({"list", "123"});
  ASSERT_EQ(res.status, kUsageError);
}

TEST(Ctl, WrapRunsTheCommandInsideAPod) {
  attach();

  const CommandResult res =
      ctl({"wrap", "wrapped", "svc@meta", "--", "/bin/echo", "hello"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("hello"));

  // The wrapped process has exited but its pod outlives it: there is no pod GC
  // in this tree yet, which is why `pids` and `refs` are both worth printing.
  const CommandResult listed = ctl({"list"});
  ASSERT(listed.outHas("wrapped"));
  ASSERT(listed.outHas("svc@meta"));
}

TEST(Ctl, WrapKeepsCapabilitiesWithoutDropCap) {
  attach();

  const CommandResult res = ctl(
      {"wrap",
       "keeps",
       "svc",
       "--",
       "/bin/sh",
       "-c",
       "grep -E '^(CapBnd|NoNewPrivs)' /proc/self/status"});
  ASSERT_EQ(res.status, 0);
  ASSERT(!res.outHas("CapBnd:\t0000000000000000"));
  ASSERT(res.outHas("NoNewPrivs:\t0"));
}

TEST(Ctl, WrapDropsCapabilitiesWhenAsked) {
  attach();

  const CommandResult res = ctl(
      {"wrap",
       "drops",
       "svc",
       "--drop-cap",
       "--",
       "/bin/sh",
       "-c",
       "grep -E '^(CapBnd|CapPrm|NoNewPrivs)' /proc/self/status"});
  ASSERT_EQ(res.status, 0);
  ASSERT(res.outHas("CapBnd:\t0000000000000000"));
  ASSERT(res.outHas("CapPrm:\t0000000000000000"));
  ASSERT(res.outHas("NoNewPrivs:\t1"));
}

TEST(Ctl, WrapReportsACommandItCannotRun) {
  attach();

  const CommandResult res =
      ctl({"wrap", "missing", "svc", "--", "/nonexistent/binary"});
  ASSERT_EQ(res.status, 127);
  ASSERT(res.errHas("cannot exec /nonexistent/binary"));
}
