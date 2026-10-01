// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <string>

#include "bpfj/enforce/KillEnforcer.h"

using bpfjailer::KillEnforcer;
using bpfjailer::Policy;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

/// @brief Bring up the jailer and the signal enforcer over `yaml`.
void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(KillEnforcer::load(testPins(), policy));
}

/// @brief The errno from signalling `pid`, or 0 if it was allowed. Signal 0
/// runs the permission checks, security_task_kill among them, and delivers
/// nothing, so the target survives being asked.
[[nodiscard]] int signalErrno(pid_t pid) {
  errno = 0;
  return ::kill(pid, 0) == 0 ? 0 : errno;
}

} // namespace

TEST(KillEnforcer, LoadPinsItsLinkAndMaps) {
  attach("roles:\n  svc:\n");

  ASSERT(linkPinned("bpfj_kill_check"));
  ASSERT(mapPinned("bpfj_kill_roles"));
  ASSERT(mapPinned("bpfj_kill_access"));
}

TEST(KillEnforcer, LoadAgainstAPolicyConfiguringNothingSucceeds) {
  // The rule goes on one role at a time, so a policy writing no `kill` anywhere
  // must be a no-op rather than a load failure.
  attach("roles:\n  svc:\n  worker:\n");

  ASSERT(linkPinned("bpfj_kill_check"));
}

TEST(KillEnforcer, AnUnconfiguredRoleMaySignalAnyone) {
  attach("roles:\n  svc:\n");

  Child target;
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), 0);
}

TEST(KillEnforcer, ARestrictedRoleMaySignalInsideItsOwnPod) {
  attach("roles:\n  svc:\n    kill:\n");

  enroll("svc", ::getpid());

  // Forked after the enrollment, so it inherited the pod.
  Child inPod;

  ASSERT_EQ(signalErrno(inPod.pid()), 0);
}

TEST(KillEnforcer, ARoleWithNoKillMayNotSignalInsideItsOwnPod) {
  attach("roles:\n  svc:\n    no-kill: true\n");

  enroll("svc", ::getpid());
  Child inPod;

  ASSERT_EQ(signalErrno(inPod.pid()), EPERM);
}

TEST(KillEnforcer, ARestrictedRoleMayNotSignalAnUnjailedProcess) {
  attach("roles:\n  svc:\n    kill:\n");

  // Forked first, so it is in no pod: there is no role to check it against, and
  // allowing that would hand back everything the empty list took away.
  Child outside;
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(outside.pid()), EPERM);
}

TEST(KillEnforcer, ARestrictedRoleMaySignalARoleItNamed) {
  attach("roles:\n  svc:\n    kill:\n      - worker\n  worker:\n");

  Child target;
  enroll("worker", target.pid());
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), 0);
}

TEST(KillEnforcer, ARestrictedRoleMayNotSignalARoleItDidNotName) {
  attach("roles:\n  svc:\n    kill:\n      - worker\n  worker:\n  other:\n");

  Child target;
  enroll("other", target.pid());
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), EPERM);
}

TEST(KillEnforcer, ATargetRoleOffTheListDeniesTheWholeTarget) {
  attach("roles:\n  svc:\n    kill:\n      - worker\n  worker:\n  other:\n");

  // Every role the target holds must be listed, or it would become reachable
  // by acquiring `worker` alongside the role protecting it.
  Child target;
  enroll("worker", target.pid());
  enroll("other", target.pid());
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), EPERM);
}

TEST(KillEnforcer, EveryActorRoleHasToPermit) {
  attach(
      "roles:\n  svc:\n    kill:\n      - worker\n  strict:\n    kill:\n"
      "  worker:\n");

  Child target;
  enroll("worker", target.pid());

  // `svc` would permit, but `strict` may act only in its own pod, and one
  // configured role denying is enough to deny the task.
  enroll("strict", ::getpid());
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), EPERM);
}

TEST(KillEnforcer, AnUnconfiguredActorRoleAbstains) {
  attach("roles:\n  svc:\n    kill:\n      - worker\n  base:\n  worker:\n");

  Child target;
  enroll("worker", target.pid());
  enroll("base", ::getpid());
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), 0);
}

TEST(KillEnforcer, AnOverrideRoleThatPermitsAnswersForTheRolesUnderIt) {
  attach(
      "roles:\n"
      "  strict:\n    kill:\n"
      "  worker:\n"
      "  svc:\n    override-stacked: true\n    kill:\n      - worker\n");

  Child target;
  enroll("worker", target.pid());
  enroll("strict", ::getpid());
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), 0);
}

TEST(KillEnforcer, AnOverrideRoleOnTheTargetStillHasToBeCovered) {
  // Override bounds the actor's walk only: `svc` lists `shield` but not
  // `worker`, and the target holding `shield` on top does not drop `worker`.
  attach(
      "roles:\n"
      "  svc:\n    kill:\n      - shield\n"
      "  worker:\n"
      "  shield:\n    override-stacked: true\n");

  Child target;
  enroll("worker", target.pid());
  enroll("shield", target.pid());
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), EPERM);
}

TEST(KillEnforcer, AnOverrideRoleStopsTheWalkBeforeTheRolesUnderIt) {
  // The same rule as the BPF object gate, the flag belonging to the pod stack
  // rather than any one enforcer: `locked` is stacked on the `svc` that would
  // have permitted the signal, and stops the walk before it is consulted.
  attach(
      "roles:\n"
      "  svc:\n    kill:\n      - worker\n"
      "  worker:\n"
      "  locked:\n    override-stacked: true\n    kill:\n");

  Child target;
  enroll("worker", target.pid());
  enroll("svc", ::getpid());
  enroll("locked", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), EPERM);
}

TEST(KillEnforcer, WithoutOverrideTheRoleUnderneathStillDenies) {
  // `svc` on top would permit, but without the flag the walk carries on to
  // `locked`, which permits nothing outside its own pod.
  attach(
      "roles:\n"
      "  svc:\n    kill:\n      - worker\n"
      "  worker:\n"
      "  locked:\n    kill:\n");

  Child target;
  enroll("worker", target.pid());
  enroll("locked", ::getpid());
  enroll("svc", ::getpid());

  ASSERT_EQ(signalErrno(target.pid()), EPERM);
}
