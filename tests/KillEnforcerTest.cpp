// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

#include "bpfj/enforce/KillEnforcer.h"

using bpfjailer::KillEnforcer;
using bpfjailer::Policy;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::noteDiagnostic;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

constexpr std::string_view kPolicy =
    "roles:\n"
    "  open:\n    any: true\n"
    "  default-deny:\n"
    "  restricted:\n    kill-roles:\n      - worker\n"
    "  denied:\n"
    "  worker:\n"
    "  other:\n"
    "  strict:\n    kill-pod: true\n"
    "  base:\n    kill-any: true\n"
    "  override-allow:\n"
    "    override-stacked: true\n"
    "    kill-roles:\n      - worker\n"
    "  shield-reader:\n    kill-roles:\n      - shield\n"
    "  shield:\n    override-stacked: true\n"
    "  locked-override:\n"
    "    override-stacked: true\n"
    "    kill-pod: true\n"
    "  locked:\n    kill-pod: true\n";

void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(KillEnforcer::load(testPins(), policy));
}

[[nodiscard]] int signalErrno(pid_t pid) {
  errno = 0;
  return ::kill(pid, 0) == 0 ? 0 : errno;
}

/// Run a policy scenario in a fresh task so its memberships cannot leak into
/// the next scenario while every scenario shares one attached tree.
[[nodiscard]] int runIsolated(
    std::string_view scenarioName,
    std::function<int()> body) {
  noteDiagnostic("      scenario: " + std::string(scenarioName) + "\n");
  Child scenario(std::move(body));
  return scenario.run();
}

} // namespace

TEST(KillEnforcer, LoadAgainstAPolicyConfiguringNothingSucceeds) {
  // This loader-specific case must use an otherwise unconfigured policy.
  attach("roles:\n  svc:\n  worker:\n");

  ASSERT(linkPinned("bpfj_kill_check"));
}

TEST(KillEnforcer, EnforcesPoliciesWithOneAttachment) {
  attach(std::string(kPolicy));

  ASSERT(linkPinned("bpfj_kill_check"));
  ASSERT(!mapPinned("bpfj_role_policies"));
  ASSERT(!mapPinned("bpfj_kill_roles"));
  ASSERT(!mapPinned("bpfj_kill_access"));

  ASSERT_EQ(
      runIsolated(
          "an unspecified kill policy denies",
          [] {
            Child target;
            enroll("default-deny", ::getpid());
            return signalErrno(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "an explicitly open role is unrestricted",
          [] {
            Child target;
            enroll("open", ::getpid());
            return signalErrno(target.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "a restricted role may signal its own pod",
          [] {
            enroll("restricted", ::getpid());
            Child inPod;
            return signalErrno(inPod.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "a denied role may not signal its own pod",
          [] {
            enroll("denied", ::getpid());
            Child inPod;
            return signalErrno(inPod.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "a restricted role may not signal an unowned task",
          [] {
            Child outside;
            enroll("restricted", ::getpid());
            return signalErrno(outside.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "a restricted role may signal a named role",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("restricted", ::getpid());
            return signalErrno(target.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "a restricted role may not signal another role",
          [] {
            Child target;
            enroll("other", target.pid());
            enroll("restricted", ::getpid());
            return signalErrno(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "every target role must be named",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("other", target.pid());
            enroll("restricted", ::getpid());
            return signalErrno(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "every actor role must permit the signal",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("strict", ::getpid());
            enroll("restricted", ::getpid());
            return signalErrno(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "an unconfigured actor role does not restrict",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("base", ::getpid());
            enroll("restricted", ::getpid());
            return signalErrno(target.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "an override bounds the actor policy walk",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("strict", ::getpid());
            enroll("override-allow", ::getpid());
            return signalErrno(target.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "a target override does not hide target roles",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("shield", target.pid());
            enroll("shield-reader", ::getpid());
            return signalErrno(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "a denying override blocks the actor",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("restricted", ::getpid());
            enroll("locked-override", ::getpid());
            return signalErrno(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "a stacked denial blocks the actor",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("locked", ::getpid());
            enroll("restricted", ::getpid());
            return signalErrno(target.pid());
          }),
      EPERM);
}
