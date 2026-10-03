// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <fstream>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

#include "bpfj/enforce/PtraceEnforcer.h"

using bpfjailer::Policy;
using bpfjailer::PtraceEnforcer;
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
    "  default-deny:\n"
    "  restricted:\n    ptrace-roles:\n      - worker\n"
    "  denied:\n"
    "  worker:\n"
    "  other:\n";

void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(PtraceEnforcer::load(testPins(), policy));
}

[[nodiscard]] int attachErrno(pid_t pid) {
  errno = 0;
  if (::ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
    return errno;
  }

  int status = 0;
  (void)::waitpid(pid, &status, 0);
  (void)::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
  return 0;
}

[[nodiscard]] int tracemeErrno() {
  errno = 0;
  return ::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == 0 ? 0 : errno;
}

[[nodiscard]] int runIsolated(
    std::string_view scenarioName,
    std::function<int()> body) {
  noteDiagnostic("      scenario: " + std::string(scenarioName) + "\n");
  Child scenario(std::move(body));
  return scenario.run();
}

} // namespace

TEST(PtraceEnforcer, LoadAgainstAPolicyConfiguringNothingSucceeds) {
  attach("roles:\n  svc:\n  worker:\n");

  ASSERT(linkPinned("bpfj_ptrace_check"));
}

TEST(PtraceEnforcer, EnforcesPoliciesWithOneAttachment) {
  attach(std::string(kPolicy));

  ASSERT(linkPinned("bpfj_ptrace_check"));
  ASSERT(linkPinned("bpfj_ptrace_traceme"));
  ASSERT(mapPinned("bpfj_role_policies"));
  ASSERT(!mapPinned("bpfj_ptrace_roles"));
  ASSERT(!mapPinned("bpfj_ptrace_access"));

  ASSERT_EQ(
      runIsolated(
          "an unconfigured role may attach",
          [] {
            Child target;
            enroll("default-deny", ::getpid());
            return attachErrno(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "a restricted role may attach within its pod",
          [] {
            enroll("restricted", ::getpid());
            Child inPod;
            return attachErrno(inPod.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "a denied role may not attach within its pod",
          [] {
            enroll("denied", ::getpid());
            Child inPod;
            return attachErrno(inPod.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "a restricted role may not attach outside its pod",
          [] {
            Child outside;
            enroll("restricted", ::getpid());
            return attachErrno(outside.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "a restricted role may attach to a named role",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("restricted", ::getpid());
            return attachErrno(target.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "a restricted role may not attach to another role",
          [] {
            Child target;
            enroll("other", target.pid());
            enroll("restricted", ::getpid());
            return attachErrno(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "ptrace denial does not block proc maps",
          [] {
            Child outside;
            enroll("restricted", ::getpid());
            if (attachErrno(outside.pid()) != EPERM) {
              return EPROTO;
            }

            std::ifstream maps(
                "/proc/" + std::to_string(outside.pid()) + "/maps");
            std::string line;
            return std::getline(maps, line) && !line.empty() ? 0 : EIO;
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "traceme is denied when the parent cannot attach",
          [] {
            Child child(tracemeErrno);
            enroll("restricted", ::getpid());
            return child.run();
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "traceme is allowed within a permitted pod",
          [] {
            enroll("restricted", ::getpid());
            Child inPod(tracemeErrno);
            return inPod.run();
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "traceme is denied within a denied pod",
          [] {
            enroll("denied", ::getpid());
            Child inPod(tracemeErrno);
            return inPod.run();
          }),
      EPERM);
}
