// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <fstream>
#include <string>

#include "bpfj/enforce/PtraceEnforcer.h"

using bpfjailer::Policy;
using bpfjailer::PtraceEnforcer;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

/// @brief Bring up the jailer and the ptrace enforcer over `yaml`.
void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(PtraceEnforcer::load(testPins(), policy));
}

/// @brief The errno from attaching to `pid`, or 0 if it was allowed, undoing
/// a successful attach before returning -- it stops the tracee, and the Child
/// destructor's waitpid would never return.
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

/// @brief What a child reports after asking its parent to trace it.
[[nodiscard]] int tracemeErrno() {
  errno = 0;
  return ::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == 0 ? 0 : errno;
}

} // namespace

TEST(PtraceEnforcer, LoadPinsBothLinksAndItsMaps) {
  attach("roles:\n  svc:\n");

  // Two hooks, because PTRACE_TRACEME arrives at its own with the roles
  // reversed.
  ASSERT(linkPinned("bpfj_ptrace_check"));
  ASSERT(linkPinned("bpfj_ptrace_traceme"));
  ASSERT(mapPinned("bpfj_ptrace_roles"));
  ASSERT(mapPinned("bpfj_ptrace_access"));
}

TEST(PtraceEnforcer, LoadAgainstAPolicyConfiguringNothingSucceeds) {
  attach("roles:\n  svc:\n  worker:\n");

  ASSERT(linkPinned("bpfj_ptrace_check"));
}

TEST(PtraceEnforcer, AnUnconfiguredRoleMayAttachToAnyone) {
  attach("roles:\n  svc:\n");

  Child target;
  enroll("svc", ::getpid());

  ASSERT_EQ(attachErrno(target.pid()), 0);
}

TEST(PtraceEnforcer, ARestrictedRoleMayAttachInsideItsOwnPod) {
  attach("roles:\n  svc:\n    ptrace:\n");

  enroll("svc", ::getpid());
  Child inPod;

  ASSERT_EQ(attachErrno(inPod.pid()), 0);
}

TEST(PtraceEnforcer, ARoleWithNoPtraceMayNotAttachInsideItsOwnPod) {
  attach("roles:\n  svc:\n    no-ptrace: true\n");

  enroll("svc", ::getpid());
  Child inPod;

  ASSERT_EQ(attachErrno(inPod.pid()), EPERM);
}

TEST(PtraceEnforcer, ARestrictedRoleMayNotAttachToAnUnjailedProcess) {
  attach("roles:\n  svc:\n    ptrace:\n");

  Child outside;
  enroll("svc", ::getpid());

  ASSERT_EQ(attachErrno(outside.pid()), EPERM);
}

TEST(PtraceEnforcer, ARestrictedRoleMayAttachToARoleItNamed) {
  attach("roles:\n  svc:\n    ptrace:\n      - worker\n  worker:\n");

  Child target;
  enroll("worker", target.pid());
  enroll("svc", ::getpid());

  ASSERT_EQ(attachErrno(target.pid()), 0);
}

TEST(PtraceEnforcer, ARestrictedRoleMayNotAttachToARoleItDidNotName) {
  attach("roles:\n  svc:\n    ptrace:\n      - worker\n  worker:\n  other:\n");

  Child target;
  enroll("other", target.pid());
  enroll("svc", ::getpid());

  ASSERT_EQ(attachErrno(target.pid()), EPERM);
}

TEST(PtraceEnforcer, ReadOnlyAccessIsNotGated) {
  attach("roles:\n  svc:\n    ptrace:\n");

  Child outside;
  enroll("svc", ::getpid());

  // Opening /proc/<pid>/maps goes through ptrace_access_check in the
  // read-only mode, which is not gated; the attach to this very process is
  // denied, which makes this a carve-out rather than an accident.
  ASSERT_EQ(attachErrno(outside.pid()), EPERM);

  std::ifstream maps("/proc/" + std::to_string(outside.pid()) + "/maps");
  std::string line;
  ASSERT(static_cast<bool>(std::getline(maps, line)));
  ASSERT(!line.empty());
}

TEST(PtraceEnforcer, TracemeIsRefusedWhenTheParentCouldNotAttach) {
  attach("roles:\n  svc:\n    ptrace:\n");

  // Forked before the enrollment, so the child is outside the parent's pod.
  // Consent from the tracee is not the jail's to give.
  Child child(tracemeErrno);
  enroll("svc", ::getpid());

  ASSERT_EQ(child.run(), EPERM);
}

TEST(PtraceEnforcer, TracemeIsAllowedInsideTheParentsPod) {
  attach("roles:\n  svc:\n    ptrace:\n");

  enroll("svc", ::getpid());
  Child inPod(tracemeErrno);

  ASSERT_EQ(inPod.run(), 0);
}

TEST(PtraceEnforcer, NoPtraceRefusesTracemeInsideTheParentsPod) {
  attach("roles:\n  svc:\n    no-ptrace: true\n");

  enroll("svc", ::getpid());
  Child inPod(tracemeErrno);

  ASSERT_EQ(inPod.run(), EPERM);
}
