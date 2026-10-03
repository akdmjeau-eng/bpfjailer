// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

#include "bpfj/enforce/LkmEnforcer.h"

using bpfjailer::LkmEnforcer;
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
    "  unrestricted:\n    lkm-any: true\n"
    "  denied:\n";

void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(LkmEnforcer::load(testPins(), policy));
}

[[nodiscard]] int initModuleErrno() {
  char module[1000] = {};
  errno = 0;
  return ::syscall(SYS_init_module, module, sizeof(module), "") == 0 ? 0
                                                                     : errno;
}

[[nodiscard]] int runIsolated(
    std::string_view scenarioName,
    std::function<int()> body) {
  noteDiagnostic("      scenario: " + std::string(scenarioName) + "\n");
  Child scenario(std::move(body));
  return scenario.run();
}

} // namespace

TEST(LkmEnforcer, LoadAgainstAnUnconfiguredPolicySucceeds) {
  attach("roles:\n  svc:\n");

  ASSERT(!mapPinned("bpfj_role_policies"));
}

TEST(LkmEnforcer, EnforcesPoliciesWithOneAttachment) {
  attach(std::string(kPolicy));

  ASSERT(linkPinned("bpfj_kernel_module_request"));
  ASSERT(linkPinned("bpfj_kernel_load_data"));
  ASSERT(linkPinned("bpfj_kernel_read_file"));
  ASSERT(!mapPinned("bpfj_role_policies"));
  ASSERT(!mapPinned("bpfj_no_lkm_roles"));

  ASSERT_EQ(
      runIsolated(
          "a no-lkm role denies module load",
          [] {
            Child actor(initModuleErrno);
            enroll("denied", actor.pid());
            return actor.run();
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "an unrestricted role reaches the kernel",
          [] {
            Child actor(initModuleErrno);
            enroll("unrestricted", actor.pid());
            return actor.run();
          }),
      ENOEXEC);

  ASSERT_EQ(
      runIsolated(
          "a stacked no-lkm role still denies",
          [] {
            Child actor(initModuleErrno);
            enroll("denied", actor.pid());
            enroll("unrestricted", actor.pid());
            return actor.run();
          }),
      EPERM);
}
