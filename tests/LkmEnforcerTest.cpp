// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <string>

#include "bpfj/enforce/LkmEnforcer.h"

using bpfjailer::LkmEnforcer;
using bpfjailer::Policy;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::pinnedMapIsEmpty;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

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

} // namespace

TEST(LkmEnforcer, LoadPinsItsLinksAndMap) {
  attach("roles:\n  svc:\n");

  ASSERT(linkPinned("bpfj_kernel_module_request"));
  ASSERT(linkPinned("bpfj_kernel_load_data"));
  ASSERT(linkPinned("bpfj_kernel_read_file"));
  ASSERT(mapPinned("bpfj_role_policies"));
  ASSERT(!mapPinned("bpfj_no_lkm_roles"));
}

TEST(LkmEnforcer, APolicyConfiguringNothingLeavesTheRoleMapEmpty) {
  attach("roles:\n  svc:\n");

  ASSERT(!pinnedMapIsEmpty("bpfj_role_policies"));
}

TEST(LkmEnforcer, ANoLkmRoleMayNotLoadAKernelModule) {
  attach("roles:\n  denied:\n    no-lkm: true\n");

  Child actor(initModuleErrno);
  enroll("denied", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(LkmEnforcer, AnUnconfiguredRoleMayReachTheKernelModuleLoader) {
  attach("roles:\n  unrestricted:\n");

  Child actor(initModuleErrno);
  enroll("unrestricted", actor.pid());

  ASSERT_EQ(actor.run(), ENOEXEC);
}

TEST(LkmEnforcer, NoLkmOnOneRoleDeniesAStackedTask) {
  attach("roles:\n  unrestricted:\n  denied:\n    no-lkm: true\n");

  Child actor(initModuleErrno);
  enroll("denied", actor.pid());
  enroll("unrestricted", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}
