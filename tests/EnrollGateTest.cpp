// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <unistd.h>

#include <string>
#include <string_view>

#include "bpfj/enforce/EnrollGate.h"

using bpfjailer::enrollPermitted;
using bpfjailer::test::enroll;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

/// @brief Whether this process may add `role`, ending the test on an error.
[[nodiscard]] bool permitted(std::string_view role) {
  auto res = enrollPermitted(testPins(), ::getpid(), role);
  ASSERT_OK(res);
  return *res;
}

} // namespace

TEST(EnrollGate, LoadPinsItsMaps) {
  loadJailer(policyOf("roles:\n  svc:\n"));

  ASSERT(mapPinned("bpfj_enroll_roles"));
  ASSERT(mapPinned("bpfj_enroll_access"));
}

TEST(EnrollGate, AnUnjailedCallerIsUnrestricted) {
  loadJailer(policyOf("roles:\n  sandbox:\n"));

  ASSERT(permitted("sandbox"));
}

TEST(EnrollGate, ARoleWithNoEnrollKeyIsUnrestricted) {
  loadJailer(policyOf("roles:\n  svc:\n  sandbox:\n"));
  enroll("svc", ::getpid());

  ASSERT(permitted("sandbox"));
  ASSERT(permitted("svc"));
}

TEST(EnrollGate, AnEmptyListForbidsEvenTheSameRoleAgain) {
  loadJailer(policyOf("roles:\n  sandbox:\n    enroll:\n  other:\n"));
  enroll("sandbox", ::getpid());

  ASSERT(!permitted("sandbox"));
  ASSERT(!permitted("other"));
}

TEST(EnrollGate, AListPermitsOnlyTheRolesItNames) {
  loadJailer(policyOf(
      "roles:\n  svc:\n    enroll:\n      - worker\n  worker:\n  other:\n"));
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
  ASSERT(!permitted("other"));
}

TEST(EnrollGate, EveryConfiguredRoleHasToPermit) {
  loadJailer(policyOf(
      "roles:\n"
      "  svc:\n    enroll:\n      - worker\n"
      "  strict:\n    enroll:\n"
      "  worker:\n"));
  enroll("strict", ::getpid());
  enroll("svc", ::getpid());

  ASSERT(!permitted("worker"));
}

TEST(EnrollGate, AnUnconfiguredRoleAbstains) {
  loadJailer(policyOf(
      "base-role: floor\n"
      "roles:\n  floor:\n  svc:\n    enroll:\n      - worker\n  worker:\n"));
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
}

TEST(EnrollGate, AnOverrideRoleAnswersForTheRolesUnderIt) {
  loadJailer(policyOf(
      "roles:\n"
      "  strict:\n    enroll:\n"
      "  svc:\n    override-stacked: true\n    enroll:\n      - worker\n"
      "  worker:\n"));
  enroll("strict", ::getpid());
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
}

TEST(EnrollGate, ABaseRoleCanForbidStackingHostWide) {
  loadJailer(
      policyOf("base-role: floor\nroles:\n  floor:\n    enroll:\n  svc:\n"));

  ASSERT(!permitted("svc"));
}
