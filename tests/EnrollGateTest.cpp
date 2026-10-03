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
  loadJailer(policyOf(R"toml([roles]

[roles.svc]
)toml"));

  ASSERT(!mapPinned("bpfj_role_policies"));
  ASSERT(!mapPinned("bpfj_enroll_roles"));
  ASSERT(!mapPinned("bpfj_enroll_access"));
}

TEST(EnrollGate, AnUnjailedCallerIsUnrestricted) {
  loadJailer(policyOf(R"toml([roles]

[roles.sandbox]
)toml"));

  ASSERT(permitted("sandbox"));
}

TEST(EnrollGate, ARoleWithNoEnrollKeyIsDenied) {
  loadJailer(policyOf(R"toml([roles]

[roles.svc]

[roles.sandbox]
)toml"));
  enroll("svc", ::getpid());

  ASSERT(!permitted("sandbox"));
  ASSERT(!permitted("svc"));
}

TEST(EnrollGate, AnEmptyListForbidsEvenTheSameRoleAgain) {
  loadJailer(policyOf(R"toml([roles]

[roles.sandbox]
enroll-roles = []

[roles.other]
)toml"));
  enroll("sandbox", ::getpid());

  ASSERT(!permitted("sandbox"));
  ASSERT(!permitted("other"));
}

TEST(EnrollGate, AListPermitsOnlyTheRolesItNames) {
  loadJailer(policyOf(
      R"toml([roles]

[roles.svc]
enroll-roles = ["worker"]

[roles.worker]

[roles.other]
)toml"));
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
  ASSERT(!permitted("other"));
}

TEST(EnrollGate, EveryConfiguredRoleHasToPermit) {
  loadJailer(policyOf(
      R"toml([roles]

[roles.svc]
enroll-roles = ["worker"]

[roles.strict]
enroll-roles = []

[roles.worker]
)toml"));
  enroll("strict", ::getpid());
  enroll("svc", ::getpid());

  ASSERT(!permitted("worker"));
}

TEST(EnrollGate, AnAnyRolePermitsTheNarrowerRoleToAnswer) {
  loadJailer(policyOf(
      R"toml(base-role = "floor"

[roles]

[roles.floor]
enroll-any = true

[roles.svc]
enroll-roles = ["worker"]

[roles.worker]
)toml"));
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
}

TEST(EnrollGate, AnOverrideRoleAnswersForTheRolesUnderIt) {
  loadJailer(policyOf(
      R"toml([roles]

[roles.strict]
enroll-roles = []

[roles.svc]
override-stacked = true
enroll-roles = ["worker"]

[roles.worker]
)toml"));
  enroll("strict", ::getpid());
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
}

TEST(EnrollGate, ABaseRoleCanForbidStackingHostWide) {
  loadJailer(policyOf(
      R"toml(base-role = "floor"

[roles]

[roles.floor]
enroll-roles = []

[roles.svc]
)toml"));

  ASSERT(!permitted("svc"));
}
