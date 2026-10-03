// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <unistd.h>

#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>

#include "bpfj/enforce/BpfEnforcer.h"
#include "bpfj/enforce/Pins.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/Pods.h"
#include "bpfj/enforce/Replace.h"
#include "bpfj/enforce/RoleId.h"

using bpfjailer::BpfEnforcer;
using bpfjailer::enrollPod;
using bpfjailer::PodArena;
using bpfjailer::Policy;
using bpfjailer::readPolicyCatalog;
using bpfjailer::replaceJailer;
using bpfjailer::Threads;
namespace pins = bpfjailer::pins;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

/// @brief Bring up the jailer and the BPF object enforcer over `yaml`.
void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(BpfEnforcer::load(testPins(), policy));
}

/// @brief The errno from creating a BPF map, or 0 if the syscall was allowed.
[[nodiscard]] int mapCreateErrno() {
  errno = 0;
  const int fd = ::bpf_map_create(
      BPF_MAP_TYPE_HASH, "bpfj_probe", sizeof(int), sizeof(int), 1, nullptr);
  if (fd < 0) {
    return errno;
  }

  ::close(fd);
  return 0;
}

/// @brief Create a map and return its id, or the negated errno. The child
/// holding it stays alive after reporting, so the id still names a live map
/// when another role tries to open it.
[[nodiscard]] int createOwnedMap() {
  errno = 0;
  const int fd = ::bpf_map_create(
      BPF_MAP_TYPE_HASH, "bpfj_owned", sizeof(int), sizeof(int), 1, nullptr);
  if (fd < 0) {
    return -errno;
  }

  struct bpf_map_info info{};
  __u32 len = sizeof(info);
  if (::bpf_obj_get_info_by_fd(fd, &info, &len) != 0) {
    return -errno;
  }

  // Deliberately leaked: closing it would free the map, and the point of the id
  // is that something else can reach it afterwards.
  return static_cast<int>(info.id);
}

/// @brief The errno from opening the map `id`, or 0 if it was allowed.
[[nodiscard]] int openMapErrno(int id) {
  errno = 0;
  const int fd = ::bpf_map_get_fd_by_id(static_cast<__u32>(id));
  if (fd < 0) {
    return errno;
  }

  ::close(fd);
  return 0;
}

/// @brief Run replace in a helper process that can still call bpf(2), and
/// leave its error on the test log if it fails.
[[nodiscard]] int replaceErrno(const std::string& yaml) {
  auto replaced = replaceJailer(testPins(), policyOf(yaml));
  if (replaced) {
    return 0;
  }

  bpfjailer::test::noteDiagnostic("      " + replaced.error().message() + "\n");
  return replaced.error().code().value() == 0 ? 1
                                              : replaced.error().code().value();
}

/// @brief The role recorded as owning the map `id`, or "" if none is. Reads
/// the map the gate reads rather than inferring from a denial, the two being
/// able to disagree for a moment after a replace.
[[nodiscard]] std::string ownerOf(int id) {
  auto owners = pins::openPinnedMap(testPins(), "bpfj_bpf_map_owners");
  if (!owners) {
    return "";
  }

  std::uint64_t curr = 0;
  std::uint64_t next = 0;
  const void* from = nullptr;
  while (::bpf_map_get_next_key(owners->get(), from, &next) == 0) {
    struct bpfj_bpf_owner owner{};
    if (::bpf_map_lookup_elem(owners->get(), &next, &owner) == 0 &&
        owner.id == static_cast<__u32>(id)) {
      return owner.role.id;
    }

    curr = next;
    from = &curr;
  }

  return "";
}

} // namespace

TEST(BpfEnforcer, LoadPinsItsLinksAndMaps) {
  attach("roles:\n  svc:\n");

  ASSERT(linkPinned("bpfj_bpf_syscall"));
  ASSERT(linkPinned("bpfj_bpf_map_created"));
  ASSERT(linkPinned("bpfj_bpf_prog_loaded"));
  ASSERT(linkPinned("bpfj_bpf_map_check"));
  ASSERT(linkPinned("bpfj_bpf_prog_check"));
  ASSERT(linkPinned("bpfj_bpf_map_free"));
  ASSERT(linkPinned("bpfj_bpf_prog_free"));

  ASSERT(mapPinned("bpfj_role_policies"));
  ASSERT(!mapPinned("bpfj_bpf_syscall_roles"));
  ASSERT(!mapPinned("bpfj_bpf_access"));
  ASSERT(mapPinned("bpfj_bpf_map_owners"));
  ASSERT(mapPinned("bpfj_bpf_prog_owners"));
  ASSERT(mapPinned("bpfj_heap_arena"));
}

TEST(BpfEnforcer, LoadAgainstAPolicyConfiguringNothingSucceeds) {
  // A policy configuring no role costs nothing, which is what lets the scheme
  // go on one role at a time.
  attach("roles:\n  svc:\n  worker:\n");

  ASSERT(linkPinned("bpfj_bpf_syscall"));
}

TEST(BpfEnforcer, EnrollIsRefusedWhileAReplaceHasFrozenTheTree) {
  attach("roles:\n  svc:\n");

  auto frozen = pins::openPinnedMap(testPins(), "bpfj_replace_frozen");
  ASSERT(frozen);

  const std::uint32_t slot = 0;
  const std::uint8_t yes = 1;
  ASSERT_EQ(::bpf_map_update_elem(frozen->get(), &slot, &yes, BPF_ANY), 0);

  auto uuid =
      enrollPod(testPins(), "svc", "frozen@meta", {}, ::getpid(), Threads::All);
  ASSERT(!uuid);
  ASSERT_EQ(
      uuid.error().code(),
      std::make_error_code(std::errc::device_or_resource_busy));
}

TEST(BpfEnforcer, AnUnconfiguredRoleMayStillCallBpf) {
  attach("roles:\n  svc:\n");

  Child actor(mapCreateErrno);
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, ARoleThatWroteAnEmptyListMayStillCallBpf) {
  // Written empty restricts what the role reaches, as it does for kill and
  // ptrace. It is not a denial of the syscall: that is `no-bpf`.
  attach("roles:\n  confined:\n    bpf:\n");

  Child actor(mapCreateErrno);
  enroll("confined", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, ARoleThatNamedItselfMayCallBpf) {
  attach("roles:\n  svc:\n    bpf:\n      - svc\n");

  Child actor(mapCreateErrno);
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, AnUnjailedProcessIsNotSubjectToThePolicy) {
  attach("roles:\n  denied:\n    no-bpf: true\n");

  // Never enrolled, so no policy applies: the denial above is about the role,
  // not about the enforcer being loaded.
  Child actor(mapCreateErrno);

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, AMapIsOpenableByTheRoleThatOwnsIt) {
  attach("roles:\n  owner:\n    bpf:\n      - owner\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  // A different process in the same role, and so a different pod: the gate is
  // keyed on the role, so owning is not about being the creator.
  Child peer([id] { return openMapErrno(id); });
  enroll("owner", peer.pid());

  ASSERT_EQ(peer.run(), 0);
}

TEST(BpfEnforcer, AMapIsNotOpenableByARoleTheOwnerDidNotName) {
  attach(
      "roles:\n  owner:\n    bpf:\n      - owner\n"
      "  snoop:\n    bpf:\n      - snoop\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  Child snoop([id] { return openMapErrno(id); });
  enroll("snoop", snoop.pid());

  ASSERT_EQ(snoop.run(), EPERM);
}

TEST(BpfEnforcer, AnUnconfiguredRoleReachesNothingThatIsOwned) {
  attach("roles:\n  owner:\n    bpf:\n      - owner\n  bystander:\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  // Letting an unconfigured role through would make protection defeatable by
  // leaving a role out of the policy.
  Child bystander([id] { return openMapErrno(id); });
  enroll("bystander", bystander.pid());

  ASSERT_EQ(bystander.run(), EPERM);
}

TEST(BpfEnforcer, AnUnownedMapIsNotGated) {
  attach(
      "roles:\n  owner:\n    bpf:\n      - owner\n  snoop:\n    bpf:\n"
      "      - snoop\n");

  // Created by a process in no pod, so nothing recorded an owner and the gate
  // has nothing to check it against.
  Child creator(createOwnedMap);
  const int id = creator.run();
  ASSERT(id > 0);

  Child snoop([id] { return openMapErrno(id); });
  enroll("snoop", snoop.pid());

  ASSERT_EQ(snoop.run(), 0);
}

TEST(BpfEnforcer, ARoleWithNoBpfMayNotCallBpf) {
  attach("roles:\n  denied:\n    no-bpf: true\n");

  Child actor(mapCreateErrno);
  enroll("denied", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(BpfEnforcer, ARoleThatWroteAnEmptyListReachesWhatItOwns) {
  attach("roles:\n  confined:\n    bpf:\n");

  Child creator(createOwnedMap);
  enroll("confined", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  // Writing the list at all is what buys this, the way writing `kill` leaves
  // a role able to signal inside its own pod. Nothing had to name itself.
  Child peer([id] { return openMapErrno(id); });
  enroll("confined", peer.pid());

  ASSERT_EQ(peer.run(), 0);
}

TEST(BpfEnforcer, ARoleThatWroteAnEmptyListReachesNothingElse) {
  attach(
      "roles:\n  owner:\n    bpf:\n"
      "  confined:\n    bpf:\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  Child confined([id] { return openMapErrno(id); });
  enroll("confined", confined.pid());

  ASSERT_EQ(confined.run(), EPERM);
}

TEST(BpfEnforcer, ARoleReachesItsOwnWithoutListingItself) {
  attach(
      "roles:\n  owner:\n    bpf:\n      - other\n"
      "  other:\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  // `owner` named only `other`, so before the own-pod exemption it could not
  // reach a map its own role owned.
  Child peer([id] { return openMapErrno(id); });
  enroll("owner", peer.pid());

  ASSERT_EQ(peer.run(), 0);
}

TEST(BpfEnforcer, NoBpfOnOneRoleDeniesATaskHoldingAPermittedRoleToo) {
  attach(
      "roles:\n  allowed:\n    bpf:\n"
      "  denied:\n    no-bpf: true\n");

  // A denial a task can shed by picking up another role would deny nothing,
  // least of all under a base role.
  Child actor(mapCreateErrno);
  enroll("allowed", actor.pid());
  enroll("denied", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

// The two below pin the ownership half of the policy shape
// examples/signed-attach depends on: ownership goes to the newest role a task
// holds that may call bpf(2), so the specific role owns what it creates
// whether or not the base role is configured.

TEST(BpfEnforcer, AnUnconfiguredBaseRoleLeavesOwnershipToTheRoleAboveIt) {
  attach("base-role: floor\nroles:\n  floor:\n  bpfjailer:\n    bpf:\n");

  // [floor, bpfjailer]: the base role came from the attach above, the second
  // from the enrollment, exactly as an exec would append it.
  Child creator(createOwnedMap);
  enroll("bpfjailer", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  // In the base role and nothing else, which is every other process here.
  Child bystander([id] { return openMapErrno(id); });

  ASSERT_EQ(bystander.run(), EPERM);
}

TEST(BpfEnforcer, AConfiguredBaseRoleDoesNotTakeOwnershipFromTheRoleAboveIt) {
  // The same policy with `bpf` added to the base role, which walking oldest
  // first would hand every object to. `bpfjailer` overrides, as in
  // examples/signed-attach, or `floor` would also have to agree to it opening
  // what it just created.
  attach(
      "base-role: floor\nroles:\n  floor:\n    bpf:\n"
      "  bpfjailer:\n    override-stacked: true\n    bpf:\n");

  Child creator(createOwnedMap);
  enroll("bpfjailer", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  Child bystander([id] { return openMapErrno(id); });

  ASSERT_EQ(bystander.run(), EPERM);
}

// The other thing writing `bpf` on a base role decides: a configured role
// owns what it creates and, through the load-time seeding walk, what it
// already holds open -- which for a base role is the whole host, and which is
// what `untracked-bpf` exists to stop.

TEST(BpfEnforcer, AnUnconfiguredBaseRoleLeavesWhatPredatesTheJailUnowned) {
  // Created before anything is attached, and still held open by the child
  // that made it, which is what the seeding walk reads.
  Child creator(createOwnedMap);
  const int id = creator.run();
  ASSERT(id > 0);

  attach(
      "base-role: floor\n"
      "roles:\n"
      "  floor:\n"
      "  upgrade:\n    override-stacked: true\n    bpf:\n");

  Child actor([id] { return openMapErrno(id); });
  enroll("upgrade", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, AConfiguredBaseRoleClaimsWhatPredatesTheJail) {
  Child creator(createOwnedMap);
  const int id = creator.run();
  ASSERT(id > 0);

  // The same policy with `bpf` on the base role and nothing exempting it, so
  // the walk records `floor` against every object on the host -- and
  // `upgrade`, which is in `floor` too, reaches none of them.
  attach(
      "base-role: floor\n"
      "roles:\n"
      "  floor:\n    bpf:\n"
      "  upgrade:\n    override-stacked: true\n    bpf:\n");

  Child actor([id] { return openMapErrno(id); });
  enroll("upgrade", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(BpfEnforcer, UntrackedBpfLeavesWhatPredatesTheJailUnowned) {
  Child creator(createOwnedMap);
  const int id = creator.run();
  ASSERT(id > 0);

  // The same policy again with the exemption the example carries: `floor` is
  // still configured and restricted, it just does not come to own the host.
  attach(
      "base-role: floor\n"
      "roles:\n"
      "  floor:\n    bpf:\n    untracked-bpf: true\n"
      "  upgrade:\n    override-stacked: true\n    bpf:\n");

  Child actor([id] { return openMapErrno(id); });
  enroll("upgrade", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, UntrackedBpfLeavesWhatTheRoleCreatesUnowned) {
  // The create hook rather than the seeding walk, or a base role would come
  // to own the host a few seconds later instead.
  attach(
      "roles:\n"
      "  maker:\n    bpf:\n    untracked-bpf: true\n"
      "  other:\n    bpf:\n");

  Child creator(createOwnedMap);
  enroll("maker", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  Child actor([id] { return openMapErrno(id); });
  enroll("other", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, AnUntrackedRoleIsStillGrantedWhatItsListNames) {
  // What separates it from simply leaving `bpf` out: an unconfigured role
  // reaches nothing a configured role owns, and this one still holds the
  // grant it asked for.
  attach(
      "roles:\n"
      "  owner:\n    bpf:\n"
      "  reader:\n    bpf:\n      - owner\n    untracked-bpf: true\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  Child actor([id] { return openMapErrno(id); });
  enroll("reader", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, AnOverrideRoleStopsTheWalkBeforeTheRolesUnderIt) {
  // `strict` reaches only what it owns, but the walk evaluates the `reader`
  // stacked on top, sees override-stacked, and never reaches that denial.
  attach(
      "roles:\n"
      "  strict:\n    bpf:\n"
      "  owner:\n    bpf:\n"
      "  reader:\n    override-stacked: true\n    bpf:\n      - owner\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  Child actor([id] { return openMapErrno(id); });
  enroll("strict", actor.pid());
  enroll("reader", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, WithoutOverrideTheRoleUnderneathStillDenies) {
  // The same policy with the flag dropped, so `strict` -- which every
  // configured role has to satisfy -- denies after all.
  attach(
      "roles:\n"
      "  strict:\n    bpf:\n"
      "  owner:\n    bpf:\n"
      "  reader:\n    bpf:\n      - owner\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  Child actor([id] { return openMapErrno(id); });
  enroll("strict", actor.pid());
  enroll("reader", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(BpfEnforcer, AConfiguredBaseRoleHasToAgreeToARoleAboveItsOwnObjects) {
  // The cost of every role having to agree: a role stacked on `floor`
  // without override-stacked cannot open even the map it just created, whose
  // fd is checked like any other.
  attach("base-role: floor\nroles:\n  floor:\n    bpf:\n  owner:\n    bpf:\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());

  ASSERT_EQ(creator.run(), -EPERM);
}

TEST(BpfEnforcer, AnUnconfiguredBaseRoleAbstains) {
  // `floor` wrote no `bpf`, so it neither grants nor denies, and `reader`
  // alone decides for a task holding both.
  attach(
      "base-role: floor\n"
      "roles:\n"
      "  floor:\n"
      "  owner:\n    bpf:\n"
      "  reader:\n    bpf:\n      - owner\n");

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);

  Child actor([id] { return openMapErrno(id); });
  enroll("reader", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(BpfEnforcer, OwnershipSurvivesAReplace) {
  const std::string yaml = "roles:\n  owner:\n    bpf:\n      - owner\n";
  attach(yaml);

  Child creator(createOwnedMap);
  enroll("owner", creator.pid());
  const int id = creator.run();
  ASSERT(id > 0);
  ASSERT_EQ(ownerOf(id), std::string("owner"));

  ASSERT_OK(replaceJailer(testPins(), policyOf(yaml)));

  // The new tree cannot rebuild this: its seeding walk only reaches objects
  // some task holds an fd to, and a pinned object is held by its pin, so
  // without carrying the records across this map comes out unowned.
  ASSERT_EQ(ownerOf(id), std::string("owner"));
}

TEST(BpfEnforcer, AReplaceKeepsANonLeaderThreadJailed) {
  const std::string yaml = "roles:\n  denied:\n    no-bpf: true\n";
  attach(yaml);
  Child replacer([yaml] { return replaceErrno(yaml); });

  std::mutex mutex;
  std::condition_variable cv;
  bool ready = false;
  bool go = false;
  int workerErrno = -1;

  std::thread worker([&] {
    {
      std::unique_lock<std::mutex> lock(mutex);
      ready = true;
      cv.notify_one();
      cv.wait(lock, [&] { return go; });
    }

    workerErrno = mapCreateErrno();
  });

  {
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock, [&] { return ready; });
  }

  ASSERT_OK(enrollPod(
      testPins(), "denied", "threaded@meta", {}, ::getpid(), Threads::All));
  ASSERT_EQ(replacer.run(), 0);

  {
    std::lock_guard<std::mutex> lock(mutex);
    go = true;
  }
  cv.notify_one();
  worker.join();

  ASSERT_EQ(workerErrno, EPERM);
}

TEST(BpfEnforcer, AReplaceIsRefusedWhenTheOwnerLayoutIsUnknown) {
  const std::string yaml = "roles:\n  owner:\n    bpf:\n      - owner\n";
  attach(yaml);

  ASSERT(!mapPinned("bpfj_bpf_owner_version"));

  // A tree written by a build with a different bpfj_bpf_owner, whose records
  // this build cannot parse, so the replace refuses rather than guesses.
  auto arena = PodArena::open(testPins());
  ASSERT(arena);
  auto catalog = readPolicyCatalog(*arena);
  ASSERT_OK(catalog);
  ASSERT(*catalog);

  auto* mutableCatalog = const_cast<struct bpfj_policy_catalog*>(*catalog);
  mutableCatalog->runtime_versions &=
      ~(BPFJ_RUNTIME_VERSION_MASK << BPFJ_BPF_OWNER_VERSION_SHIFT);
  mutableCatalog->runtime_versions |= (BPFJ_BPF_OWNER_VERSION + 1)
      << BPFJ_BPF_OWNER_VERSION_SHIFT;

  ASSERT(!replaceJailer(testPins(), policyOf(yaml)));
}

TEST(BpfEnforcer, AReplaceIsRefusedWhenTheMembershipLayoutIsUnknown) {
  const std::string yaml = "roles:\n  carried:\n";
  attach(yaml);

  auto arena = PodArena::open(testPins());
  ASSERT(arena);
  auto catalog = readPolicyCatalog(*arena);
  ASSERT_OK(catalog);
  ASSERT(*catalog);

  auto* mutableCatalog = const_cast<struct bpfj_policy_catalog*>(*catalog);
  mutableCatalog->runtime_versions &=
      ~(BPFJ_RUNTIME_VERSION_MASK << BPFJ_MEMBERSHIP_VERSION_SHIFT);
  mutableCatalog->runtime_versions |= (BPFJ_MEMBERSHIP_VERSION + 1)
      << BPFJ_MEMBERSHIP_VERSION_SHIFT;

  ASSERT(!replaceJailer(testPins(), policyOf(yaml)));
}
