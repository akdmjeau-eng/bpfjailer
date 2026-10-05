// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <optional>
#include <string>
#include <utility>

#include "bpfj/enforce/MountEnforcer.h"

using bpfjailer::MountEnforcer;
using bpfjailer::Policy;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

constexpr unsigned int kOpenTreeClone = 1;
constexpr unsigned int kMoveMountEmptyPath = 0x00000004;

class Fixture {
 public:
  Fixture() {
    char path[] = "/tmp/bpfj-mount-test-XXXXXX";
    ASSERT(::mkdtemp(path) != nullptr);
    root_ = path;
    source_ = root_ + "/source";
    destination_ = root_ + "/destination";
    other_ = root_ + "/other";
    ASSERT_EQ(::mkdir(source_.c_str(), 0700), 0);
    ASSERT_EQ(::mkdir(destination_.c_str(), 0700), 0);
    ASSERT_EQ(::mkdir(other_.c_str(), 0700), 0);
  }

  ~Fixture() {
    (void)::umount2(source_.c_str(), MNT_DETACH);
    (void)::umount2(destination_.c_str(), MNT_DETACH);
    (void)::umount2(other_.c_str(), MNT_DETACH);
    (void)::rmdir(source_.c_str());
    (void)::rmdir(destination_.c_str());
    (void)::rmdir(other_.c_str());
    (void)::rmdir(root_.c_str());
  }

  const std::string& root() const {
    return root_;
  }
  const std::string& source() const {
    return source_;
  }
  const std::string& destination() const {
    return destination_;
  }
  const std::string& other() const {
    return other_;
  }

 private:
  std::string root_;
  std::string source_;
  std::string destination_;
  std::string other_;
};

[[nodiscard]] int
mountFs(const std::string& path, const char* type, unsigned long flags = 0) {
  errno = 0;
  const int result = ::mount("none", path.c_str(), type, flags, nullptr);
  return result == 0 ? 0 : errno;
}

[[nodiscard]] int unmount(const std::string& path) {
  errno = 0;
  const int result = ::umount2(path.c_str(), MNT_DETACH);
  return result == 0 ? 0 : errno;
}

[[nodiscard]] int moveMount(
    const std::string& source,
    const std::string& destination) {
  const int tree = static_cast<int>(::syscall(
      SYS_open_tree, AT_FDCWD, source.c_str(), kOpenTreeClone | O_CLOEXEC));
  if (tree < 0) {
    return errno;
  }
  errno = 0;
  const int result = static_cast<int>(::syscall(
      SYS_move_mount,
      tree,
      "",
      AT_FDCWD,
      destination.c_str(),
      kMoveMountEmptyPath));
  const int error = result == 0 ? 0 : errno;
  ::close(tree);
  return error;
}

[[nodiscard]] int moveAttachedMount(
    const std::string& source,
    const std::string& destination) {
  errno = 0;
  const int result = static_cast<int>(::syscall(
      SYS_move_mount,
      AT_FDCWD,
      source.c_str(),
      AT_FDCWD,
      destination.c_str(),
      0));
  return result == 0 ? 0 : errno;
}

void attach(std::string rules) {
  const Policy policy = policyOf(R"toml([roles]

[roles.svc]
)toml" + std::move(rules));
  loadJailer(policy);
  ASSERT_OK(MountEnforcer::load(testPins(), policy));
}

[[nodiscard]] std::string mountRule(
    const std::string& path,
    std::optional<std::string_view> filesystems) {
  std::string result = "[[roles.svc.mount]]\npath = \"" + path + "\"\n";
  if (!filesystems.has_value()) {
    return result + "allow = false\n";
  }
  return result + "allow = true\nfilesystems = " + std::string(*filesystems) +
      "\n";
}

[[nodiscard]] std::string umountRule(const std::string& path, bool allow) {
  return "[[roles.svc.umount]]\npath = \"" + path +
      "\"\nallow = " + (allow ? "true\n" : "false\n");
}

} // namespace

TEST(MountEnforcer, LoadPinsEveryHook) {
  Fixture fixture;
  attach(mountRule(fixture.destination(), std::nullopt));

  ASSERT(linkPinned("bpfj_mount_new"));
  ASSERT(linkPinned("bpfj_mount_remount"));
  ASSERT(linkPinned("bpfj_mount_move_source"));
  ASSERT(linkPinned("bpfj_mount_remount_relay"));
  ASSERT(linkPinned("bpfj_remount"));
  ASSERT(linkPinned("bpfj_umount"));
  ASSERT(linkPinned("bpfj_move_mount_destination"));
  ASSERT(linkPinned("bpfj_move_mount_source"));
  ASSERT(linkPinned("bpfj_pivot_root_new"));
  ASSERT(linkPinned("bpfj_pivot_root_old"));
}

TEST(MountEnforcer, MissingMountPolicyDeniesMount) {
  Fixture fixture;
  attach("");

  Child actor([&] { return mountFs(fixture.destination(), "tmpfs"); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, MountAnyAllowsMount) {
  Fixture fixture;
  attach("mount-any = true\n");

  Child actor([&] { return mountFs(fixture.destination(), "tmpfs"); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(MountEnforcer, UnmatchedDestinationIsDenied) {
  Fixture fixture;
  attach(mountRule(fixture.destination(), std::nullopt));

  Child actor([&] { return mountFs(fixture.other(), "tmpfs"); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, DeniedMountRuleBlocksMount) {
  Fixture fixture;
  attach(mountRule(fixture.destination(), std::nullopt));

  Child actor([&] { return mountFs(fixture.destination(), "tmpfs"); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, FilesystemTypeListSelectsAllowedTypeAndAny) {
  Fixture fixture;
  attach(
      "umount-any = true\n" + mountRule(fixture.destination(), "[\"tmpfs\"]") +
      mountRule(fixture.other(), "[\"any\"]"));

  Child actor([&] {
    const int allowed = mountFs(fixture.destination(), "tmpfs");
    if (allowed != 0) {
      return 100 + allowed;
    }
    const int removed = unmount(fixture.destination());
    if (removed != 0) {
      return 200 + removed;
    }
    const int denied = mountFs(fixture.destination(), "proc");
    if (denied != EACCES) {
      return 300 + denied;
    }
    return mountFs(fixture.other(), "proc");
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(MountEnforcer, LongestDestinationOverridesRootDenial) {
  Fixture fixture;
  attach(
      mountRule(fixture.destination(), "[\"tmpfs\"]") +
      mountRule("/", std::nullopt));

  Child actor([&] {
    const int allowed = mountFs(fixture.destination(), "tmpfs");
    return allowed == 0 ? mountFs(fixture.other(), "tmpfs") : allowed;
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, MissingUmountPolicyDeniesUnmount) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.source(), "tmpfs"), 0);
  attach("mount-any = true\n");

  Child actor([&] { return unmount(fixture.source()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, DeeperUmountAllowOverridesRootDenial) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.source(), "tmpfs"), 0);
  ASSERT_EQ(mountFs(fixture.other(), "tmpfs"), 0);
  attach(
      "mount-any = true\n" + umountRule("/", false) +
      umountRule(fixture.source(), true));

  Child actor([&] {
    const int allowed = unmount(fixture.source());
    return allowed == 0 ? unmount(fixture.other()) : 100 + allowed;
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, UmountAnyAllowsUnmount) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.source(), "tmpfs"), 0);
  attach(
      "mount-any = true\n"
      "umount-any = true\n");

  Child actor([&] { return unmount(fixture.source()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(MountEnforcer, MoveMountRequiresDestinationPermission) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.source(), "tmpfs"), 0);
  attach(mountRule(fixture.destination(), std::nullopt));

  Child actor(
      [&] { return moveMount(fixture.source(), fixture.destination()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, MoveMountRequiresSourceUmountPermission) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.source(), "tmpfs"), 0);
  attach(
      mountRule(fixture.destination(), "[\"tmpfs\"]") + umountRule("/", false) +
      umountRule(fixture.other(), true));

  Child actor([&] {
    return moveAttachedMount(fixture.source(), fixture.destination());
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, MoveMountSucceedsWhenBothPermissionsAgree) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.source(), "tmpfs"), 0);
  attach(
      mountRule(fixture.destination(), "[\"tmpfs\"]") + umountRule("/", false) +
      umountRule(fixture.source(), true));

  Child actor([&] {
    return moveAttachedMount(fixture.source(), fixture.destination());
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(MountEnforcer, RemountUsesTheMountedFilesystemType) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.destination(), "tmpfs"), 0);
  attach(mountRule(fixture.destination(), "[\"tmpfs\"]"));

  Child actor(
      [&] { return mountFs(fixture.destination(), nullptr, MS_REMOUNT); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(MountEnforcer, RemountIsDeniedByFalseRule) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.destination(), "tmpfs"), 0);
  attach(mountRule(fixture.destination(), std::nullopt));

  Child actor(
      [&] { return mountFs(fixture.destination(), nullptr, MS_REMOUNT); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, OverrideStackedBoundsTheActorPolicyWalk) {
  Fixture fixture;
  const Policy policy = policyOf(
      "[roles.denied.mount]\n\"" + fixture.destination() +
      "\" = []\n"
      "[roles.override]\noverride-stacked = true\n"
      "[roles.override.mount]\n\"" +
      fixture.destination() +
      "\" = [\"tmpfs\"]\n"
      "[roles.top.mount]\n\"" +
      fixture.destination() + "\" = []\n");
  loadJailer(policy);
  ASSERT_OK(MountEnforcer::load(testPins(), policy));

  Child allowed([&] { return mountFs(fixture.destination(), "tmpfs"); });
  enroll("denied", allowed.pid());
  enroll("override", allowed.pid());
  ASSERT_EQ(allowed.run(), 0);
  ASSERT_EQ(unmount(fixture.destination()), 0);

  Child denied([&] { return mountFs(fixture.destination(), "tmpfs"); });
  enroll("denied", denied.pid());
  enroll("override", denied.pid());
  enroll("top", denied.pid());
  ASSERT_EQ(denied.run(), EACCES);
}
