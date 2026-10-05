// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
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

} // namespace

TEST(MountEnforcer, LoadPinsEveryHook) {
  Fixture fixture;
  attach("mount.\"" + fixture.destination() + "\" = []\n");

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
  attach("mount.\"" + fixture.destination() + "\" = []\n");

  Child actor([&] { return mountFs(fixture.other(), "tmpfs"); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, EmptyFilesystemListBlocksMount) {
  Fixture fixture;
  attach("mount.\"" + fixture.destination() + "\" = []\n");

  Child actor([&] { return mountFs(fixture.destination(), "tmpfs"); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, FilesystemTypeListSelectsAllowedTypeAndAny) {
  Fixture fixture;
  attach(
      "mount.\"" + fixture.destination() +
      "\" = [\"tmpfs\"]\n"
      "mount.\"" +
      fixture.other() +
      "\" = [\"any\"]\n"
      "umount-any = true\n");

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
      "mount.\"" + fixture.destination() +
      "\" = [\"tmpfs\"]\n"
      "mount.\"/\" = []\n");

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

TEST(MountEnforcer, DeeperUmountAnyOverridesRootNone) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.source(), "tmpfs"), 0);
  ASSERT_EQ(mountFs(fixture.other(), "tmpfs"), 0);
  attach(
      "mount-any = true\n"
      "[roles.svc.umount]\n"
      "\"/\" = \"NONE\"\n"
      "\"" +
      fixture.source() + "\" = \"ANY\"\n");

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
  attach("mount.\"" + fixture.destination() + "\" = []\n");

  Child actor(
      [&] { return moveMount(fixture.source(), fixture.destination()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(MountEnforcer, MoveMountRequiresSourceUmountPermission) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.source(), "tmpfs"), 0);
  attach(
      "mount.\"" + fixture.destination() +
      "\" = [\"tmpfs\"]\n"
      "[roles.svc.umount]\n"
      "\"/\" = \"NONE\"\n"
      "\"" +
      fixture.other() + "\" = \"ANY\"\n");

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
      "mount.\"" + fixture.destination() +
      "\" = [\"tmpfs\"]\n"
      "[roles.svc.umount]\n"
      "\"/\" = \"NONE\"\n"
      "\"" +
      fixture.source() + "\" = \"any\"\n");

  Child actor([&] {
    return moveAttachedMount(fixture.source(), fixture.destination());
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(MountEnforcer, RemountUsesTheMountedFilesystemType) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.destination(), "tmpfs"), 0);
  attach("mount.\"" + fixture.destination() + "\" = [\"tmpfs\"]\n");

  Child actor(
      [&] { return mountFs(fixture.destination(), nullptr, MS_REMOUNT); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(MountEnforcer, RemountIsDeniedByAnEmptyFilesystemList) {
  Fixture fixture;
  ASSERT_EQ(mountFs(fixture.destination(), "tmpfs"), 0);
  attach("mount.\"" + fixture.destination() + "\" = []\n");

  Child actor(
      [&] { return mountFs(fixture.destination(), nullptr, MS_REMOUNT); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}
