// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <string>

#include "bpfj/enforce/FsEnforcer.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/Pods.h"

using bpfjailer::FsEnforcer;
using bpfjailer::Policy;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

class Fixture {
 public:
  Fixture() {
    char path[] = "/tmp/bpfj-fs-test-XXXXXX";
    ASSERT(::mkdtemp(path) != nullptr);
    dir_ = path;
    file_ = dir_ + "/data";
    const int fd = ::open(file_.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    ASSERT(fd >= 0);
    ASSERT_EQ(::write(fd, "data", 4), 4);
    ASSERT_EQ(::close(fd), 0);
  }

  ~Fixture() {
    (void)::unlink((dir_ + "/renamed").c_str());
    (void)::unlink((dir_ + "/new").c_str());
    (void)::unlink(file_.c_str());
    (void)::rmdir(dir_.c_str());
  }

  const std::string& dir() const {
    return dir_;
  }

  const std::string& file() const {
    return file_;
  }

 private:
  std::string dir_;
  std::string file_;
};

void attach(const std::string& paths) {
  const Policy policy = policyOf("roles:\n  svc:\n    paths:\n" + paths);
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));
}

[[nodiscard]] int openErrno(const std::string& path, int flags) {
  errno = 0;
  const int fd = ::open(path.c_str(), flags | O_CLOEXEC);
  if (fd < 0) {
    return errno;
  }
  ::close(fd);
  return 0;
}

} // namespace

TEST(FsEnforcer, LoadPinsEveryHook) {
  Fixture fixture;
  attach("      " + fixture.file() + ": RDONLY\n");

  ASSERT(linkPinned("bpfj_fs_file_open"));
  ASSERT(linkPinned("bpfj_fs_inode_rename"));
  ASSERT(linkPinned("bpfj_fs_inode_rename_destination"));
  ASSERT(linkPinned("bpfj_fs_inode_link_source"));
  ASSERT(linkPinned("bpfj_fs_file_ioctl"));
}

TEST(FsEnforcer, ReadOnlyAllowsReadsAndDeniesWrites) {
  Fixture fixture;
  attach("      " + fixture.file() + ": RDONLY\n");

  Child actor([&] {
    const int readError = openErrno(fixture.file(), O_RDONLY);
    return readError != 0 ? readError : openErrno(fixture.file(), O_WRONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, NoneDeniesReads) {
  Fixture fixture;
  attach("      " + fixture.file() + ": NONE\n");

  Child actor([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, ReadWriteAllowsWrites) {
  Fixture fixture;
  attach("      " + fixture.file() + ": RDWR\n");

  Child actor([&] { return openErrno(fixture.file(), O_WRONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(FsEnforcer, LongestPathWins) {
  Fixture fixture;
  attach(
      "      " + fixture.dir() + ": NONE\n      " + fixture.file() +
      ": RDONLY\n");

  Child actor([&] {
    const int readError = openErrno(fixture.file(), O_RDONLY);
    return readError != 0 ? readError : openErrno(fixture.file(), O_WRONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, ReadOnlyDirectoryDeniesCreate) {
  Fixture fixture;
  attach("      " + fixture.dir() + ": RDONLY\n");

  Child actor(
      [&] { return openErrno(fixture.dir() + "/new", O_CREAT | O_WRONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, RenameInvalidatesTheCachedPath) {
  Fixture fixture;
  const std::string renamed = fixture.dir() + "/renamed";
  attach("      " + fixture.file() + ": RDWR\n      " + renamed + ": NONE\n");

  Child actor([&] {
    int error = openErrno(fixture.file(), O_RDONLY);
    if (error != 0) {
      return error;
    }
    if (::rename(fixture.file().c_str(), renamed.c_str()) != 0) {
      return errno;
    }
    return openErrno(renamed, O_RDONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, CacheSeparatesPodsWithDifferentVariableBindings) {
  char root[] = "/tmp/bpfj-fs-vars-test-XXXXXX";
  ASSERT(::mkdtemp(root) != nullptr);
  const std::string alice = std::string(root) + "/alice";
  ASSERT_EQ(::mkdir(alice.c_str(), 0700), 0);
  const std::string file = alice + "/data";
  int fd = ::open(file.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::close(fd), 0);

  const Policy policy = policyOf(
      "vars:\n  - USER\nroles:\n  svc:\n    paths:\n      " +
      std::string(root) + "/$USER/data: NONE\n");
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));

  Child alicePod([&] { return openErrno(file, O_RDONLY); });
  const std::array<bpfjailer::PodVar, 1> aliceVars{{{"USER", "alice"}}};
  ASSERT_OK(
      bpfjailer::enrollPod(
          testPins(),
          "svc",
          "alice@meta",
          aliceVars,
          alicePod.pid(),
          bpfjailer::Threads::All));
  ASSERT_EQ(alicePod.run(), EACCES);

  Child bobPod([&] { return openErrno(file, O_RDONLY); });
  const std::array<bpfjailer::PodVar, 1> bobVars{{{"USER", "bob"}}};
  ASSERT_OK(
      bpfjailer::enrollPod(
          testPins(),
          "svc",
          "bob@meta",
          bobVars,
          bobPod.pid(),
          bpfjailer::Threads::All));
  ASSERT_EQ(bobPod.run(), 0);

  ASSERT_EQ(::unlink(file.c_str()), 0);
  ASSERT_EQ(::rmdir(alice.c_str()), 0);
  ASSERT_EQ(::rmdir(root), 0);
}
