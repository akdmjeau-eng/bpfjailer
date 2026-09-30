// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <dirent.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

using bpfjailer::test::bpffsPath;
using bpfjailer::test::exists;

namespace {

// Deliberately the same name in every test that writes, each checking the
// probe is absent first, so two tests sharing a mount would fail.
constexpr char kProbe[] = "probe";

[[nodiscard]] std::string probePath() {
  return bpffsPath() + "/" + kProbe;
}

[[nodiscard]] std::string readFile(const std::string& path) {
  std::ifstream in(path);
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

/// @brief How many tests the harness has in flight, this one included. Its
/// children are exactly its running tests: a test's own helpers are forked by
/// the test, not by the harness, and a finished one is reaped before the next
/// starts.
[[nodiscard]] int testsInFlight() {
  DIR* proc = ::opendir("/proc");
  if (proc == nullptr) {
    return -1;
  }

  const std::string parent = "PPid:\t" + std::to_string(::getppid());
  int found = 0;

  while (const dirent* entry = ::readdir(proc)) {
    if (::atoi(entry->d_name) <= 0) {
      continue;
    }

    std::ifstream status(std::string("/proc/") + entry->d_name + "/status");
    for (std::string line; std::getline(status, line);) {
      if (line.rfind("PPid:", 0) == 0) {
        found += line == parent ? 1 : 0;
        break;
      }
    }
  }

  ::closedir(proc);
  return found;
}

} // namespace

TEST(Harness, MountIsBpffs) {
  struct statfs sfs{};
  ASSERT_EQ(::statfs(bpffsPath().c_str(), &sfs), 0);
  ASSERT_EQ(
      static_cast<unsigned long>(sfs.f_type),
      static_cast<unsigned long>(BPF_FS_MAGIC));
}

TEST(Harness, MountIsWritable) {
  // Absence of the probe rather than an empty directory: the kernel seeds a
  // fresh bpffs with maps.debug and progs.debug, and may seed more.
  ASSERT(!exists(probePath()));
  ASSERT_EQ(::mkdir(probePath().c_str(), 0700), 0);

  struct stat st{};
  ASSERT_EQ(::stat(probePath().c_str(), &st), 0);
  ASSERT(S_ISDIR(st.st_mode));
}

TEST(Harness, MountAcceptsPins) {
  ASSERT(!exists(probePath()));

  // The right magic number is not a usable filesystem. Pinning is what the
  // jailer does to a bpffs, so pinning is what proves the mount real.
  const int fd = ::bpf_map_create(
      BPF_MAP_TYPE_HASH, "bpfj_probe", sizeof(int), sizeof(int), 1, nullptr);
  ASSERT(fd >= 0);

  ASSERT_EQ(::bpf_obj_pin(fd, probePath().c_str()), 0);
  ::close(fd);
  ASSERT(exists(probePath()));
}

TEST(Harness, MountIsNotSharedWithOtherTests) {
  // Both tests above leave a probe in their own mount, so seeing one here would
  // mean the mounts are the same.
  ASSERT(!exists(probePath()));
}

/// Exclusive because it asserts the thing TEST_EXCLUSIVE promises, so it is
/// also what keeps that promise honest: run it in the shared phase at -j2 or
/// wider and it fails.
TEST_EXCLUSIVE(Harness, AnExclusiveTestRunsAlone) {
  ASSERT_EQ(testsInFlight(), 1);
}

TEST(Harness, MountIsInvisibleToTheHarness) {
  // Positive control: without it the check below would also pass on a mount
  // that was never made.
  const std::string ownMounts = readFile("/proc/self/mountinfo");
  ASSERT(ownMounts.find(bpffsPath()) != std::string::npos);

  // The harness is the parent and never left the original mount namespace,
  // which is what has teeth against the unshare() going missing: per-test temp
  // directories alone would let every mount outlive the run.
  const std::string harnessMounts =
      readFile("/proc/" + std::to_string(::getppid()) + "/mountinfo");
  ASSERT(!harnessMounts.empty());
  ASSERT(harnessMounts.find(bpffsPath()) == std::string::npos);
}
