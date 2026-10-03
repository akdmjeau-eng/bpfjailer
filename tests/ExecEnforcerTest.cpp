// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <string>

#include "bpfj/enforce/ExecEnforcer.h"

using bpfjailer::ExecEnforcer;
using bpfjailer::Policy;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

constexpr int kRanAndFailed = -1;

[[nodiscard]] std::string truePath() {
  return std::filesystem::canonical("/bin/true").string();
}

[[nodiscard]] std::string uniquePath(const std::string& prefix) {
  std::string dir = "/tmp/" + prefix + "-XXXXXX";
  ASSERT(::mkdtemp(dir.data()) != nullptr);
  return dir + "/file";
}

[[nodiscard]] std::string rule(
    const std::string& path,
    bool allowExec,
    bool allowSetuid,
    bool allowSharedObject) {
  return "      " + path + ":\n" +
      "        allow-exec: " + (allowExec ? "true\n" : "false\n") +
      "        allow-setuid: " + (allowSetuid ? "true\n" : "false\n") +
      "        allow-shared-object: " +
      (allowSharedObject ? "true\n" : "false\n");
}

[[nodiscard]] std::string execPolicy(
    const std::string& executable,
    bool allowExec,
    bool allowSetuid = false,
    bool allowSharedObjects = true) {
  return "roles:\n  svc:\n    exec-paths:\n" +
      rule("/usr/lib64/*", false, false, allowSharedObjects) +
      rule(executable, allowExec, allowSetuid, false);
}

void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(ExecEnforcer::load(testPins(), policy));
}

[[nodiscard]] int runProgram(const std::string& path) {
  int report[2] = {-1, -1};
  if (::pipe(report) != 0) {
    return errno;
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    return errno;
  }
  if (pid == 0) {
    ::close(report[0]);
    std::string owned = path;
    char* const argv[] = {owned.data(), nullptr};
    ::execv(owned.c_str(), argv);
    const int failed = errno;
    (void)::write(report[1], &failed, sizeof(failed));
    ::_exit(127);
  }

  ::close(report[1]);
  int failed = 0;
  const ssize_t n = ::read(report[0], &failed, sizeof(failed));
  ::close(report[0]);
  int status = 0;
  (void)::waitpid(pid, &status, 0);
  if (n == static_cast<ssize_t>(sizeof(failed))) {
    return failed;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : kRanAndFailed;
}

[[nodiscard]] std::string copyExecutable(mode_t mode) {
  const std::string path = uniquePath("exec-enforcer-true");
  std::filesystem::copy_file(
      truePath(), path, std::filesystem::copy_options::overwrite_existing);
  ASSERT_EQ(::chmod(path.c_str(), mode), 0);
  return path;
}

[[nodiscard]] int addExecutePermission(const std::string& path) {
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    return errno;
  }
  if (::ftruncate(fd, 4096) != 0) {
    const int failed = errno;
    ::close(fd);
    return failed;
  }
  void* mapping = ::mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (mapping == MAP_FAILED) {
    return errno;
  }
  const int result = ::mprotect(mapping, 4096, PROT_READ | PROT_EXEC);
  const int failed = result == 0 ? 0 : errno;
  ::munmap(mapping, 4096);
  return failed;
}

} // namespace

TEST(ExecEnforcer, LoadPinsEveryHook) {
  attach("roles:\n  svc:\n");

  ASSERT(linkPinned("bpfj_exec_bprm_check"));
  ASSERT(linkPinned("bpfj_exec_mmap_file"));
  ASSERT(linkPinned("bpfj_exec_file_mprotect"));
  ASSERT(linkPinned("bpfj_exec_inode_rename"));
}

TEST(ExecEnforcer, MissingPolicyDeniesExec) {
  const std::string executable = truePath();
  attach("roles:\n  svc:\n");

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, AllowedDynamicExecutableRuns) {
  const std::string executable = truePath();
  attach(execPolicy(executable, true));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, DeniedExecutableDoesNotRun) {
  const std::string executable = truePath();
  attach(execPolicy(executable, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, DeniedSharedObjectStopsDynamicProgram) {
  const std::string executable = truePath();
  attach(execPolicy(executable, true, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), kRanAndFailed);
}

TEST(ExecEnforcer, SetuidNeedsBothExecPermissions) {
  const std::string executable = copyExecutable(04755);
  attach(execPolicy(executable, true, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, AllowedSetuidExecutableRuns) {
  const std::string executable = copyExecutable(04755);
  attach(execPolicy(executable, true, true));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, FileMprotectNeedsSharedObjectPermission) {
  const std::string path = uniquePath("exec-enforcer-mprotect");
  attach("roles:\n  svc:\n    exec-paths:\n" + rule(path, false, false, false));

  Child actor([&] { return addExecutePermission(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, SharedObjectPermissionAllowsFileMprotect) {
  const std::string path = uniquePath("exec-enforcer-mprotect");
  attach("roles:\n  svc:\n    exec-paths:\n" + rule(path, false, false, true));

  Child actor([&] { return addExecutePermission(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, UnjailedProcessMayExec) {
  const std::string executable = truePath();
  attach(execPolicy(executable, false));

  Child actor([&] { return runProgram(executable); });

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, AnyAllowsExecutableAndSharedObjects) {
  const std::string executable = truePath();
  attach("roles:\n  svc:\n    any: true\n");

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, LongestPathMatchWins) {
  const std::string executable = truePath();
  attach(
      "roles:\n  svc:\n    exec-paths:\n" + rule("/usr", false, false, false) +
      rule("/usr/lib64/*", false, false, true) +
      rule(executable, true, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, EveryStackedRoleMustAllowExec) {
  const std::string executable = truePath();
  attach(
      "roles:\n  allow:\n    exec-paths:\n" +
      rule("/usr/lib64/*", false, false, true) +
      rule(executable, true, false, false) + "  deny:\n    exec-paths:\n" +
      rule("/usr/lib64/*", false, false, true) +
      rule(executable, false, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("allow", actor.pid());
  enroll("deny", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}
