// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/enforce/ProcEnforcer.h"

using bpfjailer::Policy;
using bpfjailer::ProcEnforcer;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::noteDiagnostic;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

constexpr std::string_view kPolicy =
    "roles:\n"
    "  default-deny:\n"
    "  unrestricted:\n    any-proc: true\n"
    "  same-pod:\n    proc-pod: true\n"
    "  reader:\n    proc-roles:\n      - worker\n"
    "  worker:\n"
    "  other:\n";

void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(ProcEnforcer::load(testPins(), policy));
}

[[nodiscard]] int openProc(pid_t pid, const std::string& root = "/proc") {
  const std::string path = root + "/" + std::to_string(pid) + "/status";
  errno = 0;
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return errno;
  }
  ::close(fd);
  return 0;
}

[[nodiscard]] int runIsolated(
    std::string_view scenarioName,
    std::function<int()> body) {
  noteDiagnostic("      scenario: " + std::string(scenarioName) + "\n");
  Child scenario(std::move(body));
  return scenario.run();
}

[[nodiscard]] std::vector<pid_t> childrenOf(pid_t parent) {
  std::vector<pid_t> children;
  DIR* proc = ::opendir("/proc");
  if (!proc) {
    return children;
  }

  while (struct dirent* entry = ::readdir(proc)) {
    if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
      continue;
    }
    const pid_t pid = static_cast<pid_t>(::atoi(entry->d_name));
    const std::string path = "/proc/" + std::to_string(pid) + "/status";
    FILE* status = ::fopen(path.c_str(), "r");
    if (!status) {
      continue;
    }
    char line[256];
    while (::fgets(line, sizeof(line), status)) {
      int ppid = 0;
      if (::sscanf(line, "PPid:\t%d", &ppid) == 1) {
        if (ppid == parent) {
          children.push_back(pid);
        }
        break;
      }
    }
    ::fclose(status);
  }
  ::closedir(proc);
  std::sort(children.begin(), children.end());
  return children;
}

[[nodiscard]] int runPidNamespaceScenario() {
  int readyPipe[2] = {-1, -1};
  int goPipe[2] = {-1, -1};
  ASSERT_EQ(::pipe(readyPipe), 0);
  ASSERT_EQ(::pipe(goPipe), 0);

  const pid_t container = ::fork();
  ASSERT(container >= 0);
  if (container == 0) {
    ::close(readyPipe[0]);
    ::close(goPipe[1]);
    if (::unshare(CLONE_NEWPID | CLONE_NEWNS) != 0) {
      ::_exit(errno);
    }

    const pid_t init = ::fork();
    if (init > 0) {
      (void)::write(readyPipe[1], &init, sizeof(init));
      int status = 0;
      (void)::waitpid(init, &status, 0);
      ::_exit(WIFEXITED(status) ? WEXITSTATUS(status) : ECHILD);
    }
    if (init < 0) {
      ::_exit(errno);
    }

    char procRoot[] = "/tmp/bpfj-proc-XXXXXX";
    if (!::mkdtemp(procRoot) ||
        ::mount(
            "proc",
            procRoot,
            "proc",
            MS_NOSUID | MS_NOEXEC | MS_NODEV,
            nullptr) != 0) {
      ::_exit(errno);
    }

    const pid_t target = ::fork();
    if (target == 0) {
      ::pause();
      ::_exit(0);
    }
    const pid_t reader = ::fork();
    if (reader == 0) {
      char go = 0;
      if (::read(goPipe[0], &go, 1) != 1) {
        ::_exit(EPIPE);
      }
      ::_exit(openProc(target, procRoot));
    }

    const char ready = 1;
    (void)::write(readyPipe[1], &ready, 1);
    int readerStatus = 0;
    (void)::waitpid(reader, &readerStatus, 0);
    (void)::kill(target, SIGKILL);
    (void)::waitpid(target, nullptr, 0);
    (void)::umount(procRoot);
    (void)::rmdir(procRoot);
    ::_exit(WIFEXITED(readerStatus) ? WEXITSTATUS(readerStatus) : ECHILD);
  }

  ::close(readyPipe[1]);
  ::close(goPipe[0]);
  pid_t initHostPid = 0;
  ASSERT_EQ(
      ::read(readyPipe[0], &initHostPid, sizeof(initHostPid)),
      static_cast<ssize_t>(sizeof(initHostPid)));
  char ready = 0;
  ASSERT_EQ(::read(readyPipe[0], &ready, 1), 1);
  ::close(readyPipe[0]);

  const auto children = childrenOf(initHostPid);
  ASSERT_EQ(children.size(), 2);
  enroll("worker", children[0]);
  enroll("reader", children[1]);

  const char go = 1;
  ASSERT_EQ(::write(goPipe[1], &go, 1), 1);
  ::close(goPipe[1]);

  int status = 0;
  ASSERT_EQ(::waitpid(container, &status, 0), container);
  return WIFEXITED(status) ? WEXITSTATUS(status) : ECHILD;
}

} // namespace

TEST(ProcEnforcer, LoadAgainstAPolicyConfiguringNothingSucceeds) {
  attach("roles:\n  svc:\n");
  ASSERT(linkPinned("bpfj_proc_file_open"));
}

TEST(ProcEnforcer, EnforcesPodRoleAndAnyPolicies) {
  attach(std::string(kPolicy));
  ASSERT(linkPinned("bpfj_proc_file_open"));

  ASSERT_EQ(
      runIsolated(
          "an unconfigured role is denied",
          [] {
            Child target;
            enroll("default-deny", ::getpid());
            return openProc(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "any-proc reaches an unowned task",
          [] {
            Child target;
            enroll("unrestricted", ::getpid());
            return openProc(target.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "proc-pod reaches a task in the same pod",
          [] {
            enroll("same-pod", ::getpid());
            Child target;
            return openProc(target.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "proc-pod rejects another pod",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("same-pod", ::getpid());
            return openProc(target.pid());
          }),
      EPERM);

  ASSERT_EQ(
      runIsolated(
          "proc-roles reaches a named role",
          [] {
            Child target;
            enroll("worker", target.pid());
            enroll("reader", ::getpid());
            return openProc(target.pid());
          }),
      0);

  ASSERT_EQ(
      runIsolated(
          "proc-roles rejects another role",
          [] {
            Child target;
            enroll("other", target.pid());
            enroll("reader", ::getpid());
            return openProc(target.pid());
          }),
      EPERM);
}

TEST(ProcEnforcer, ResolvesPidInTheProcMountNamespace) {
  attach(std::string(kPolicy));
  ASSERT_EQ(runPidNamespaceScenario(), 0);
}
