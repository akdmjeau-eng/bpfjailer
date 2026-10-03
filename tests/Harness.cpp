// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include "bpfj/enforce/Jailer.h"
#include "bpfj/fsverity/Keyctl.h"
#include "bpfj/fsverity/Keyring.h"

#include <bpf/bpf.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace bpfjailer::test {

namespace {

struct RegisteredTest {
  std::string suite;
  std::string name;
  TestBody body;
  bool exclusive = false;

  [[nodiscard]] std::string fullName() const {
    return suite + "." + name;
  }
};

// Function-local so a TEST in any translation unit can register before main()
// regardless of when this file's statics are constructed.
std::vector<RegisteredTest>& registry() {
  static std::vector<RegisteredTest> tests;
  return tests;
}

// Where every test's mountpoint, and everything a test writes beside it, lives
// for the length of the run. A tmpfs under build/, mounted inside the
// harness's own mount namespace, so the kernel takes it all down with the
// harness process and there is no cleanup path to get wrong.
std::string& runRoot() {
  static std::string path;
  return path;
}

// The fs-verity scratch filesystem, built once for the run rather than once
// per test. It used to be per test, which meant 36 ext4 images and 36 loop
// devices per run -- and a loop device is the one thing here that cannot be
// scoped to a namespace, because Linux has no namespace for block devices.
// They come from a global pool of 128 shared with everything else on the
// host, and LOOP_CTL_GET_FREE reports a number rather than reserving one, so
// churning through them is what made the harness race itself.
//
// One filesystem for the run costs one of those 128 and has nothing to race
// against. Each test still gets its own fixture directory inside it, which is
// all the isolation the fixtures need: fs-verity is a property of a file, and
// no two tests share one.
std::string& scratchRoot() {
  static std::string path;
  return path;
}

std::string& lastDiagnostic() {
  static std::string text;
  return text;
}

std::string& mountPath() {
  static std::string path;
  return path;
}

void unloadTestJailer() noexcept {
  if (!mountPath().empty()) {
    (void)Jailer::unload(PinConfig{.bpffsPath = mountPath()});
  }
}

[[nodiscard]] bool waitForBpfPolicyDetach();

constexpr int kFailExit = 1;
constexpr int kSetupExit = 2;

[[noreturn]] void exitChild(int status) {
  std::cout << std::flush;
  std::cerr << std::flush;
  // _exit, so the child does not run the parent's atexit handlers.
  ::_exit(status);
}

[[noreturn]] void failSetup(std::string_view what) {
  std::cerr << "      harness could not " << what << ": "
            << std::strerror(errno) << "\n";
  exitChild(kSetupExit);
}

/// @brief Run `argv` to completion. @return whether it exited 0.
[[nodiscard]] bool runTool(const std::vector<std::string>& args) {
  std::vector<char*> argv;
  argv.reserve(args.size() + 1);
  for (const auto& arg : args) {
    argv.push_back(const_cast<char*>(arg.c_str()));
  }
  argv.push_back(nullptr);

  std::cout << std::flush;
  std::cerr << std::flush;

  const pid_t pid = ::fork();
  if (pid < 0) {
    return false;
  }

  if (pid == 0) {
    const int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDOUT_FILENO);
      ::dup2(devnull, STDERR_FILENO);
    }

    ::execvp(argv[0], argv.data());
    ::_exit(127);
  }

  int status = 0;
  return ::waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
      WEXITSTATUS(status) == 0;
}

/// @brief A loop device, and a descriptor holding it open. See attachLoop().
struct LoopDevice {
  std::string path;
  int fd = -1;
};

/// @brief Attach `image` to a free loop device, by hand rather than by
/// shelling out so LO_FLAGS_AUTOCLEAR detaches it with the dying mount
/// namespace. The returned descriptor must stay open until the filesystem is
/// mounted, or closing it is itself the last reference and the mount gets EIO.
[[nodiscard]] LoopDevice attachLoop(const std::string& image) {
  const int control = ::open("/dev/loop-control", O_RDWR | O_CLOEXEC);
  if (control < 0) {
    return {};
  }

  const int number = ::ioctl(control, LOOP_CTL_GET_FREE);
  ::close(control);
  if (number < 0) {
    return {};
  }

  const std::string device = "/dev/loop" + std::to_string(number);
  const int deviceFd = ::open(device.c_str(), O_RDWR | O_CLOEXEC);
  if (deviceFd < 0) {
    return {};
  }

  const int imageFd = ::open(image.c_str(), O_RDWR | O_CLOEXEC);
  if (imageFd < 0) {
    ::close(deviceFd);
    return {};
  }

  // One ioctl, so the device is never briefly attached without autoclear set.
  struct loop_config config{};
  config.fd = static_cast<__u32>(imageFd);
  config.info.lo_flags = LO_FLAGS_AUTOCLEAR;

  const bool configured = ::ioctl(deviceFd, LOOP_CONFIGURE, &config) == 0;
  ::close(imageFd);

  if (!configured) {
    ::close(deviceFd);
    return {};
  }

  return LoopDevice{device, deviceFd};
}

/// @brief Send the child's output to `log`, so a run several tests wide can
/// print each test's output in one piece when it finishes rather than
/// interleaved with whatever else was running.
void captureOutput(const std::string& log) {
  const int fd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    failSetup("open its output file");
  }

  if (::dup2(fd, STDOUT_FILENO) < 0 || ::dup2(fd, STDERR_FILENO) < 0) {
    failSetup("redirect its output");
  }
  ::close(fd);
}

/// @brief Set up the test's private world in the forked child and run it, so
/// everything it changes dies with the test. Does not return.
[[noreturn]] void runChild(
    const RegisteredTest& test,
    const std::string& dir,
    const std::string& log) {
  captureOutput(log);

  // A process group of its own, so the harness can be sure the test takes
  // everything it forked with it; a failed assertion _exits without running
  // destructors, and helper processes hold the mount namespace open.
  if (::setpgid(0, 0) != 0) {
    failSetup("put the test in its own process group");
  }

  // A retiring LSM fork hook can enroll this freshly forked process even
  // after the preceding test has closed its links. Probe from the child that
  // will actually run the test, and do not begin until that inherited policy
  // has stopped denying bpf(2).
  if (!waitForBpfPolicyDetach()) {
    errno = EPERM;
    failSetup("wait for the previous BPF policy to detach");
  }

  if (::unshare(CLONE_NEWNS) != 0) {
    failSetup("unshare a mount namespace");
  }

  // Distributions generally leave / shared, and a mount under a shared parent
  // propagates straight back out into the harness.
  if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
    failSetup("make the mount tree private");
  }

  if (::mount("bpf", dir.c_str(), "bpf", 0, nullptr) != 0) {
    failSetup("mount a bpffs");
  }

  // A session keyring of this test's own. The fs-verity enforcer links what
  // it builds into whatever setKeyringPersistTarget() names, and pointing
  // that at a session rather than at the uid's keyring is what makes those
  // keyrings the test's: inherited by everything it forks and execs, so
  // verification inside its own process tree still possesses them, and reaped
  // by the kernel once the last of those exits. Nothing is left to sweep up,
  // and nothing of this test's is visible to the next one -- or to a
  // bpfjailerd on the same host, whose keyrings are in the uid's keyring and
  // are none of the harness's business.
  const keyctl::Serial session = keyctl::joinSessionKeyring();
  if (session < 0) {
    failSetup("join a session keyring");
  }

  // By serial, not KEY_SPEC_SESSION_KEYRING. A load that models bpfjctl runs
  // in a process that joins a session keyring of its own and then exits, so
  // the symbolic name would resolve to *that* keyring and the enforcer's
  // keyrings would die with the loader -- which is the one thing persist()
  // exists to prevent. Naming this test's session keyring outright gives the
  // lifetime the tests actually want: longer than any loader, shorter than
  // the run.
  // A joined session keyring is alswrv for the possessor and rv for the
  // owner, so a process that joined a session of its own -- which is how the
  // tests model bpfjctl -- cannot link into this one: it no longer possesses
  // it, and the owner's half has no write bit. Widening the owner's half is
  // what lets those loads persist here. It is this test's keyring and it dies
  // with it, and root could write it anyway.
  if (keyctl::setperm(session, keyctl::kPossessorAll | keyctl::kUserAll) < 0) {
    failSetup("open the session keyring to its owner");
  }

  setKeyringPersistTarget(session);

  mountPath() = dir;
  test.body();
  unloadTestJailer();
  exitChild(0);
}

/// @brief Why a test's exit status means it failed, or empty if it passed.
[[nodiscard]] std::string diagnose(int status) {
  if (WIFSIGNALED(status)) {
    const int sig = WTERMSIG(status);
    return std::string("died on signal ") + std::to_string(sig) + " (" +
        ::strsignal(sig) + ")";
  }

  if (!WIFEXITED(status)) {
    return "stopped without exiting";
  }

  switch (WEXITSTATUS(status)) {
    case 0:
      return {};
    case kFailExit:
      // fail() already printed the assertion.
      return "assertion failed";
    case kSetupExit:
      return "harness setup failed";
    default:
      return "exited with status " + std::to_string(WEXITSTATUS(status));
  }
}

/// @brief Report a run-root setup failure and stop. Does not return.
[[noreturn]] void failRunRoot(std::string_view what) {
  std::cerr << "harness could not " << what << ": " << std::strerror(errno)
            << "\n";
  ::_exit(1);
}

void buildScratchFs() {
  // Directly in the run root, already a tmpfs in the harness's own mount
  // namespace, so the image, the loop device and the ext4 all go when it
  // does.
  const std::string base = runRoot() + "/scratch";
  if (::mkdir(base.c_str(), 0700) != 0) {
    failRunRoot("create a scratch directory");
  }

  const std::string image = base + "/ext4.img";
  const int imageFd = ::open(image.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
  if (imageFd < 0) {
    failRunRoot("create the scratch filesystem image");
  }
  if (::ftruncate(imageFd, 512L * 1024 * 1024) != 0) {
    failRunRoot("size the scratch filesystem image");
  }
  ::close(imageFd);

  // -b 4096 because fs-verity needs the block size to be the page size, and
  // -I 256 because mkfs otherwise pairs an image this small with inodes too
  // narrow for the verity descriptor.
  if (!runTool(
          {"mkfs.ext4",
           "-q",
           "-F",
           "-b",
           "4096",
           "-I",
           "256",
           "-O",
           "verity",
           image})) {
    failRunRoot("make an ext4 filesystem with verity support");
  }

  const LoopDevice loop = attachLoop(image);
  if (loop.fd < 0) {
    failRunRoot("attach the scratch filesystem image to a loop device");
  }

  const std::string mount = base + "/mnt";
  if (::mkdir(mount.c_str(), 0700) != 0) {
    failRunRoot("create the scratch filesystem mountpoint");
  }
  if (::mount(loop.path.c_str(), mount.c_str(), "ext4", 0, nullptr) != 0) {
    failRunRoot("mount the scratch filesystem");
  }

  // Safe only now the mount holds the device.
  ::close(loop.fd);

  scratchRoot() = mount;
}

/// @brief Put the harness in its own mount namespace and mount the run root,
/// before the first test forks and unshares again on top of it.
void setUpRunRoot() {
  if (::unshare(CLONE_NEWNS) != 0) {
    std::cerr << "harness could not unshare a mount namespace: "
              << std::strerror(errno) << "\n";
    ::_exit(1);
  }

  // Same reason the tests do it, or the mount outlives this process.
  if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
    std::cerr << "harness could not make the mount tree private: "
              << std::strerror(errno) << "\n";
    ::_exit(1);
  }

  // Relative to the tree root, where `make test` starts the harness.
  const std::string root = "build/test-run";
  if (::mkdir(root.c_str(), 0700) != 0 && errno != EEXIST) {
    std::cerr << "harness could not create " << root << ": "
              << std::strerror(errno) << "\n";
    ::_exit(1);
  }

  // Sized for mountpoints and a policy file each; the fs-verity fixtures get a
  // tmpfs of their own under scratchFsPath().
  if (::mount("tmpfs", root.c_str(), "tmpfs", 0, "size=1g") != 0) {
    std::cerr << "harness could not mount a tmpfs on " << root << ": "
              << std::strerror(errno) << "\n";
    ::_exit(1);
  }

  runRoot() = root;

  buildScratchFs();
}

/// @brief Wait until no process of `pgid`'s group is left, since SIGKILL is a
/// request and the mount namespace lives until the last of them goes -- with
/// the test's bpffs mounted, its LSM programs still enforcing, and its loop
/// device held against LO_FLAGS_AUTOCLEAR. Polled on `kill(0)` rather than
/// waitpid(), these being orphans by now, and the deadline only bounds the
/// damage of a process wedged in D state.
void drainGroup(pid_t pgid) {
  constexpr auto kDeadline = std::chrono::seconds(10);
  constexpr auto kPoll = std::chrono::microseconds(200);

  const auto giveUp = std::chrono::steady_clock::now() + kDeadline;
  while (::killpg(pgid, 0) == 0) {
    if (std::chrono::steady_clock::now() >= giveUp) {
      std::cerr << "      harness timed out waiting for the test's process "
                   "group to exit\n";
      return;
    }
    std::this_thread::sleep_for(kPoll);
  }
}

[[nodiscard]] bool waitForBpfPolicyDetach() {
  constexpr auto kDeadline = std::chrono::seconds(10);
  constexpr auto kPoll = std::chrono::milliseconds(1);

  const auto giveUp = std::chrono::steady_clock::now() + kDeadline;
  while (std::chrono::steady_clock::now() < giveUp) {
    const int fd = ::bpf_map_create(
        BPF_MAP_TYPE_HASH,
        "bpfj_teardown",
        sizeof(std::uint32_t),
        sizeof(std::uint32_t),
        1,
        nullptr);
    if (fd >= 0) {
      ::close(fd);
      // A closed LSM link has stopped denying bpf(2) by here. Leave one short
      // grace period so its fork hook cannot seed work while the kernel
      // finishes detaching the link set.
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      return true;
    }
    if (errno != EPERM) {
      return true;
    }
    std::this_thread::sleep_for(kPoll);
  }

  std::cerr << "      harness timed out waiting for BPF policy teardown\n";
  return false;
}

[[nodiscard]] std::vector<std::uint32_t> bpfjProgramIds() {
  std::vector<std::uint32_t> ids;
  std::uint32_t id = 0;
  std::uint32_t next = 0;
  while (::bpf_prog_get_next_id(id, &next) == 0) {
    const int fd = ::bpf_prog_get_fd_by_id(next);
    if (fd >= 0) {
      struct bpf_prog_info info{};
      std::uint32_t size = sizeof(info);
      if (::bpf_obj_get_info_by_fd(fd, &info, &size) == 0 &&
          std::string_view(info.name).starts_with("bpfj_")) {
        ids.push_back(next);
      }
      ::close(fd);
    }
    id = next;
  }
  return ids;
}

[[nodiscard]] std::vector<std::uint32_t> bpfjMapIds() {
  std::vector<std::uint32_t> ids;
  std::uint32_t id = 0;
  std::uint32_t next = 0;
  while (::bpf_map_get_next_id(id, &next) == 0) {
    const int fd = ::bpf_map_get_fd_by_id(next);
    if (fd >= 0) {
      struct bpf_map_info info{};
      std::uint32_t size = sizeof(info);
      if (::bpf_obj_get_info_by_fd(fd, &info, &size) == 0 &&
          std::string_view(info.name).starts_with("bpfj_")) {
        ids.push_back(next);
      }
      ::close(fd);
    }
    id = next;
  }
  return ids;
}

template <typename ListIds, typename OpenById>
void waitForBpfObjectsGone(
    const std::vector<std::uint32_t>& baseline,
    ListIds listIds,
    OpenById openById,
    std::string_view kind) {
  std::vector<std::uint32_t> created;
  for (const std::uint32_t id : listIds()) {
    if (std::find(baseline.begin(), baseline.end(), id) == baseline.end()) {
      created.push_back(id);
    }
  }

  constexpr auto kDeadline = std::chrono::seconds(10);
  constexpr auto kPoll = std::chrono::milliseconds(1);
  const auto giveUp = std::chrono::steady_clock::now() + kDeadline;
  while (!created.empty() && std::chrono::steady_clock::now() < giveUp) {
    std::erase_if(created, [openById](std::uint32_t id) {
      const int fd = openById(id);
      if (fd >= 0) {
        ::close(fd);
        return false;
      }
      return errno == ENOENT;
    });
    if (!created.empty()) {
      std::this_thread::sleep_for(kPoll);
    }
  }

  if (!created.empty()) {
    std::cerr << "      harness timed out waiting for " << created.size()
              << " BPF " << kind << "(s) to detach\n";
  }
}

/// @brief A test that has been forked and not yet reaped.
struct Running {
  const RegisteredTest* test = nullptr;
  pid_t pid = -1;
  // The test's own directory, holding the two below and nothing else.
  std::string dir;
  // Where its bpffs is mounted. A level down from `dir` so that `dir` can also
  // hold the log, which a mount over it would hide.
  std::string mnt;
  std::string log;
  std::vector<std::uint32_t> baselinePrograms;
  std::vector<std::uint32_t> baselineMaps;
  std::chrono::steady_clock::time_point started;
};

/// @brief Fork `test`. @return nullopt if it could not be started.
[[nodiscard]] std::optional<Running> launch(const RegisteredTest& test) {
  std::string dir = runRoot() + "/bpfj-test-XXXXXX";
  if (::mkdtemp(dir.data()) == nullptr) {
    std::cerr << "      harness could not create a temp dir: "
              << std::strerror(errno) << "\n";
    return std::nullopt;
  }

  const std::string mnt = dir + "/mnt";
  if (::mkdir(mnt.c_str(), 0700) != 0) {
    std::cerr << "      harness could not create " << mnt << ": "
              << std::strerror(errno) << "\n";
    ::rmdir(dir.c_str());
    return std::nullopt;
  }

  const std::string log = dir + "/out";
  auto baselinePrograms = bpfjProgramIds();
  auto baselineMaps = bpfjMapIds();

  std::cout << std::flush;
  std::cerr << std::flush;

  const pid_t pid = ::fork();
  if (pid < 0) {
    std::cerr << "      harness could not fork: " << std::strerror(errno)
              << "\n";
    ::rmdir(mnt.c_str());
    ::rmdir(dir.c_str());
    return std::nullopt;
  }

  if (pid == 0) {
    runChild(test, mnt, log);
  }

  return Running{
      &test,
      pid,
      dir,
      mnt,
      log,
      std::move(baselinePrograms),
      std::move(baselineMaps),
      std::chrono::steady_clock::now()};
}

void printLog(const std::string& path) {
  std::ifstream in(path);
  // Inserting an empty streambuf sets failbit, which would silence every
  // report after the first test that printed nothing.
  if (in && in.peek() != std::ifstream::traits_type::eof()) {
    std::cout << in.rdbuf();
  }
}

/// @brief Clean up after a reaped test and report it. @return whether it
/// passed.
[[nodiscard]] bool reap(const Running& run, int status) {
  // Anything the test forked and did not reap keeps its mount namespace alive
  // past the test; ESRCH is the ordinary answer.
  (void)::killpg(run.pid, SIGKILL);
  drainGroup(run.pid);
  waitForBpfObjectsGone(
      run.baselinePrograms, bpfjProgramIds, ::bpf_prog_get_fd_by_id, "program");
  waitForBpfObjectsGone(
      run.baselineMaps, bpfjMapIds, ::bpf_map_get_fd_by_id, "map");
  (void)waitForBpfPolicyDetach();

  const std::string name = run.test->fullName();
  std::string problem = diagnose(status);

  // One piece, now the test is over, rather than around it: several tests are
  // in flight and interleaved output belongs to no one.
  std::cout << "[ RUN      ] " << name << "\n";
  printLog(run.log);

  // The bpffs lived in the child's namespace, so EBUSY means the mount escaped
  // into the harness and tests would quietly collide.
  if (::rmdir(run.mnt.c_str()) != 0) {
    std::cout << "      harness could not remove " << run.mnt << ": "
              << std::strerror(errno) << "\n";
    if (problem.empty()) {
      problem = "test namespace leaked its mount";
    }
  }

  ::unlink(run.log.c_str());
  ::rmdir(run.dir.c_str());

  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - run.started)
                      .count();

  if (problem.empty()) {
    std::cout << "[       OK ] " << name << " (" << ms << " ms)" << std::endl;
    return true;
  }

  std::cout << "[  FAILED  ] " << name << " (" << ms << " ms): " << problem
            << std::endl;
  return false;
}

/// @brief Run `tests`, `jobs` of them at a time, collecting the names of those
/// that failed.
void runPhase(
    const std::vector<const RegisteredTest*>& tests,
    int jobs,
    std::vector<std::string>& failed) {
  std::vector<Running> live;
  std::size_t next = 0;

  while (next < tests.size() || !live.empty()) {
    while (static_cast<int>(live.size()) < jobs && next < tests.size()) {
      auto started = launch(*tests[next]);
      if (started) {
        live.push_back(std::move(*started));
      } else {
        failed.push_back(tests[next]->fullName());
      }
      ++next;
    }

    // Every launch in that batch failed; go round and try the rest.
    if (live.empty()) {
      continue;
    }

    int status = 0;
    const pid_t done = ::waitpid(-1, &status, 0);
    if (done < 0) {
      if (errno == EINTR) {
        continue;
      }
      std::cerr << "      harness could not wait for a test: "
                << std::strerror(errno) << "\n";
      break;
    }

    const auto at =
        std::find_if(live.begin(), live.end(), [done](const Running& running) {
          return running.pid == done;
        });
    if (at == live.end()) {
      continue;
    }

    if (!reap(*at, status)) {
      failed.push_back(at->test->fullName());
    }
    live.erase(at);
  }
}

} // namespace

bool registerTest(
    const char* suite,
    const char* name,
    TestBody body,
    bool exclusive) {
  registry().push_back(RegisteredTest{suite, name, body, exclusive});
  return true;
}

int defaultJobs() {
  if (const char* env = ::getenv("BPFJTEST_JOBS")) {
    const int jobs = std::atoi(env);
    if (jobs > 0) {
      return jobs;
    }
  }

  return 1;
}

const std::string& scratchFsPath() {
  return scratchRoot();
}

const std::string& bpffsPath() {
  return mountPath();
}

bool exists(const std::string& path) {
  return ::access(path.c_str(), F_OK) == 0;
}

void fail(
    const char* file,
    int line,
    std::string_view expression,
    std::string_view detail) {
  std::cerr << "      " << file << ":" << line << ": " << expression << "\n";
  if (!detail.empty()) {
    std::cerr << detail << "\n";
  }

  if (!lastDiagnostic().empty()) {
    std::cerr << lastDiagnostic();
  }

  unloadTestJailer();
  exitChild(kFailExit);
}

void noteDiagnostic(std::string text) {
  lastDiagnostic() = std::move(text);
}

int runAll(int jobs, std::string_view selection) {
  if (jobs < 1) {
    jobs = 1;
  }

  const auto& tests = registry();

  std::vector<const RegisteredTest*> shared;
  std::vector<const RegisteredTest*> exclusive;
  for (const auto& test : tests) {
    if (!selection.empty() && selection != test.suite &&
        selection != test.fullName()) {
      continue;
    }
    (test.exclusive ? exclusive : shared).push_back(&test);
  }

  const std::size_t selected = shared.size() + exclusive.size();
  if (selected == 0) {
    std::cerr << "bpfjtest: no suite or test named '" << selection << "'\n";
    return 1;
  }

  setUpRunRoot();

  std::cout << "[==========] Running " << selected << " test(s), " << jobs
            << " at a time";
  if (!exclusive.empty()) {
    std::cout << ", then " << exclusive.size() << " on their own";
  }
  std::cout << std::endl;

  std::vector<std::string> failed;
  runPhase(shared, jobs, failed);

  // After, not before: an exclusive test is one that cannot tolerate another
  // test's enforcement, and the shared phase is what would supply it.
  runPhase(exclusive, 1, failed);

  std::cout << "[==========] " << selected - failed.size() << "/" << selected
            << " passed" << std::endl;
  for (const auto& name : failed) {
    std::cout << "[  FAILED  ] " << name << std::endl;
  }

  return failed.empty() ? 0 : 1;
}

} // namespace bpfjailer::test
