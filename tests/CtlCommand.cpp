// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/CtlCommand.h"

#include "tests/Harness.h"

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string_view>

#include "ctl/Dispatch.h"

namespace bpfjailer::test {

namespace {

// Stands in for "dispatch() returned nullopt". No command returns it: they
// answer 0, 1, argp's 64, or wrap's 127.
constexpr int kNoSuchCommand = 120;

[[nodiscard]] std::string drain(int fd) {
  if (::lseek(fd, 0, SEEK_SET) < 0) {
    return {};
  }

  std::string out;
  char buf[4096];
  for (;;) {
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n <= 0) {
      return out;
    }

    out.append(buf, static_cast<std::size_t>(n));
  }
}

} // namespace

CommandResult runCtl(const std::vector<std::string>& args) {
  return runCtl(args, {});
}

CommandResult runCtl(
    const std::vector<std::string>& args,
    std::string_view compiledPolicy) {
  CommandResult result;

  // memfds rather than pipes, which deadlock if the command outwrites the
  // buffer before exiting; dup2 clears close-on-exec, so these survive
  // `wrap`'s exec.
  const int outFd = ::memfd_create("bpfj-test-stdout", 0);
  const int errFd = ::memfd_create("bpfj-test-stderr", 0);
  if (outFd < 0 || errFd < 0) {
    result.status = -1;
    result.err = std::string("memfd_create: ") + std::strerror(errno);
    return result;
  }

  // argv[0] is the program name, because dispatch() reads the command from
  // argv[1] exactly as main() hands it over.
  std::vector<std::string> owned;
  owned.reserve(args.size() + 1);
  owned.emplace_back("bpfjctl");
  owned.insert(owned.end(), args.begin(), args.end());

  std::vector<char*> argv;
  argv.reserve(owned.size() + 1);
  for (auto& arg : owned) {
    argv.push_back(arg.data());
  }
  argv.push_back(nullptr);

  std::cout << std::flush;
  std::cerr << std::flush;

  const pid_t pid = ::fork();
  if (pid < 0) {
    result.status = -1;
    result.err = std::string("fork: ") + std::strerror(errno);
    ::close(outFd);
    ::close(errFd);
    return result;
  }

  if (pid == 0) {
    ::dup2(outFd, STDOUT_FILENO);
    ::dup2(errFd, STDERR_FILENO);

    const auto rc = ctl::dispatch(
        static_cast<int>(owned.size()), argv.data(), compiledPolicy);

    std::cout << std::flush;
    std::cerr << std::flush;
    ::_exit(rc ? *rc : kNoSuchCommand);
  }

  int status = 0;
  if (::waitpid(pid, &status, 0) < 0) {
    result.status = -1;
    result.err = std::string("waitpid: ") + std::strerror(errno);
  } else if (WIFSIGNALED(status)) {
    result.status = -1;
    result.signal = WTERMSIG(status);
  } else {
    result.status = WEXITSTATUS(status);
    result.dispatched = result.status != kNoSuchCommand;
  }

  result.out = drain(outFd);
  result.err = drain(errFd);

  // Kept for fail() rather than printed, plenty of tests running a command
  // they expect to fail; an unexpected one would otherwise report only
  // "lhs was 1, rhs was 0".
  if (result.status != 0) {
    std::string joined;
    for (const auto& arg : args) {
      joined += arg;
      joined += ' ';
    }
    noteDiagnostic(
        "      last failing bpfjctl: " + joined + "(status " +
        std::to_string(result.status) + ")\n" +
        (result.err.empty() ? std::string("      (no stderr)\n") : result.err));
  }
  ::close(outFd);
  ::close(errFd);

  return result;
}

} // namespace bpfjailer::test
