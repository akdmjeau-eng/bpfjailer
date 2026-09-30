// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <argp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <string>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "ctl/Options.h"
#include "srv/Server.h"

const char* argp_program_version = "bpfjsrv 0.1";

namespace {

using bpfjailer::Expected;
using bpfjailer::makeErrnoError;
using bpfjailer::makeError;
using bpfjailer::makeUnexpected;
using bpfjailer::PinConfig;

struct SrvArgs {
  PinConfig pin;
};

constexpr char kDoc[] =
    "bpfjsrv -- enroll a connecting process in a pod"
    "\vSocket activated, one instance per connection. systemd passes the "
    "connected socket and bpfjsrv reads the peer's pid from it, so the process "
    "that connects is the process that gets jailed and there is nothing in the "
    "request naming another one.";

error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto* args = static_cast<SrvArgs*>(state->input);
  switch (key) {
    case ARGP_KEY_ARG:
      argp_usage(state);
      return 0;
    default:
      return bpfjailer::ctl::parsePinOpt(key, arg, args->pin);
  }
}

const struct argp kArgp = {
    bpfjailer::ctl::kPinOptions,
    parseOpt,
    nullptr,
    kDoc};

// systemd's first passed descriptor, as SD_LISTEN_FDS_START spells it.
constexpr int kListenFdsStart = 3;

/// @brief Whether systemd said it passed descriptors to this process, read
/// out of the environment rather than through sd_listen_fds() so `make srv`
/// can link statically. The LISTEN_PID check is what keeps a child from
/// inheriting the variables and claiming somebody else's descriptors.
[[nodiscard]] bool systemdPassedFds() noexcept {
  const char* listenPid = ::getenv("LISTEN_PID");
  const char* listenFds = ::getenv("LISTEN_FDS");
  if (listenPid == nullptr || listenFds == nullptr) {
    return false;
  }

  return std::atol(listenPid) == static_cast<long>(::getpid()) &&
      std::atol(listenFds) >= 1;
}

/// @brief The connected socket systemd handed over, on stdin with
/// StandardInput=socket or at fd 3 when the unit also sets LISTEN_FDS. The
/// descriptor is checked rather than assumed: a listening socket means the
/// unit was written with Accept=no, and serving it would block forever.
[[nodiscard]] Expected<int> connectionFd() noexcept {
  const int fd = systemdPassedFds() ? kListenFdsStart : STDIN_FILENO;

  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    return makeUnexpected(makeErrnoError(
        "no descriptor on fd ",
        std::to_string(fd),
        "; bpfjsrv is socket activated"));
  }

  if (!S_ISSOCK(st.st_mode)) {
    return makeUnexpected(makeError(
        std::errc::not_a_socket,
        "fd ",
        std::to_string(fd),
        " is not a socket; bpfjsrv has to be started by bpfjsrv.socket"));
  }

  int listening = 0;
  socklen_t len = sizeof(listening);
  if (::getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &len) != 0) {
    return makeUnexpected(makeErrnoError(
        "failed to check whether fd ", std::to_string(fd), " is listening"));
  }

  if (listening != 0) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "fd ",
        std::to_string(fd),
        " is a listening socket: bpfjsrv serves one connection and needs "
        "Accept=yes in bpfjsrv.socket"));
  }

  return fd;
}

/// @brief The credentials on the other end of `fd`, which decide both who
/// gets jailed and what they may ask for, so a connection whose peer cannot be
/// named is refused. A zero pid is what SO_PEERCRED reports for a peer in a
/// pid namespace this process cannot see into, where enrolling the number
/// anyway would jail whichever local task shared it.
[[nodiscard]] Expected<struct ucred> peerCredentials(int fd) noexcept {
  struct ucred cred{};
  socklen_t len = sizeof(cred);
  if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to read the peer's credentials"));
  }

  if (len != sizeof(cred) || cred.pid <= 0) {
    return makeUnexpected(makeError(
        std::errc::protocol_error,
        "the connection carries no peer pid, so there is nothing to enroll"));
  }

  return cred;
}

} // namespace

int main(int argc, char** argv) {
  SrvArgs args;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &args);

  auto conn = connectionFd();
  if (!conn) {
    std::cerr << "bpfjsrv: " << conn.error() << std::endl;
    return 1;
  }

  auto cred = peerCredentials(*conn);
  if (!cred) {
    std::cerr << "bpfjsrv: " << cred.error() << std::endl;
    return 1;
  }

  // Reports a refused request as well as one that could not be answered, in
  // more detail than the client is told: the uid belongs in the journal.
  if (auto res = bpfjailer::srv::serveConnection(
          *conn, cred->pid, cred->uid, args.pin);
      !res) {
    std::cerr << "bpfjsrv: pid " << cred->pid << " uid " << cred->uid << ": "
              << res.error() << std::endl;
    return 1;
  }

  return 0;
}
