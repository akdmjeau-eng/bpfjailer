// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>

#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/UnixEnforcer.h"

using bpfjailer::PodVar;
using bpfjailer::Policy;
using bpfjailer::UnixEnforcer;
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
    char path[] = "/tmp/bpfj-unix-test-XXXXXX";
    ASSERT(::mkdtemp(path) != nullptr);
    dir_ = path;
  }

  ~Fixture() {
    (void)::unlink(socket_.c_str());
    (void)::unlink(other_.c_str());
    (void)::rmdir(dir_.c_str());
  }

  const std::string& dir() const {
    return dir_;
  }
  const std::string& socket() {
    socket_ = dir_ + "/socket";
    return socket_;
  }
  const std::string& other() {
    other_ = dir_ + "/other";
    return other_;
  }
  std::string abstractName(std::string_view suffix) const {
    return "bpfj-unix-" + std::to_string(::getpid()) + "-" +
        std::string(suffix);
  }

 private:
  std::string dir_;
  std::string socket_;
  std::string other_;
};

[[nodiscard]] sockaddr_un pathname(std::string_view name) {
  sockaddr_un address{.sun_family = AF_UNIX};
  ASSERT(name.size() < sizeof(address.sun_path));
  std::memcpy(address.sun_path, name.data(), name.size());
  address.sun_path[name.size()] = '\0';
  return address;
}

[[nodiscard]] sockaddr_un abstract(std::string_view name) {
  sockaddr_un address{.sun_family = AF_UNIX};
  ASSERT(name.size() + 1 < sizeof(address.sun_path));
  address.sun_path[0] = '\0';
  std::memcpy(address.sun_path + 1, name.data(), name.size());
  return address;
}

[[nodiscard]] socklen_t abstractLength(std::string_view name) {
  return static_cast<socklen_t>(
      offsetof(sockaddr_un, sun_path) + 1 + name.size());
}

[[nodiscard]] int bindPath(std::string_view name) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return errno;
  }
  const auto address = pathname(name);
  errno = 0;
  const int result =
      ::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
  const int error = result == 0 ? 0 : errno;
  ::close(fd);
  return error;
}

[[nodiscard]] int bindAbstract(std::string_view name) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return errno;
  }
  const auto address = abstract(name);
  errno = 0;
  const int result = ::bind(
      fd, reinterpret_cast<const sockaddr*>(&address), abstractLength(name));
  const int error = result == 0 ? 0 : errno;
  ::close(fd);
  return error;
}

[[nodiscard]] int listenPath(std::string_view name, int type) {
  const int fd = ::socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
  ASSERT(fd >= 0);
  const auto address = pathname(name);
  ASSERT_EQ(
      ::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)),
      0);
  if (type == SOCK_STREAM) {
    ASSERT_EQ(::listen(fd, 1), 0);
  }
  return fd;
}

[[nodiscard]] int listenAbstract(std::string_view name, int type) {
  const int fd = ::socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
  ASSERT(fd >= 0);
  const auto address = abstract(name);
  ASSERT_EQ(
      ::bind(
          fd,
          reinterpret_cast<const sockaddr*>(&address),
          abstractLength(name)),
      0);
  if (type == SOCK_STREAM) {
    ASSERT_EQ(::listen(fd, 1), 0);
  }
  return fd;
}

[[nodiscard]] int connectPath(std::string_view name) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return errno;
  }
  const auto address = pathname(name);
  errno = 0;
  const int result = ::connect(
      fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
  const int error = result == 0 ? 0 : errno;
  ::close(fd);
  return error;
}

[[nodiscard]] int connectAbstract(std::string_view name) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return errno;
  }
  const auto address = abstract(name);
  errno = 0;
  const int result = ::connect(
      fd, reinterpret_cast<const sockaddr*>(&address), abstractLength(name));
  const int error = result == 0 ? 0 : errno;
  ::close(fd);
  return error;
}

[[nodiscard]] int sendPath(std::string_view name) {
  const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return errno;
  }
  const auto address = pathname(name);
  errno = 0;
  const int result = static_cast<int>(::sendto(
      fd,
      "x",
      1,
      0,
      reinterpret_cast<const sockaddr*>(&address),
      sizeof(address)));
  const int error = result == 1 ? 0 : errno;
  ::close(fd);
  return error;
}

[[nodiscard]] int sendAbstract(std::string_view name) {
  const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return errno;
  }
  const auto address = abstract(name);
  errno = 0;
  const int result = static_cast<int>(::sendto(
      fd,
      "x",
      1,
      0,
      reinterpret_cast<const sockaddr*>(&address),
      abstractLength(name)));
  const int error = result == 1 ? 0 : errno;
  ::close(fd);
  return error;
}

void attach(std::string rules, std::string vars = {}) {
  const Policy policy = policyOf(vars + R"toml([roles]

[roles.svc]
)toml" + std::move(rules));
  loadJailer(policy);
  ASSERT_OK(UnixEnforcer::load(testPins(), policy));
}

[[nodiscard]] std::string
rule(std::string_view operation, const std::string& path, bool allow) {
  const std::string_view selector = path.starts_with('@') ? "name" : "path";
  return "[[roles.svc." + std::string(operation) + "]]\n" +
      std::string(selector) + " = \"" + path +
      "\"\nallow = " + (allow ? "true\n" : "false\n");
}

} // namespace

TEST(UnixEnforcer, LoadPinsEveryHook) {
  Fixture fixture;
  attach(rule("unix-bind", fixture.socket(), false));

  ASSERT(linkPinned("bpfj_unix_path_bind"));
  ASSERT(linkPinned("bpfj_unix_abstract_bind"));
  ASSERT(linkPinned("bpfj_unix_abstract_connect"));
  ASSERT(linkPinned("bpfj_unix_stream_connect"));
  ASSERT(linkPinned("bpfj_unix_dgram_send_path"));
  ASSERT(linkPinned("bpfj_unix_dgram_send_abstract"));
}

TEST(UnixEnforcer, UnmatchedPathIsDenied) {
  Fixture fixture;
  attach(rule("unix-bind", fixture.socket(), false));

  Child actor([&] { return bindPath(fixture.other()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(UnixEnforcer, MissingPathPolicyIsDenied) {
  Fixture fixture;
  attach("");

  Child actor([&] { return bindPath(fixture.socket()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(UnixEnforcer, MissingAbstractPolicyIsAllowed) {
  attach("");

  Child actor([] { return bindAbstract("bpfj-unconfigured"); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(UnixEnforcer, AnyAllowsUnconfiguredPathOperation) {
  Fixture fixture;
  attach("any = true\n");

  Child actor([&] { return bindPath(fixture.socket()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(UnixEnforcer, LongestPathOverridesRootDefault) {
  Fixture fixture;
  attach(
      rule("unix-bind", "/", false) +
      rule("unix-bind", fixture.socket(), true));

  Child actor([&] {
    const int allowed = bindPath(fixture.socket());
    return allowed == 0 ? bindPath(fixture.other()) : 100 + allowed;
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(UnixEnforcer, ConnectPolicyUsesServerPath) {
  Fixture fixture;
  const int listener = listenPath(fixture.socket(), SOCK_STREAM);
  attach(rule("unix-connect", fixture.socket(), false));

  Child actor([&] { return connectPath(fixture.socket()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
  ::close(listener);
}

TEST(UnixEnforcer, DatagramPolicyUsesDestinationPath) {
  Fixture fixture;
  const int receiver = listenPath(fixture.socket(), SOCK_DGRAM);
  attach(rule("unix-dgram", fixture.socket(), false));

  Child actor([&] { return sendPath(fixture.socket()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
  ::close(receiver);
}

TEST(UnixEnforcer, AbstractGlobMostSpecificRuleWins) {
  attach(
      rule("unix-bind", "@bpfj-*", false) +
      rule("unix-bind", "@bpfj-allowed", true));

  Child actor([] {
    const int allowed = bindAbstract("bpfj-allowed");
    return allowed == 0 ? bindAbstract("bpfj-denied") : 100 + allowed;
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(UnixEnforcer, AbstractGlobBindsPodVariable) {
  attach(
      rule("unix-bind", "@mine-*", false) +
          rule("unix-bind", "@mine-${UUID}", true),
      "vars = [\"UUID\"]\n");

  Child matching([] { return bindAbstract("mine-one"); });
  const std::array<PodVar, 1> one{{{"UUID", "one"}}};
  enroll("svc", matching.pid(), one);
  ASSERT_EQ(matching.run(), 0);

  Child different([] { return bindAbstract("mine-two"); });
  enroll("svc", different.pid(), one);
  ASSERT_EQ(different.run(), EACCES);

  Child missing([] { return bindAbstract("mine-one"); });
  enroll("svc", missing.pid());
  ASSERT_EQ(missing.run(), EACCES);
}

TEST(UnixEnforcer, AbstractConnectPolicyUsesRequestedName) {
  Fixture fixture;
  const std::string name = fixture.abstractName("stream");
  const int listener = listenAbstract(name, SOCK_STREAM);
  attach(rule("unix-connect", "@" + name, false));

  Child actor([&] { return connectAbstract(name); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
  ::close(listener);
}

TEST(UnixEnforcer, AbstractDatagramPolicyUsesDestinationName) {
  Fixture fixture;
  const std::string name = fixture.abstractName("dgram");
  const int receiver = listenAbstract(name, SOCK_DGRAM);
  attach(rule("unix-dgram", "@" + name, false));

  Child actor([&] { return sendAbstract(name); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
  ::close(receiver);
}

TEST(UnixEnforcer, OperationsAreIndependent) {
  Fixture fixture;
  attach(
      rule("unix-bind", fixture.socket(), true) +
      rule("unix-connect", fixture.socket(), false));

  Child actor([&] { return bindPath(fixture.socket()); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(UnixEnforcer, OverrideStackedBoundsTheActorPolicyWalk) {
  Fixture fixture;
  const Policy policy = policyOf(
      "[roles.denied]\nunix-bind.\"" + fixture.socket() +
      "\" = false\n"
      "[roles.override]\noverride-stacked = true\nunix-bind.\"" +
      fixture.socket() +
      "\" = true\n"
      "[roles.top]\nunix-bind.\"" +
      fixture.socket() + "\" = false\n");
  loadJailer(policy);
  ASSERT_OK(UnixEnforcer::load(testPins(), policy));

  Child allowed([&] { return bindPath(fixture.socket()); });
  enroll("denied", allowed.pid());
  enroll("override", allowed.pid());
  ASSERT_EQ(allowed.run(), 0);
  ASSERT_EQ(::unlink(fixture.socket().c_str()), 0);

  Child denied([&] { return bindPath(fixture.socket()); });
  enroll("denied", denied.pid());
  enroll("override", denied.pid());
  enroll("top", denied.pid());
  ASSERT_EQ(denied.run(), EACCES);
}
