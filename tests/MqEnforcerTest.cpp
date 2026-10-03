// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <mqueue.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <string>

#include "bpfj/enforce/MqEnforcer.h"
#include "bpfj/enforce/Replace.h"

using bpfjailer::MqEnforcer;
using bpfjailer::PodVar;
using bpfjailer::Policy;
using bpfjailer::replaceJailer;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(MqEnforcer::load(testPins(), policy));
}

[[nodiscard]] key_t uniqueKey() {
  static std::uint32_t serial = 0;
  return static_cast<key_t>(
      0x51000000U | ((static_cast<std::uint32_t>(::getpid()) & 0xffffU) << 8) |
      (++serial & 0xffU));
}

[[nodiscard]] std::string uniquePosixName() {
  static std::uint32_t serial = 0;
  return "/bpfj-mq-test-" + std::to_string(::getpid()) + "-" +
      std::to_string(++serial);
}

[[nodiscard]] int createSysv(key_t key) {
  errno = 0;
  return ::msgget(key, IPC_CREAT | IPC_EXCL | 0600) >= 0 ? 0 : errno;
}

[[nodiscard]] int acquireSysv(key_t key) {
  errno = 0;
  return ::msgget(key, 0) >= 0 ? 0 : errno;
}

[[nodiscard]] int createPosix(const std::string& name) {
  errno = 0;
  const mqd_t queue =
      ::mq_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600, nullptr);
  if (queue == static_cast<mqd_t>(-1)) {
    return errno;
  }
  ::mq_close(queue);
  return 0;
}

[[nodiscard]] int acquirePosix(const std::string& name) {
  errno = 0;
  const mqd_t queue = ::mq_open(name.c_str(), O_RDWR);
  if (queue == static_cast<mqd_t>(-1)) {
    return errno;
  }
  ::mq_close(queue);
  return 0;
}

[[nodiscard]] int receiveFdErrno(int socket) {
  char byte = 0;
  struct iovec iov{.iov_base = &byte, .iov_len = sizeof(byte)};
  alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
  struct msghdr message{
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };
  errno = 0;
  if (::recvmsg(socket, &message, 0) < 0) {
    return errno;
  }

  const struct cmsghdr* header = CMSG_FIRSTHDR(&message);
  if (!header) {
    return ENOMSG;
  }
  int received = -1;
  __builtin_memcpy(&received, CMSG_DATA(header), sizeof(received));
  ::close(received);
  return 0;
}

void sendFd(int socket, int fd) {
  char byte = 0;
  struct iovec iov{.iov_base = &byte, .iov_len = sizeof(byte)};
  alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
  struct msghdr message{
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };
  struct cmsghdr* header = CMSG_FIRSTHDR(&message);
  ASSERT(header != nullptr);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(fd));
  __builtin_memcpy(CMSG_DATA(header), &fd, sizeof(fd));
  ASSERT_EQ(::sendmsg(socket, &message, 0), 1);
}

void expectReceivedFd(const std::string& policy, int expected) {
  const std::string name = uniquePosixName();
  attach(policy);

  int sockets[2] = {-1, -1};
  int result[2] = {-1, -1};
  ASSERT_EQ(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets), 0);
  ASSERT_EQ(::pipe(result), 0);
  const pid_t receiver = ::fork();
  ASSERT(receiver >= 0);
  if (receiver == 0) {
    ::close(sockets[0]);
    ::close(result[0]);
    const int received = receiveFdErrno(sockets[1]);
    (void)::write(result[1], &received, sizeof(received));
    ::_exit(0);
  }

  ::close(sockets[1]);
  ::close(result[1]);
  enroll("client", receiver);
  enroll("owner", ::getpid());

  const mqd_t queue =
      ::mq_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600, nullptr);
  ASSERT(queue != static_cast<mqd_t>(-1));
  sendFd(sockets[0], queue);

  int received = -1;
  ASSERT_EQ(
      ::read(result[0], &received, sizeof(received)),
      static_cast<ssize_t>(sizeof(received)));
  ASSERT_EQ(received, expected);

  ::close(sockets[0]);
  ::close(result[0]);
  (void)::waitpid(receiver, nullptr, 0);
  ASSERT_EQ(::mq_close(queue), 0);
  ASSERT_EQ(::mq_unlink(name.c_str()), 0);
}

} // namespace

TEST(MqEnforcer, LoadPinsLinksPolicyAndVersionedOwnershipMaps) {
  attach("roles:\n  svc:\n");

  ASSERT(linkPinned("bpfj_mq_sysv_send"));
  ASSERT(linkPinned("bpfj_mq_sysv_receive"));
  ASSERT(linkPinned("bpfj_mq_posix_alloc"));
  ASSERT(linkPinned("bpfj_mq_posix_open"));
  ASSERT(linkPinned("bpfj_mq_posix_receive_fd"));
  ASSERT(mapPinned("bpfj_mq_sysv_owners"));
  ASSERT(mapPinned("bpfj_mq_posix_owners"));
  ASSERT(!mapPinned("bpfj_mq_sysv_owner_version"));
  ASSERT(!mapPinned("bpfj_mq_posix_owner_version"));
}

TEST(MqEnforcer, NoMqSysvDeniesCreation) {
  attach("roles:\n  jailed:\n    no-mq-sysv: true\n");
  Child actor([key = uniqueKey()] { return createSysv(key); });
  enroll("jailed", actor.pid());
  ASSERT_EQ(actor.run(), EPERM);
}

TEST(MqEnforcer, EmptySysvPolicyAllowsSendAndReceiveInsideItsPod) {
  attach("roles:\n  jailed:\n    mq-sysv:\n");
  enroll("jailed", ::getpid());
  const int id = ::msgget(IPC_PRIVATE, 0600);
  ASSERT(id >= 0);

  struct Message {
    long type;
    char byte;
  } sent{.type = 1, .byte = 'x'}, received{};
  ASSERT_EQ(::msgsnd(id, &sent, sizeof(sent.byte), 0), 0);
  ASSERT_EQ(::msgrcv(id, &received, sizeof(received.byte), 1, 0), 1);
  ASSERT_EQ(received.byte, 'x');
  ASSERT_EQ(::msgctl(id, IPC_RMID, nullptr), 0);
}

TEST(MqEnforcer, EmptySysvPolicyCannotAcquireAnotherPodsQueue) {
  const key_t key = uniqueKey();
  attach("roles:\n  owner:\n  jailed:\n    mq-sysv:\n");

  Child creator([key] { return createSysv(key); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);
  const int id = ::msgget(key, 0);
  ASSERT(id >= 0);
  Child cleanup([id] {
    errno = 0;
    return ::msgctl(id, IPC_RMID, nullptr) == 0 ? 0 : errno;
  });

  enroll("jailed", ::getpid());
  ASSERT_EQ(acquireSysv(key), EPERM);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(MqEnforcer, SysvPolicyCanNameAnOwnerRole) {
  const key_t key = uniqueKey();
  attach("roles:\n  owner:\n  client:\n    mq-sysv:\n      - owner\n");

  Child creator([key] { return createSysv(key); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);
  const int id = ::msgget(key, 0);
  ASSERT(id >= 0);
  Child cleanup([id] {
    errno = 0;
    return ::msgctl(id, IPC_RMID, nullptr) == 0 ? 0 : errno;
  });

  enroll("client", ::getpid());
  ASSERT_EQ(acquireSysv(key), 0);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(MqEnforcer, RestrictedSysvPolicyRejectsAQueueWithNoKnownOwner) {
  const key_t key = uniqueKey();
  const int id = ::msgget(key, IPC_CREAT | IPC_EXCL | 0600);
  ASSERT(id >= 0);

  attach("roles:\n  jailed:\n    mq-sysv:\n");
  Child cleanup([id] {
    errno = 0;
    return ::msgctl(id, IPC_RMID, nullptr) == 0 ? 0 : errno;
  });
  enroll("jailed", ::getpid());

  ASSERT_EQ(acquireSysv(key), EPERM);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(MqEnforcer, SysvOwnershipSurvivesAReplace) {
  const key_t key = uniqueKey();
  const std::string yaml =
      "roles:\n  owner:\n  client:\n    mq-sysv:\n      - owner\n";
  attach(yaml);
  Child creator([key] { return createSysv(key); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);
  const int id = ::msgget(key, 0);
  ASSERT(id >= 0);
  Child cleanup([id] {
    errno = 0;
    return ::msgctl(id, IPC_RMID, nullptr) == 0 ? 0 : errno;
  });
  enroll("client", ::getpid());

  ASSERT_OK(replaceJailer(testPins(), policyOf(yaml)));
  ASSERT_EQ(acquireSysv(key), 0);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(MqEnforcer, NoMqPosixDeniesCreation) {
  const std::string name = uniquePosixName();
  attach("roles:\n  jailed:\n    no-mq-posix: true\n");
  Child actor([name] { return createPosix(name); });
  enroll("jailed", actor.pid());
  // mqueuefs translates an inode-allocation security refusal to ENOMEM.
  ASSERT_EQ(actor.run(), ENOMEM);
  (void)::mq_unlink(name.c_str());
}

TEST(MqEnforcer, EmptyPosixPolicyAllowsItsOwnPod) {
  const std::string name = uniquePosixName();
  attach("roles:\n  jailed:\n    mq-posix:\n");
  enroll("jailed", ::getpid());
  ASSERT_EQ(createPosix(name), 0);
  ASSERT_EQ(acquirePosix(name), 0);
  ASSERT_EQ(::mq_unlink(name.c_str()), 0);
}

TEST(MqEnforcer, EmptyPosixPolicyCannotOpenAnotherPodsQueue) {
  const std::string name = uniquePosixName();
  attach("roles:\n  owner:\n  jailed:\n    mq-posix:\n");
  Child creator([name] { return createPosix(name); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);

  enroll("jailed", ::getpid());
  ASSERT_EQ(acquirePosix(name), EPERM);
  ASSERT_EQ(::mq_unlink(name.c_str()), 0);
}

TEST(MqEnforcer, PosixPolicyCanNameAnOwnerRole) {
  const std::string name = uniquePosixName();
  attach("roles:\n  owner:\n  client:\n    mq-posix:\n      - owner\n");
  Child creator([name] { return createPosix(name); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);

  enroll("client", ::getpid());
  ASSERT_EQ(acquirePosix(name), 0);
  ASSERT_EQ(::mq_unlink(name.c_str()), 0);
}

TEST(MqEnforcer, PosixPatternOverridesUnknownOwnership) {
  const std::string name = uniquePosixName();
  const std::string serial = name.substr(name.rfind('-') + 1);
  ASSERT_EQ(createPosix(name), 0);
  attach(
      "vars:\n"
      "  - SERIAL\n"
      "roles:\n"
      "  client:\n"
      "    mq-posix-pattern: bpfj-mq-?est-*-${SERIAL}\n");
  const std::array vars{PodVar{.name = "SERIAL", .value = serial}};
  enroll("client", ::getpid(), vars);

  ASSERT_EQ(acquirePosix(name), 0);
  ASSERT_EQ(::mq_unlink(name.c_str()), 0);
}

TEST(MqEnforcer, PosixPatternWithAMissingVariableDoesNotMatch) {
  const std::string name = uniquePosixName();
  ASSERT_EQ(createPosix(name), 0);
  Child cleanup([name] {
    errno = 0;
    return ::mq_unlink(name.c_str()) == 0 ? 0 : errno;
  });
  attach(
      "vars:\n"
      "  - SERIAL\n"
      "roles:\n"
      "  client:\n"
      "    mq-posix-pattern: bpfj-mq-test-*-${SERIAL}\n");
  enroll("client", ::getpid());

  ASSERT_EQ(acquirePosix(name), EPERM);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(MqEnforcer, RestrictedPosixPolicyRejectsAQueueWithNoKnownOwner) {
  const std::string name = uniquePosixName();
  ASSERT_EQ(createPosix(name), 0);

  attach("roles:\n  jailed:\n    mq-posix:\n");
  enroll("jailed", ::getpid());

  ASSERT_EQ(acquirePosix(name), EPERM);
  ASSERT_EQ(::mq_unlink(name.c_str()), 0);
}

TEST(MqEnforcer, PosixOwnershipSurvivesAReplace) {
  const std::string name = uniquePosixName();
  const std::string yaml =
      "roles:\n  owner:\n  client:\n    mq-posix:\n      - owner\n";
  attach(yaml);
  Child creator([name] { return createPosix(name); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);
  enroll("client", ::getpid());

  ASSERT_OK(replaceJailer(testPins(), policyOf(yaml)));
  ASSERT_EQ(acquirePosix(name), 0);
  ASSERT_EQ(::mq_unlink(name.c_str()), 0);
}

TEST(MqEnforcer, PosixDescriptorReceiptChecksTheReceivingPod) {
  // SCM_RIGHTS delivers the payload but omits an fd refused by
  // security_file_receive(), which the helper reports as ENOMSG.
  expectReceivedFd("roles:\n  owner:\n  client:\n    mq-posix:\n", ENOMSG);
}

TEST(MqEnforcer, PosixDescriptorReceiptAllowsANamedOwnerRole) {
  expectReceivedFd(
      "roles:\n  owner:\n  client:\n    mq-posix:\n      - owner\n", 0);
}

TEST(MqEnforcer, PosixDescriptorReceiptAllowsAMatchingPattern) {
  expectReceivedFd(
      "roles:\n"
      "  owner:\n"
      "  client:\n"
      "    mq-posix-pattern: bpfj-mq-test-*\n",
      0);
}
