// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <string>
#include <thread>

#include "bpfj/enforce/Replace.h"
#include "bpfj/enforce/ShmEnforcer.h"

using bpfjailer::PodVar;
using bpfjailer::Policy;
using bpfjailer::replaceJailer;
using bpfjailer::ShmEnforcer;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;
using bpfjailer::test::waitForMutationJournal;

namespace {

constexpr std::size_t kSegmentSize = 4096;

void attach(const std::string& yaml) {
  const Policy policy = policyOf(yaml);
  loadJailer(policy);
  ASSERT_OK(ShmEnforcer::load(testPins(), policy));
}

[[nodiscard]] key_t uniqueKey() {
  static std::uint32_t serial = 0;
  return static_cast<key_t>(
      0x52000000U | ((static_cast<std::uint32_t>(::getpid()) & 0xffffU) << 8) |
      (++serial & 0xffU));
}

[[nodiscard]] std::string uniquePosixName() {
  static std::uint32_t serial = 0;
  return "/bpfj-shm-test-" + std::to_string(::getpid()) + "-" +
      std::to_string(++serial);
}

[[nodiscard]] int createSysv(key_t key) {
  errno = 0;
  return ::shmget(key, kSegmentSize, IPC_CREAT | IPC_EXCL | 0600) >= 0 ? 0
                                                                       : errno;
}

[[nodiscard]] int acquireSysv(key_t key) {
  errno = 0;
  return ::shmget(key, 0, 0) >= 0 ? 0 : errno;
}

[[nodiscard]] int attachSysv(int id) {
  errno = 0;
  void* address = ::shmat(id, nullptr, 0);
  if (address == reinterpret_cast<void*>(-1)) {
    return errno;
  }
  ::shmdt(address);
  return 0;
}

[[nodiscard]] int createPosix(const std::string& name) {
  errno = 0;
  const int fd = ::shm_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  if (fd < 0) {
    return errno;
  }
  const int result = ::ftruncate(fd, kSegmentSize) == 0 ? 0 : errno;
  ::close(fd);
  return result;
}

[[nodiscard]] int acquirePosix(const std::string& name) {
  errno = 0;
  const int fd = ::shm_open(name.c_str(), O_RDWR, 0600);
  if (fd < 0) {
    return errno;
  }
  ::close(fd);
  return 0;
}

[[nodiscard]] int mmapErrno(int fd) {
  errno = 0;
  void* address =
      ::mmap(nullptr, kSegmentSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (address == MAP_FAILED) {
    return errno;
  }
  ::munmap(address, kSegmentSize);
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

  const int fd = ::shm_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::ftruncate(fd, kSegmentSize), 0);
  sendFd(sockets[0], fd);

  int received = -1;
  ASSERT_EQ(
      ::read(result[0], &received, sizeof(received)),
      static_cast<ssize_t>(sizeof(received)));
  ASSERT_EQ(received, expected);

  ::close(fd);
  ::close(sockets[0]);
  ::close(result[0]);
  (void)::waitpid(receiver, nullptr, 0);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);
}

} // namespace

TEST(ShmEnforcer, LoadPinsHooksPoliciesClassifiersAndVersionedOwners) {
  attach("roles:\n  svc:\n");

  ASSERT(linkPinned("bpfj_shm_sysv_attach"));
  ASSERT(linkPinned("bpfj_shm_posix_open"));
  ASSERT(linkPinned("bpfj_shm_posix_mmap"));
  ASSERT(linkPinned("bpfj_shm_posix_receive_fd"));
  ASSERT(linkPinned("bpfj_shm_posix_file_truncate"));
  ASSERT(mapPinned("bpfj_shm_sysv_owners"));
  ASSERT(mapPinned("bpfj_shm_posix_owners"));
  ASSERT(!mapPinned("bpfj_shm_sysv_owner_version"));
  ASSERT(!mapPinned("bpfj_shm_posix_owner_version"));
  ASSERT(mapPinned("bpfj_shm_posix_mounts"));
  ASSERT(mapPinned("bpfj_shm_posix_devices"));
}

TEST(ShmEnforcer, NoShmSysvDeniesCreation) {
  attach("roles:\n  jailed:\n");
  Child actor([key = uniqueKey()] { return createSysv(key); });
  enroll("jailed", actor.pid());
  ASSERT_EQ(actor.run(), EPERM);
}

TEST(ShmEnforcer, EmptySysvPolicyAllowsAttachInsideItsPod) {
  attach("roles:\n  jailed:\n    shm-sysv-roles:\n");
  enroll("jailed", ::getpid());
  const int id = ::shmget(IPC_PRIVATE, kSegmentSize, 0600);
  ASSERT(id >= 0);
  ASSERT_EQ(attachSysv(id), 0);
  ASSERT_EQ(::shmctl(id, IPC_RMID, nullptr), 0);
}

TEST(ShmEnforcer, EmptySysvPolicyCannotAcquireAnotherPodsSegment) {
  const key_t key = uniqueKey();
  attach("roles:\n  owner:\n    any: true\n  client:\n    shm-sysv-roles:\n");
  Child creator([key] { return createSysv(key); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);
  const int id = ::shmget(key, 0, 0);
  ASSERT(id >= 0);
  Child cleanup([id] {
    errno = 0;
    return ::shmctl(id, IPC_RMID, nullptr) == 0 ? 0 : errno;
  });

  enroll("client", ::getpid());
  ASSERT_EQ(acquireSysv(key), EPERM);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(ShmEnforcer, SysvPolicyCanNameAnOwnerRole) {
  const key_t key = uniqueKey();
  attach(
      "roles:\n  owner:\n    any: true\n  client:\n    shm-sysv-roles:\n      - owner\n");
  Child creator([key] { return createSysv(key); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);
  const int id = ::shmget(key, 0, 0);
  ASSERT(id >= 0);

  enroll("client", ::getpid());
  ASSERT_EQ(acquireSysv(key), 0);
  ASSERT_EQ(attachSysv(id), 0);
  ASSERT_EQ(::shmctl(id, IPC_RMID, nullptr), 0);
}

TEST(ShmEnforcer, RestrictedSysvPolicyRejectsAnUnknownOwner) {
  const key_t key = uniqueKey();
  const int id = ::shmget(key, kSegmentSize, IPC_CREAT | IPC_EXCL | 0600);
  ASSERT(id >= 0);
  attach("roles:\n  jailed:\n    shm-sysv-roles:\n");
  Child cleanup([id] {
    errno = 0;
    return ::shmctl(id, IPC_RMID, nullptr) == 0 ? 0 : errno;
  });

  enroll("jailed", ::getpid());
  ASSERT_EQ(acquireSysv(key), EPERM);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(ShmEnforcer, NoShmPosixDeniesCreation) {
  const std::string name = uniquePosixName();
  attach("roles:\n  jailed:\n");
  Child actor([name] { return createPosix(name); });
  enroll("jailed", actor.pid());
  // tmpfs translates an inode-allocation security refusal to ENOSPC.
  ASSERT_EQ(actor.run(), ENOSPC);
  (void)::shm_unlink(name.c_str());
}

TEST(ShmEnforcer, EmptyPosixPolicyAllowsItsOwnPod) {
  const std::string name = uniquePosixName();
  attach("roles:\n  jailed:\n    shm-posix-roles:\n");
  enroll("jailed", ::getpid());
  ASSERT_EQ(createPosix(name), 0);
  ASSERT_EQ(acquirePosix(name), 0);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);
}

TEST(ShmEnforcer, EmptyPosixPolicyCannotOpenOrUnlinkAnotherPodsObject) {
  const std::string name = uniquePosixName();
  attach("roles:\n  owner:\n    any: true\n  client:\n    shm-posix-roles:\n");
  Child creator([name] { return createPosix(name); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);
  Child cleanup([name] {
    errno = 0;
    return ::shm_unlink(name.c_str()) == 0 ? 0 : errno;
  });

  enroll("client", ::getpid());
  ASSERT_EQ(acquirePosix(name), EPERM);
  errno = 0;
  ASSERT_EQ(::shm_unlink(name.c_str()), -1);
  // The VFS exposes a path_unlink security refusal as EACCES here.
  ASSERT_EQ(errno, EACCES);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(ShmEnforcer, PosixPolicyCanNameAnOwnerRole) {
  const std::string name = uniquePosixName();
  attach(
      "roles:\n  owner:\n    any: true\n  client:\n    shm-posix-roles:\n      - owner\n");
  Child creator([name] { return createPosix(name); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);

  enroll("client", ::getpid());
  ASSERT_EQ(acquirePosix(name), 0);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);
}

TEST(ShmEnforcer, PosixPatternOverridesTheOwnerRoleList) {
  const std::string name = uniquePosixName();
  const std::string serial = name.substr(name.rfind('-') + 1);
  attach(
      "vars:\n"
      "  - SERIAL\n"
      "roles:\n"
      "  owner:\n    any: true\n"
      "  client:\n"
      "    shm-posix-roles:\n"
      "    shm-posix-pattern: bpfj-shm-?est-*-${SERIAL}\n");
  Child creator([name] { return createPosix(name); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);

  const std::array vars{PodVar{.name = "SERIAL", .value = serial}};
  enroll("client", ::getpid(), vars);
  const int fd = ::shm_open(name.c_str(), O_RDWR, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(mmapErrno(fd), 0);
  ::close(fd);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);
}

TEST(ShmEnforcer, RestrictedPosixPolicyRejectsAnUnknownOwner) {
  const std::string name = uniquePosixName();
  ASSERT_EQ(createPosix(name), 0);
  attach("roles:\n  jailed:\n    shm-posix-roles:\n");
  Child cleanup([name] {
    errno = 0;
    return ::shm_unlink(name.c_str()) == 0 ? 0 : errno;
  });

  enroll("jailed", ::getpid());
  ASSERT_EQ(acquirePosix(name), EPERM);
  ASSERT_EQ(cleanup.run(), 0);
}

TEST(ShmEnforcer, AnyFloorCanOpenAJailedPodsObject) {
  const std::string name = uniquePosixName();
  attach(
      "roles:\n  floor:\n    shm-posix-any: true\n"
      "  jailed:\n    shm-posix-roles:\n");
  Child creator([name] { return createPosix(name); });
  enroll("jailed", creator.pid());
  ASSERT_EQ(creator.run(), 0);

  ASSERT_EQ(acquirePosix(name), 0);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);
}

TEST(ShmEnforcer, InheritedPosixDescriptorIsCheckedAtMmap) {
  const std::string name = uniquePosixName();
  attach("roles:\n  jailed:\n    shm-posix-roles:\n");
  const int fd = ::shm_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::ftruncate(fd, kSegmentSize), 0);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);

  enroll("jailed", ::getpid());
  ASSERT_EQ(mmapErrno(fd), EPERM);
  ::close(fd);
}

TEST(ShmEnforcer, InheritedPosixDescriptorIsCheckedAtFtruncate) {
  const std::string name = uniquePosixName();
  attach("roles:\n  jailed:\n    shm-posix:\n");
  const int fd = ::shm_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);

  enroll("jailed", ::getpid());
  errno = 0;
  ASSERT_EQ(::ftruncate(fd, kSegmentSize), -1);
  ASSERT_EQ(errno, EPERM);
  ::close(fd);
}

TEST(ShmEnforcer, ExistingPosixMappingRemainsACapability) {
  const std::string name = uniquePosixName();
  attach("roles:\n  jailed:\n");
  const int fd = ::shm_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::ftruncate(fd, kSegmentSize), 0);
  void* address =
      ::mmap(nullptr, kSegmentSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  ASSERT(address != MAP_FAILED);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);

  enroll("jailed", ::getpid());
  static_cast<char*>(address)[0] = 'x';
  ASSERT_EQ(static_cast<char*>(address)[0], 'x');

  ASSERT_EQ(::munmap(address, kSegmentSize), 0);
  ::close(fd);
}

TEST(ShmEnforcer, MprotectChecksOnlyProtectionUpgrades) {
  const std::string name = uniquePosixName();
  const int fd = ::shm_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::ftruncate(fd, kSegmentSize), 0);
  void* address = ::mmap(nullptr, kSegmentSize, PROT_READ, MAP_SHARED, fd, 0);
  ASSERT(address != MAP_FAILED);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);

  attach("roles:\n  jailed:\n    shm-posix-roles:\n");
  enroll("jailed", ::getpid());
  ASSERT_EQ(::mprotect(address, kSegmentSize, PROT_NONE), 0);
  errno = 0;
  ASSERT_EQ(::mprotect(address, kSegmentSize, PROT_READ), -1);
  ASSERT_EQ(errno, EPERM);

  ASSERT_EQ(::munmap(address, kSegmentSize), 0);
  ::close(fd);
}

TEST(ShmEnforcer, PosixDescriptorReceiptChecksTheReceivingPod) {
  expectReceivedFd(
      "roles:\n  owner:\n    any: true\n  client:\n    shm-posix-roles:\n",
      ENOMSG);
}

TEST(ShmEnforcer, PosixDescriptorReceiptAllowsANamedOwnerRole) {
  expectReceivedFd(
      "roles:\n  owner:\n    any: true\n  client:\n    shm-posix-roles:\n      - owner\n",
      0);
}

TEST(ShmEnforcer, PosixDescriptorReceiptAllowsAMatchingPattern) {
  expectReceivedFd(
      "roles:\n"
      "  owner:\n    any: true\n"
      "  client:\n"
      "    shm-posix-pattern: bpfj-shm-test-*\n",
      0);
}

TEST(ShmEnforcer, NoShmPosixDoesNotCoverMemfd) {
  attach("roles:\n  jailed:\n");
  enroll("jailed", ::getpid());
  const int fd = static_cast<int>(
      ::syscall(SYS_memfd_create, "bpfj-shm-memfd", MFD_CLOEXEC));
  ASSERT(fd >= 0);
  ASSERT_EQ(::ftruncate(fd, kSegmentSize), 0);
  ASSERT_EQ(mmapErrno(fd), 0);
  ::close(fd);
}

TEST(ShmEnforcer, OwnershipSurvivesAReplace) {
  const std::string name = uniquePosixName();
  const std::string yaml =
      "roles:\n  owner:\n    any: true\n  client:\n    any: true\n"
      "    shm-posix-roles:\n      - owner\n";
  attach(yaml);
  Child creator([name] { return createPosix(name); });
  enroll("owner", creator.pid());
  ASSERT_EQ(creator.run(), 0);
  enroll("client", ::getpid());

  ASSERT_OK(replaceJailer(testPins(), policyOf(yaml)));
  ASSERT_EQ(acquirePosix(name), 0);
  ASSERT_EQ(::shm_unlink(name.c_str()), 0);
}

TEST(ShmEnforcer, OwnershipMutationsDuringReplaceAreReplayed) {
  const key_t keptSysv = uniqueKey();
  const key_t removedSysv = uniqueKey();
  const std::string keptPosix = uniquePosixName();
  const std::string removedPosix = uniquePosixName();
  const std::string yaml =
      "roles:\n  owner:\n    any: true\n  client:\n"
      "    shm-sysv-roles:\n      - owner\n"
      "    shm-posix-roles:\n      - owner\n";
  attach(yaml);
  enroll("owner", ::getpid());

  Child replacer([yaml] {
    auto replaced = replaceJailer(testPins(), policyOf(yaml));
    if (!replaced) {
      bpfjailer::test::noteDiagnostic(
          "      " + replaced.error().message() + "\n");
      const int code = replaced.error().code().value();
      return code == 0 ? 1 : code;
    }
    return 0;
  });
  int replaceStatus = -1;
  std::thread replacing([&] { replaceStatus = replacer.run(); });

  const bool recording = waitForMutationJournal();
  const int createKeptSysv = createSysv(keptSysv);
  const int createRemovedSysv = createSysv(removedSysv);
  const int removedSysvId = ::shmget(removedSysv, 0, 0);
  const int removeSysv = removedSysvId >= 0
      ? (::shmctl(removedSysvId, IPC_RMID, nullptr) == 0 ? 0 : errno)
      : errno;
  const int createKeptPosix = createPosix(keptPosix);
  const int createRemovedPosix = createPosix(removedPosix);
  errno = 0;
  const int removePosix = ::shm_unlink(removedPosix.c_str()) == 0 ? 0 : errno;
  replacing.join();

  ASSERT(recording);
  ASSERT_EQ(createKeptSysv, 0);
  ASSERT_EQ(createRemovedSysv, 0);
  ASSERT_EQ(removeSysv, 0);
  ASSERT_EQ(createKeptPosix, 0);
  ASSERT_EQ(createRemovedPosix, 0);
  ASSERT_EQ(removePosix, 0);
  ASSERT_EQ(replaceStatus, 0);

  enroll("client", ::getpid());
  ASSERT_EQ(acquireSysv(keptSysv), 0);
  ASSERT_EQ(acquireSysv(removedSysv), ENOENT);
  ASSERT_EQ(acquirePosix(keptPosix), 0);
  ASSERT_EQ(acquirePosix(removedPosix), ENOENT);

  const int keptSysvId = ::shmget(keptSysv, 0, 0);
  ASSERT(keptSysvId >= 0);
  ASSERT_EQ(::shmctl(keptSysvId, IPC_RMID, nullptr), 0);
  ASSERT_EQ(::shm_unlink(keptPosix.c_str()), 0);
}
