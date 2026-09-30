// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/lib/Privileges.h"

#include <grp.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <string>

namespace bpfjailer {

namespace {

// A capability index cannot exceed the width of the two 32-bit masks capset
// takes, so this is the ceiling for any kernel; which exist is discovered
// below.
constexpr int kMaxCapIndex = 63;

[[nodiscard]] Expected<> clearBoundingSet() noexcept {
  for (int cap = 0; cap <= kMaxCapIndex; ++cap) {
    if (::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == 0) {
      continue;
    }

    // The kernel rejects an index it does not define, which is how the end of
    // the set is found; reading cap_last_cap would need /proc mounted.
    if (errno == EINVAL) {
      break;
    }

    return makeUnexpected(makeErrnoError(
        "failed to drop capability ",
        std::to_string(cap),
        " from the bounding set"));
  }

  return unit;
}

[[nodiscard]] Expected<> clearCapabilitySets() noexcept {
  // capset(2) has no glibc wrapper, and version 3 is the one covering all 64
  // capability bits -- older headers silently describe half the set.
  __user_cap_header_struct header{};
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;

  // Zeroed throughout: no effective, permitted or inheritable capabilities.
  __user_cap_data_struct data[2]{};

  if (::syscall(SYS_capset, &header, data) != 0) {
    return makeUnexpected(makeErrnoError("failed to clear capabilities"));
  }

  return unit;
}

} // namespace

Expected<> dropPrivileges(const PrivilegeDrop& drop) noexcept {
  // With the capabilities rather than the ids: it stops an exec handing back
  // what the capability drop just took away.
  if (drop.capabilities) {
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      return makeUnexpected(makeErrnoError("failed to set no_new_privs"));
    }
  }

  // Root's supplementary groups would otherwise outlive the identity change and
  // reach what the new ids were chosen to exclude.
  if (drop.uid || drop.gid) {
    if (::setgroups(0, nullptr) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to drop supplementary groups"));
    }
  }

  if (drop.gid) {
    if (::setresgid(*drop.gid, *drop.gid, *drop.gid) != 0) {
      return makeUnexpected(makeErrnoError(
          "failed to switch to gid ", std::to_string(*drop.gid)));
    }
  }

  // Before the uid change, which takes away the CAP_SETPCAP this needs.
  if (drop.capabilities) {
    if (auto res = clearBoundingSet(); !res) {
      return res;
    }
  }

  if (drop.uid) {
    if (::setresuid(*drop.uid, *drop.uid, *drop.uid) != 0) {
      return makeUnexpected(makeErrnoError(
          "failed to switch to uid ", std::to_string(*drop.uid)));
    }
  }

  if (drop.capabilities) {
    // Leaving root clears the capability sets by itself, but nothing else
    // does: without this, `--uid 0` and an absent `--uid` would both keep every
    // capability the process started with.
    if (auto res = clearCapabilitySets(); !res) {
      return res;
    }

    if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to clear ambient capabilities"));
    }
  }

  return unit;
}

} // namespace bpfjailer
