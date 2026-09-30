// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/types.h>

#include <optional>

#include "bpfj/err/Error.h"

namespace bpfjailer {

/// @brief What to give up before handing control to another program.
struct PrivilegeDrop {
  /// Who to run as. An unset id is left alone.
  std::optional<uid_t> uid;
  std::optional<gid_t> gid;

  /// @brief Give up every capability, and no_new_privs so it sticks. Off by
  /// default; see dropPrivileges() for what that leaves behind.
  bool capabilities = false;
};

/**
 * @brief Give up privileges before handing control to another program.
 *
 * `capabilities` takes every capability rather than a chosen few, since
 * CAP_BPF, CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SYS_BOOT,
 * CAP_SYS_PTRACE, CAP_DAC_OVERRIDE and CAP_SETPCAP each leave a process
 * unjailed in any meaningful sense, and that list grows every kernel release.
 * It is not sufficient alone -- a process left as uid 0 can unpin the programs
 * holding no capabilities at all -- so pair it with a non-root `uid`, which
 * clears the capability sets as a kernel side effect but leaves the bounding
 * set intact.
 *
 * One function rather than a few calls at the call site, because the drop also
 * needs:
 *
 * - no_new_privs, or the first setuid binary hands the privileges back.
 * - The bounding set, or exec can restore a capability through a file's
 *   inheritable set.
 * - The saved set-user-id, hence setresuid(): plain setuid() from root leaves
 *   a saved uid of 0 to return to.
 * - Supplementary groups, which a uid change does not touch.
 *
 * Ordering is load bearing: the bounding set needs CAP_SETPCAP and the group
 * calls CAP_SETGID, so both must run before the uid change takes them away.
 * Fails rather than continuing, a partial drop looking like it worked.
 */
[[nodiscard]] Expected<> dropPrivileges(const PrivilegeDrop& drop) noexcept;

} // namespace bpfjailer
