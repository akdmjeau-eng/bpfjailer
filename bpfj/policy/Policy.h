// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/err/StdExpected.h"

namespace bpfjailer {

enum class FileMode : std::uint8_t {
  None,
  ReadOnly,
  ReadWrite,
};

enum class AccessMode : std::uint8_t {
  Deny,
  Pod,
  Roles,
  Any,
};

struct ExecPathPolicy {
  bool allowExec = false;
  bool allowSetuid = false;
  bool allowSharedObject = false;
};

/// @brief What one role is subject to.
struct RolePolicy {
  /// @brief Open every operation not configured more narrowly below.
  bool any = false;

  /// @brief Path pattern to the access mode granted at that path. Matching is
  /// performed in PID 1's mount namespace.
  std::map<std::string, FileMode> paths;
  bool hasPaths = false;
  bool fsAny = false;

  /// @brief Path pattern to the executable-code operations permitted there.
  /// Matching is performed in PID 1's mount namespace.
  std::map<std::string, ExecPathPolicy> execPaths;
  bool hasExecPaths = false;
  bool execAny = false;

  /// @brief Unix-socket pathname or abstract-name rules. Pathname matches are
  /// recursive with the longest path winning; abstract names (spelled with a
  /// leading '@') are globs. Missing or unmatched pathname rules deny, while
  /// unmatched abstract names are allowed.
  std::map<std::string, bool> unixBind;
  std::map<std::string, bool> unixConnect;
  std::map<std::string, bool> unixDgram;

  /// @brief Mount destination path to the filesystem types permitted there.
  /// Matching is recursive and the longest path wins. An empty type list
  /// denies mounting at that path. An absent table denies every destination.
  std::map<std::string, std::vector<std::string>> mount;
  bool hasMount = false;
  bool mountAny = false;

  /// @brief Mountpoint patterns mapped to whether this role may remove them.
  /// This covers direct unmount, attached move_mount sources and pivot_root's
  /// old root. Matching is recursive and the longest path wins.
  std::map<std::string, bool> umount;
  bool hasUmount = false;
  bool umountAny = false;

  /// @brief Certificate ids whose signatures this role's binaries may carry.
  std::vector<std::string> enforceBinaryCerts;
  bool verityAny = false;

  /// @brief Role ids whose BPF maps and programs this role may open.
  std::vector<std::string> bpf;
  AccessMode bpfMode = AccessMode::Deny;

  /// @brief Whether this role may load kernel modules or kexec images.
  bool lkmAny = false;

  /// @brief Roles whose System V message queues this role may acquire.
  std::vector<std::string> mqSysv;
  AccessMode mqSysvMode = AccessMode::Deny;

  /// @brief The POSIX-mqueue counterpart of `mqSysv`.
  std::vector<std::string> mqPosix;
  AccessMode mqPosixMode = AccessMode::Deny;

  /// @brief POSIX queue name patterns and whether they may be acquired.
  std::map<std::string, bool> mqPosixPatterns;

  /// @brief Roles whose System V shared-memory segments this role may
  /// acquire. The three states match `mqSysv`.
  std::vector<std::string> shmSysv;
  AccessMode shmSysvMode = AccessMode::Deny;

  /// @brief The POSIX-shared-memory counterpart of `shmSysv`.
  std::vector<std::string> shmPosix;
  AccessMode shmPosixMode = AccessMode::Deny;

  /// @brief POSIX shared-memory name patterns and whether they may be acquired.
  std::map<std::string, bool> shmPosixPatterns;

  /// @brief Whether what this role creates is left unowned, keeping BPF's
  /// restriction without its ownership. Only meaningful on a role allowed to
  /// use BPF, and needed on a base role, which would otherwise own every object
  /// on the host and so gate nothing.
  bool untrackedBpf = false;

  /// @brief Role ids whose processes this role may signal.
  std::vector<std::string> kill;
  AccessMode killMode = AccessMode::Deny;

  /// @brief Role ids whose processes this role may ptrace, with the same four
  /// modes as `kill`. Only an attach is gated, since gating the read-only
  /// modes would break `ps`.
  std::vector<std::string> ptrace;
  AccessMode ptraceMode = AccessMode::Deny;

  /// @brief Role ids whose processes' proc files this role may open, with the
  /// same four modes as `kill`.
  std::vector<std::string> proc;
  AccessMode procMode = AccessMode::Deny;

  /// @brief Role ids whose fs-verity keyrings this role may write.
  std::vector<std::string> keyring;
  AccessMode keyringMode = AccessMode::Deny;

  /// @brief Whether this role answers for a task on its own: every enforcer
  /// walks a task's roles newest first and stops at the first one carrying
  /// this, so it can grant what the roles under it deny. Bounds the actor only,
  /// never the target side of the `kill`, `ptrace`, and `proc` gates.
  bool overrideStacked = false;

  /// @brief Whether a caller that is not root may enroll itself in this role;
  /// absent means false, so a role is root-only until its policy says
  /// otherwise.
  bool unprivEnroll = false;

  /// @brief Role ids a process holding this role may enroll itself in.
  std::vector<std::string> enroll;
  AccessMode enrollMode = AccessMode::Deny;

  /// @brief The lowest sequence number a binary claiming this role may carry,
  /// read from its `user.bpfj.seq` xattr and signed over along with the
  /// fs-verity digest. Nothing raises it as newer binaries run, and it is
  /// rejected without `enforceBinaryCerts` to bind it to.
  std::uint64_t minSeq = 0;

  /// @brief Whether `minSeq` was written at all. See above.
  bool hasMinSeq = false;
};

/// @brief The jailer's policy file: `base-role` names the floor every process
/// starts on, and `certs` is the trust store. `roles` maps the role id that a
/// binary claims through `user.bpfj.policy.exec` to that role's policy, and
/// `vars` lists the variable names an enrollment may set.
struct Policy {
  /// @brief The role every process on the host is enrolled in, or empty.
  /// Applied once when the jailer loads, so one carrying `enforceBinaryCerts`
  /// demands a valid signature from *every* binary on the host.
  std::string baseRole;

  /// @brief Certificate id to the DER bytes of an X.509 certificate.
  std::map<std::string, std::string> certs;

  /// @brief Role id to that role's policy.
  std::map<std::string, RolePolicy> roles;

  /// @brief The variable names a pod may carry. The jailer refuses an
  /// enrollment that names any other, which keeps a caller from creating
  /// variables of its own. If the policy leaves this out, no pod carries any.
  std::vector<std::string> vars;

  /// @brief Parse and validate `path`, decoding certificates here so a
  /// mistyped one is reported against the policy file rather than later as a
  /// keyring error.
  [[nodiscard]] static err::Expected<Policy> parseFile(
      const std::string& path) noexcept;

  /// @brief Parse and validate a policy document already in memory.
  [[nodiscard]] static err::Expected<Policy> parse(
      const std::string& text) noexcept;
};

/// @brief Strip PEM armour and decode, or decode bare base64, to the DER the
/// kernel's X.509 parser takes.
[[nodiscard]] err::Expected<std::string> decodeCertificate(
    std::string_view text) noexcept;

} // namespace bpfjailer
