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
  ReadExec,
};

enum class AccessMode : std::uint8_t {
  Deny,
  Pod,
  Roles,
  Any,
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

  /// @brief POSIX queue names this role may acquire regardless of ownership.
  std::vector<std::string> mqPosixPatterns;

  /// @brief Roles whose System V shared-memory segments this role may
  /// acquire. The three states match `mqSysv`.
  std::vector<std::string> shmSysv;
  AccessMode shmSysvMode = AccessMode::Deny;

  /// @brief The POSIX-shared-memory counterpart of `shmSysv`.
  std::vector<std::string> shmPosix;
  AccessMode shmPosixMode = AccessMode::Deny;

  /// @brief POSIX shared-memory names this role may acquire regardless of
  /// ownership.
  std::vector<std::string> shmPosixPatterns;

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

  /// @brief Role ids whose fs-verity keyrings this role may write.
  std::vector<std::string> keyring;
  AccessMode keyringMode = AccessMode::Deny;

  /// @brief Whether this role answers for a task on its own: every enforcer
  /// walks a task's roles newest first and stops at the first one carrying
  /// this, so it can grant what the roles under it deny. Bounds the actor only,
  /// never the target side of the `kill` and `ptrace` gates.
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
/// `vars` lists the variable names an enrollment may set. Lists must use block
/// style, since the vendored parser treats flow syntax as scalars.
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
