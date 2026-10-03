// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/err/StdExpected.h"

namespace bpfjailer {

/// @brief What one role is subject to.
struct RolePolicy {
  /// @brief Certificate ids whose signatures this role's binaries may carry;
  /// empty means unchecked rather than denied.
  std::vector<std::string> enforceBinaryCerts;

  /// @brief Role ids whose BPF maps and programs this role may open: absent
  /// reaches only unowned objects, empty reaches only its own, non-empty adds
  /// the listed roles, and `noBpf` is the outright denial `bpf` cannot spell.
  std::vector<std::string> bpf;

  /// @brief Whether `bpf` was written at all. See above.
  bool hasBpf = false;

  /// @brief Whether this role is denied bpf(2) entirely, the one state `bpf`
  /// cannot express; setting it alongside `bpf` is rejected.
  bool noBpf = false;

  /// @brief Whether this role is denied kernel module and kexec loading.
  bool noLkm = false;

  /// @brief Roles whose System V message queues this role may acquire: absent
  /// is unrestricted, empty stays inside its own pod, and non-empty also
  /// permits queues owned by the listed roles.
  std::vector<std::string> mqSysv;
  bool hasMqSysv = false;

  /// @brief Deny System V message queues outright. Cannot be combined with
  /// `mq-sysv`.
  bool noMqSysv = false;

  /// @brief The POSIX-mqueue counterpart of `mqSysv`.
  std::vector<std::string> mqPosix;
  bool hasMqPosix = false;

  /// @brief POSIX queue names this role may acquire regardless of ownership.
  std::vector<std::string> mqPosixPatterns;

  /// @brief Deny POSIX message queues outright. Cannot be combined with
  /// `mq-posix`.
  bool noMqPosix = false;

  /// @brief Roles whose System V shared-memory segments this role may
  /// acquire. The three states match `mqSysv`.
  std::vector<std::string> shmSysv;
  bool hasShmSysv = false;

  /// @brief Deny System V shared memory outright. Cannot be combined with
  /// `shm-sysv`.
  bool noShmSysv = false;

  /// @brief The POSIX-shared-memory counterpart of `shmSysv`.
  std::vector<std::string> shmPosix;
  bool hasShmPosix = false;

  /// @brief POSIX shared-memory names this role may acquire regardless of
  /// ownership.
  std::vector<std::string> shmPosixPatterns;

  /// @brief Deny POSIX shared memory outright. Cannot be combined with
  /// `shm-posix`.
  bool noShmPosix = false;

  /// @brief Whether what this role creates is left unowned, keeping `bpf`'s
  /// restriction without its ownership. Only meaningful on a role that wrote
  /// `bpf`, and needed on a base role, which would otherwise own every object
  /// on the host and so gate nothing.
  bool untrackedBpf = false;

  /// @brief Role ids whose processes this role may signal: absent is
  /// unrestricted, empty stays inside its own pod, and non-empty adds targets
  /// whose roles are all listed.
  std::vector<std::string> kill;

  /// @brief Whether `kill` was written at all. See above.
  bool hasKill = false;

  /// @brief Whether this role is denied signalling entirely, the one state
  /// `kill` cannot express; setting it alongside `kill` is rejected.
  bool noKill = false;

  /// @brief Role ids whose processes this role may ptrace, with the same three
  /// states as `kill`. Only an attach is gated, since gating the read-only
  /// modes would break `ps`.
  std::vector<std::string> ptrace;

  /// @brief Whether `ptrace` was written at all. See above.
  bool hasPtrace = false;

  /// @brief Whether this role is denied ptrace entirely, the one state
  /// `ptrace` cannot express; setting it alongside `ptrace` is rejected.
  bool noPtrace = false;

  /// @brief Role ids whose fs-verity keyrings this role may write: absent may
  /// write any, empty only its own, and non-empty adds the listed ones.
  std::vector<std::string> keyring;

  /// @brief Whether `keyring` was written at all. See above.
  bool hasKeyring = false;

  /// @brief Whether this role is denied keyring writes entirely, the one
  /// state `keyring` cannot express; setting it alongside `keyring` is
  /// rejected.
  bool noKeyring = false;

  /// @brief Whether this role answers for a task on its own: every enforcer
  /// walks a task's roles newest first and stops at the first one carrying
  /// this, so it can grant what the roles under it deny. Bounds the actor only,
  /// never the target side of the `kill` and `ptrace` gates.
  bool overrideStacked = false;

  /// @brief Whether a caller that is not root may enroll itself in this role;
  /// absent means false, so a role is root-only until its policy says
  /// otherwise.
  bool unprivEnroll = false;

  /// @brief Role ids a process holding this role may enroll itself in: absent
  /// leaves bpfjsrv unrestricted, empty forbids every addition, and non-empty
  /// allows only the listed roles.
  std::vector<std::string> enroll;

  /// @brief Whether `enroll` was written at all. See above.
  bool hasEnroll = false;

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
