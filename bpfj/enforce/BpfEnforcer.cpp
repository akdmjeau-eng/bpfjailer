// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/BpfEnforcer.h"

#include <cstdint>
#include <string_view>

#include "bpfj/enforce/RoleId.h"

#include "bpfj/enforce/bpf/bpf_enforce.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kSyscallRoles = "bpfj_bpf_syscall_roles";
constexpr std::string_view kAccess = "bpfj_bpf_access";
constexpr std::string_view kMapOwners = "bpfj_bpf_map_owners";
constexpr std::string_view kProgOwners = "bpfj_bpf_prog_owners";
constexpr std::string_view kOwnerVersion = "bpfj_bpf_owner_version";

// Sized well above what a host runs -- one devserver had 6176 maps and 269
// programs live -- because a failed insert leaves an object reading as
// unowned and therefore openable. A base role configured for bpf would put
// the whole host back in here, which is what `untracked-bpf` is for.
constexpr std::uint32_t kMaxOwnedMaps = 16384;
constexpr std::uint32_t kMaxOwnedProgs = 4096;

// Role-keyed, so bounded by the host's roles rather than their objects. The
// access map holds one entry per permitted (opener, owner) pair.
constexpr std::uint32_t kMaxRoles = 1024;
constexpr std::uint32_t kMaxAccessPairs = 4096;

// Mirrors BPFJ_BPF_DENY / BPFJ_BPF_ALLOW / BPFJ_BPF_ALLOW_UNTRACKED in
// bpf_enforce.bpf.c: `no-bpf` writes kDeny and `untracked-bpf`
// kAllowUntracked, and every other configured role gets kAllow.
constexpr std::uint8_t kDeny = 0;
constexpr std::uint8_t kAllow = 1;
constexpr std::uint8_t kAllowUntracked = 2;

struct AccessKey {
  struct bpfj_role_id opener;
  struct bpfj_role_id owner;
};

/// @brief Write the two policy maps. A role appears in the syscall map only if
/// it configured itself, by writing `bpf` or setting `no-bpf`, since the BPF
/// side reads absence as "not configured" rather than as either.
[[nodiscard]] Expected<> writePolicy(
    bpfj::libbpf::BpfSkelBase& skel,
    const Policy& policy) noexcept {
  auto roles = skel.getMap(kSyscallRoles.data());
  auto access = skel.getMap(kAccess.data());
  if (!roles || !access) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory, "BPF access maps are missing"));
  }

  for (const auto& [name, rolePolicy] : policy.roles) {
    if (!rolePolicy.hasBpf && !rolePolicy.noBpf) {
      continue;
    }

    auto opener = makeRoleId(name);
    if (!opener) {
      return makeUnexpected(opener.error());
    }

    const std::uint8_t mode = rolePolicy.noBpf ? kDeny
        : rolePolicy.untrackedBpf              ? kAllowUntracked
                                               : kAllow;
    if (auto res = roles->updateElem(*opener, mode); !res) {
      return res;
    }

    // Denied the syscall outright, so there is no pair worth writing; the
    // policy parser rejects a role setting both.
    if (rolePolicy.noBpf) {
      continue;
    }

    // Writing `bpf` at all buys the role its own objects, the counterpart of
    // the own-pod exemption the kill and ptrace gates give. Written for an
    // untracked role too, where it never matches, so the pair does not have
    // to appear the moment `untracked-bpf` comes off.
    AccessKey own{};
    own.opener = *opener;
    own.owner = *opener;
    if (auto res = access->updateElem(own, kAllow); !res) {
      return res;
    }

    for (const auto& target : rolePolicy.bpf) {
      auto owner = makeRoleId(target);
      if (!owner) {
        return makeUnexpected(owner.error());
      }

      AccessKey key{};
      key.opener = *opener;
      key.owner = *owner;

      if (auto res = access->updateElem(key, kAllow); !res) {
        return res;
      }
    }
  }

  return unit;
}

/// @brief Publish the layout of this build's owner records, which the next
/// build's replace reads through the pin to decide whether it can carry
/// them across.
[[nodiscard]] Expected<> writeOwnerVersion(
    bpfj::libbpf::BpfSkelBase& skel) noexcept {
  auto version = skel.getMap(kOwnerVersion.data());
  if (!version) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory,
        "the BPF owner version map is missing"));
  }

  const std::uint32_t slot = 0;
  const std::uint32_t value = BPFJ_BPF_OWNER_VERSION;
  return version->updateElem(slot, value);
}

} // namespace

Expected<> BpfEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<bpf_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }

  const std::pair<std::string_view, std::uint32_t> owned[] = {
      {kSyscallRoles, kMaxRoles},
      {kAccess, kMaxAccessPairs},
      {kMapOwners, kMaxOwnedMaps},
      {kProgOwners, kMaxOwnedProgs},
      // Pinned like the rest so a replace can read the running tree's copy
      // before it decides whether to carry that tree's records across.
      {kOwnerVersion, 1},
  };
  for (const auto& [name, maxEntries] : owned) {
    if (auto res = pins::pinMap(skel, name, mapDir, maxEntries); !res) {
      return res;
    }
  }

  if (auto res = skel.load(); !res) {
    return res;
  }

  if (auto res = heap::init(created.value()); !res) {
    return res;
  }

  // Before attach, so no hook runs against a half-written policy and reads a
  // configured role as unconfigured.
  if (auto res = writePolicy(skel, policy); !res) {
    return res;
  }

  if (auto res = writeOwnerVersion(skel); !res) {
    return res;
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }

  // Objects a configured role opened before load would be unowned and so
  // unprotected. The same one-shot walk the base role uses, over open files.
  {
    bpfj::libbpf::BpfLink seed(skel.links().bpfj_bpf_seed_owners);
    if (auto res = seed.iter(); !res) {
      return makeUnexpected(res.error());
    }
  }

  const auto linkDir = cfg.linkDir();
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_bpf_map_created, "bpfj_bpf_map_created"},
      {skel.links().bpfj_bpf_prog_loaded, "bpfj_bpf_prog_loaded"},
      {skel.links().bpfj_bpf_map_check, "bpfj_bpf_map_check"},
      {skel.links().bpfj_bpf_prog_check, "bpfj_bpf_prog_check"},
      {skel.links().bpfj_bpf_map_free, "bpfj_bpf_map_free"},
      {skel.links().bpfj_bpf_prog_free, "bpfj_bpf_prog_free"},
      // Last: this is the program that can deny bpf(2), and pinning is itself
      // a bpf(2) call.
      {skel.links().bpfj_bpf_syscall, "bpfj_bpf_syscall"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }

  return unit;
}

} // namespace bpfjailer
