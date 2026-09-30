// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/VerityEnforcer.h"

#include <bpf/bpf.h>

#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/enforce/RoleGate.h"
#include "bpfj/enforce/RoleId.h"
#include "bpfj/enforce/bpf/verity_enforce.skel.h"
#include "bpfj/fsverity/Keyctl.h"
#include "bpfj/fsverity/Keyring.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

// role -> keyring serial. Pinned because `bpfjctl load` applies policy and then
// exits, and this is what the running programs read afterwards.
constexpr std::string_view kKeyMap = "bpfj_key_map";

// The same keyrings the other way round, serial -> role, the direction
// lsm/key_permission needs.
constexpr std::string_view kOwnerMap = "bpfj_keyring_owner";

// role -> the lowest sequence number a binary claiming it may carry, straight
// from `min-seq`; a role absent from here is not sequence-checked.
constexpr std::string_view kSeqMap = "bpfj_verity_seq_map";

// Declared with one entry, like the pod map, and sized here. Keyed by role, so
// it needs room for the host's roles rather than its jails.
constexpr std::uint32_t kMaxRoleKeys = 1024;

// Which roles may write another role's keyring.
constexpr RoleGate kGate{
    .rolesMap = "bpfj_keyring_roles",
    .accessMap = "bpfj_keyring_access",
    .configured = &RolePolicy::hasKeyring,
    .targets = &RolePolicy::keyring,
};

// Named "bpfj:<scope>:<role>", <scope> unique to the load that built it,
// since the user keyring is per-UID and a bare "bpfj:<role>" let a replace's
// new tree evict the still-enforcing old tree's keyrings.
constexpr std::string_view kKeyringPrefix = "bpfj";

/// @brief A token no other live load will be using. Random rather than
/// derived from the pin tree, which a replace renames out from under it, and
/// unique rather than unguessable, the user keyring being root-only.
[[nodiscard]] std::string makeKeyringScope() noexcept {
  static constexpr char kHex[] = "0123456789abcdef";

  std::random_device rd;
  std::uniform_int_distribution<int> nibble(0, 15);

  std::string scope(16, '0');
  for (auto& c : scope) {
    c = kHex[nibble(rd)];
  }
  return scope;
}

/// @brief Build the keyring for one role and return its serial. Built in the
/// session keyring, which this process possesses and so can add to, then
/// linked into the user keyring, which outlives the bpfjctl that exits as soon
/// as load() returns.
[[nodiscard]] Expected<std::uint32_t> buildKeyring(
    const std::string& scope,
    const std::string& role,
    const RolePolicy& rolePolicy,
    const Policy& policy) noexcept {
  Keyring keyring(kKeyringPrefix, scope + ":" + role);
  if (auto res = keyring.init(); !res) {
    return makeUnexpected(res.error());
  }

  for (const auto& certId : rolePolicy.enforceBinaryCerts) {
    // Policy parsing rejects a reference with no certificate behind it.
    const auto& der = policy.certs.at(certId);
    if (auto res = keyring.addPKey(certId, der); !res) {
      return makeUnexpected(res.error());
    }
  }

  if (auto res = keyring.persist(); !res) {
    return makeUnexpected(res.error());
  }

  const auto serial = keyring.keyring();
  if (serial < 0) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument, "keyring for role ", role, " has no id"));
  }

  return static_cast<std::uint32_t>(serial);
}

/// @brief Write one bpfj_key_map entry per role that names a certificate, and
/// the matching bpfj_keyring_owner entry. Before attach(), so no jailed task
/// reaches the hooks mid-write and the add_key() calls here are not yet
/// subject to the key_permission gate they install.
[[nodiscard]] Expected<> writeKeyMap(
    bpfj::libbpf::BpfSkelBase& skel,
    const Policy& policy) noexcept {
  auto map = skel.getMap(kKeyMap.data());
  if (!map) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory, "no map named ", kKeyMap));
  }

  auto owners = skel.getMap(kOwnerMap.data());
  if (!owners) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory, "no map named ", kOwnerMap));
  }

  auto floors = skel.getMap(kSeqMap.data());
  if (!floors) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory, "no map named ", kSeqMap));
  }

  // One scope for the load, so a reader can tell which tree a keyring is.
  const std::string scope = makeKeyringScope();

  for (const auto& [role, rolePolicy] : policy.roles) {
    if (rolePolicy.enforceBinaryCerts.empty()) {
      continue;
    }

    auto id = makeRoleId(role);
    if (!id) {
      return makeUnexpected(id.error());
    }

    auto serial = buildKeyring(scope, role, rolePolicy, policy);
    if (!serial) {
      return makeUnexpected(serial.error());
    }

    if (auto res = map->updateElem(*id, *serial); !res) {
      return res;
    }

    if (auto res = owners->updateElem(*serial, *id); !res) {
      return res;
    }

    // Last of the three, so a role is never sequence-checked before it has a
    // keyring to verify the signature against.
    if (rolePolicy.hasMinSeq) {
      if (auto res = floors->updateElem(*id, rolePolicy.minSeq); !res) {
        return res;
      }
    }
  }

  return unit;
}

} // namespace

Expected<> VerityEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<verity_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }

  if (auto res = pins::pinScratchMaps(skel, mapDir); !res) {
    return res;
  }

  if (auto res = pins::pinMap(skel, kKeyMap, mapDir, kMaxRoleKeys); !res) {
    return res;
  }

  if (auto res = pins::pinMap(skel, kOwnerMap, mapDir, kMaxRoleKeys); !res) {
    return res;
  }

  if (auto res = pins::pinMap(skel, kSeqMap, mapDir, kMaxRoleKeys); !res) {
    return res;
  }

  if (auto res = gate::pinMaps(skel, kGate, mapDir); !res) {
    return res;
  }

  if (auto res = skel.load(); !res) {
    return res;
  }

  if (auto res = writeKeyMap(skel, policy); !res) {
    return res;
  }

  if (auto res = gate::writePolicy(skel, kGate, policy); !res) {
    return res;
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }

  const auto linkDir = cfg.linkDir();
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_verity_mmap_file, "bpfj_verity_mmap_file"},
      {skel.links().bpfj_verity_bprm_check, "bpfj_verity_bprm_check"},
      {skel.links().bpfj_keyring_check, "bpfj_keyring_check"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }

  return unit;
}

Expected<std::vector<keyctl::Serial>> VerityEnforcer::disarm(
    const PinConfig& cfg) noexcept {
  std::vector<keyctl::Serial> serials;

  std::error_code ec;
  if (!std::filesystem::exists(cfg.mapPath(kKeyMap), ec)) {
    // Nothing loaded here, or a tree that never named a certificate.
    return serials;
  }

  auto map = pins::openPinnedMap(cfg, kKeyMap);
  if (!map) {
    return makeUnexpected(map.error());
  }

  // Every role collected before any is deleted, since deleting the key a
  // walk is on sends bpf_map_get_next_key back to the start.
  std::vector<struct bpfj_role_id> roles;
  struct bpfj_role_id next{};
  int rc = ::bpf_map_get_next_key(map->get(), nullptr, &next);
  while (rc == 0) {
    roles.push_back(next);
    rc = ::bpf_map_get_next_key(map->get(), &roles.back(), &next);
  }

  for (const auto& role : roles) {
    std::uint32_t serial = 0;
    if (::bpf_map_lookup_elem(map->get(), &role, &serial) != 0) {
      continue;
    }

    if (::bpf_map_delete_elem(map->get(), &role) != 0) {
      return makeUnexpected(makeError(
          std::error_code(errno, std::generic_category()),
          "failed to clear ",
          kKeyMap));
    }
    serials.push_back(static_cast<keyctl::Serial>(serial));
  }

  return serials;
}

void VerityEnforcer::release(
    const std::vector<keyctl::Serial>& serials) noexcept {
  for (const auto serial : serials) {
    keyctl::unlink(serial, keyringPersistTarget());
  }
}

} // namespace bpfjailer
