// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/VerityEnforcer.h"

#include <bpf/bpf.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/RoleId.h"
#include "bpfj/enforce/bpf/verity_enforce.skel.h"
#include "bpfj/fsverity/Keyctl.h"
#include "bpfj/fsverity/Keyring.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

// The same keyrings the other way round, serial -> role, the direction
// lsm/key_permission needs.
constexpr std::string_view kOwnerMap = "bpfj_keyring_owner";

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

/// @brief Publish each keyring serial in its arena policy and write the
/// matching bpfj_keyring_owner entry. Before attach(), so no jailed task
/// reaches the hooks mid-write and the add_key() calls here are not yet subject
/// to the key_permission gate they install.
[[nodiscard]] Expected<> writeKeyrings(
    bpfj::libbpf::BpfSkelBase& skel,
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  auto owners = skel.getMap(kOwnerMap.data());
  if (!owners) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory, "no map named ", kOwnerMap));
  }

  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies) {
    return makeUnexpected(policies.error());
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

    auto publishedPolicy = lookupRolePolicy(*policies, *id);
    if (!publishedPolicy) {
      return makeUnexpected(publishedPolicy.error());
    }
    if (!*publishedPolicy) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "role ",
          role,
          " is missing from the arena role map"));
    }
    const struct bpfj_role_policy_ref ref{.policy = *publishedPolicy};
    if (auto res = owners->updateElem(*serial, ref); !res) {
      return res;
    }

    auto* published = const_cast<struct bpfj_role_policy*>(*publishedPolicy);
    published->key_serial = *serial;
  }

  return unit;
}

} // namespace

Expected<> VerityEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy,
    const ScratchMapFds& scratchMaps) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<verity_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  if (auto res = scratchMaps.reuseIn(skel); !res) {
    return res;
  }

  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }

  const auto keyringCount = static_cast<std::uint32_t>(std::count_if(
      policy.roles.begin(), policy.roles.end(), [](const auto& role) {
        return !role.second.enforceBinaryCerts.empty();
      }));
  if (auto res = pins::pinMap(skel, kOwnerMap, mapDir, keyringCount); !res) {
    return res;
  }

  if (auto res = skel.load(); !res) {
    return res;
  }

  if (auto res = heap::init(created.value()); !res) {
    return res;
  }

  if (auto res = writeKeyrings(skel, cfg, policy); !res) {
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
  if (!std::filesystem::exists(cfg.mapPath("bpfj_heap_arena"), ec)) {
    // Nothing loaded here, or a tree that never named a certificate.
    return serials;
  }

  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies || !*policies) {
    return serials;
  }
  for (__u32 i = 0; i < (*policies)->capacity; ++i) {
    const auto& entry = (*policies)->vec[i];
    if (entry.key == nullptr) {
      continue;
    }
    auto* policy = static_cast<struct bpfj_role_policy*>(entry.val);
    const auto serial = policy->key_serial;
    if (serial != 0) {
      serials.push_back(static_cast<keyctl::Serial>(serial));
      policy->key_serial = 0;
    }
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
