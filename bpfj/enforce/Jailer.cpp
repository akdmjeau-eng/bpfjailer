// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/Jailer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>

// Ahead of the skeleton, in its own block so the formatter keeps it there: the
// generated rodata struct only forward-declares `struct bpfj_uuid`.
#include "bpfj/enforce/Pods.h"
#include "bpfj/enforce/RoleId.h"

// For unload(), which disarms the fs-verity keyrings before removing the map
// that names them; the one enforcer with state the pin tree does not own.
#include "bpfj/enforce/VerityEnforcer.h"

#include "bpfj/enforce/bpf/jailer.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

namespace fs = std::filesystem;

/// @brief The encoded base role id, validated in userspace before load so BPF
/// can copy it straight into a prebuilt or fallback-allocated base-role pod.
[[nodiscard]] Expected<struct bpfj_role_id> makeBaseRoleId(
    const std::string& role) noexcept {
  auto roleId = makeRoleId(role);
  if (!roleId) {
    return makeUnexpected(makeError(
        roleId.error().code(), "base-role: ", roleId.error().message()));
  }
  return *roleId;
}

/// @brief Build the one pod the base-role seeding walk names on every task.
[[nodiscard]] Expected<std::pair<PodArena, struct bpfj_pod*>> makeBaseRolePod(
    const PinConfig& cfg,
    const struct bpfj_role_id& roleId) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }

  auto blob = arena->alloc(sizeof(struct bpfj_pod));
  if (!blob) {
    return makeUnexpected(blob.error());
  }

  auto* pod = static_cast<struct bpfj_pod*>(*blob);
  *pod = {};
  pod->role_id = roleId;
  auto rolePolicies = pins::openPinnedMap(cfg, "bpfj_role_policies");
  if (!rolePolicies) {
    (void)arena->free(pod);
    return makeUnexpected(rolePolicies.error());
  }
  auto rolePolicy = lookupRolePolicy(*rolePolicies, roleId);
  if (!rolePolicy || !*rolePolicy) {
    (void)arena->free(pod);
    if (!rolePolicy) {
      return makeUnexpected(rolePolicy.error());
    }
    return makeUnexpected(makeError(
        std::errc::invalid_argument, "base role is missing from policy"));
  }
  pod->policy = *rolePolicy;
  auto uuid = makeUuid4();
  if (!uuid) {
    (void)arena->free(pod);
    return makeUnexpected(uuid.error());
  }
  pod->uuid = *uuid;
  pod->enrollment_source = BPFJ_ENROLL_BASE_ROLE;
  bpfj_var_array_init(&pod->var_array);

  auto nowNs = monotonicNs();
  if (!nowNs) {
    (void)arena->free(pod);
    return makeUnexpected(nowNs.error());
  }
  pod->creation_time_ns = *nowNs;

  return std::pair{std::move(*arena), pod};
}

} // namespace

Expected<ScratchMapFds> Jailer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  constexpr std::size_t kMaxCatalogRoles =
      (std::numeric_limits<std::uint32_t>::max() -
       offsetof(struct bpfj_policy_catalog, policies)) /
      sizeof(struct bpfj_role_policy);
  if (policy.roles.size() > kMaxCatalogRoles) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "the role policy catalog exceeds one arena allocation"));
  }

  // Before makeTree rather than inside it: the links going is what detaches
  // whatever was running, so removing only the map pins would leave those
  // programs attached to unreachable maps.
  if (auto res = unload(cfg); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = pins::makeTree(cfg); !res) {
    return makeUnexpected(res.error());
  }

  auto created = bpfj::libbpf::BpfSkel<jailer_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  // One path from the binary's own xattr, plus optionally the base role.
  skel.rodata().bpfj_enroll_from_xattr = 1;

  // Before load(), since rodata is frozen there.
  const bool hasBaseRole = !policy.baseRole.empty();
  std::optional<struct bpfj_role_id> baseRoleId;
  if (hasBaseRole) {
    auto parsedBaseRoleId = makeBaseRoleId(policy.baseRole);
    if (!parsedBaseRoleId) {
      return makeUnexpected(parsedBaseRoleId.error());
    }
    baseRoleId = *parsedBaseRoleId;
    skel.rodata().bpfj_base_role_enabled = 1;
    skel.rodata().bpfj_base_role_id = *baseRoleId;
  }

  auto rolePolicies = skel.getMap("bpfj_role_policies");
  if (!rolePolicies) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory,
        "the role policy index map is missing"));
  }
  if (auto res = rolePolicies->setMaxEntries(
          std::max<std::size_t>(1, policy.roles.size()));
      !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = pins::pinSharedMaps(skel, cfg.mapDir()); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = skel.load(); !res) {
    return makeUnexpected(res.error());
  }

  auto scratchMaps = ScratchMapFds::duplicateFrom(skel);
  if (!scratchMaps) {
    return makeUnexpected(scratchMaps.error());
  }

  if (auto res = heap::init(created.value()); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = publishPolicyCatalog(cfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  std::optional<PodArena> baseRoleArena;
  struct bpfj_pod* baseRolePod = nullptr;
  auto freeBaseRolePod = makeGuard([&] {
    if (baseRoleArena && baseRolePod) {
      (void)baseRoleArena->free(baseRolePod);
    }
  });
  if (baseRoleId) {
    auto pod = makeBaseRolePod(cfg, *baseRoleId);
    if (!pod) {
      return makeUnexpected(pod.error());
    }
    baseRoleArena = std::move(pod->first);
    baseRolePod = pod->second;
    skel.bss().bpfj_base_role_pod = baseRolePod;
  }

  if (auto res = skel.attach(); !res) {
    return makeUnexpected(res.error());
  }

  // After attach, so anything forked from here on is covered by
  // bpfj_jailer_fork whether or not the walk reaches it. Unpinned, the walk
  // being over once this returns.
  if (hasBaseRole) {
    bpfj::libbpf::BpfLink seed(skel.links().bpfj_jailer_seed_base_role);
    if (auto res = seed.iter(); !res) {
      return makeUnexpected(res.error());
    }
    freeBaseRolePod.dismiss();
  }

  // An attached link that is not pinned dies with this process, and for
  // bpfj_jailer_free that means pods created and never released.
  const auto linkDir = cfg.linkDir();
  if (auto res = pins::pinLink(
          skel.links().bpfj_jailer_fork, "bpfj_jailer_fork", linkDir);
      !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = pins::pinLink(
          skel.links().bpfj_jailer_exec, "bpfj_jailer_exec", linkDir);
      !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = pins::pinLink(
          skel.links().bpfj_jailer_free, "bpfj_jailer_free", linkDir);
      !res) {
    return makeUnexpected(res.error());
  }

  return std::move(*scratchMaps);
}

Expected<> Jailer::unload(const PinConfig& cfg) noexcept {
  if (auto res = pins::checkBpffs(cfg.bpffsPath); !res) {
    return res;
  }

  const fs::path root = cfg.root();

  std::error_code ec;
  if (!fs::exists(root, ec)) {
    return unit;
  }

  // The fs-verity keyrings live in the kernel's keyring subsystem, so
  // removing the pins below would strand them. Disarmed first, the map naming
  // them being one of the pins about to go, and released once they are gone.
  auto serials = VerityEnforcer::disarm(cfg);
  if (!serials) {
    return makeUnexpected(serials.error());
  }

  // Removing a pinned link drops its last reference, detaching the program.
  fs::remove_all(root, ec);

  // Even if the removal failed, disarm() took these out of the map.
  VerityEnforcer::release(*serials);

  if (ec) {
    return makeUnexpected(
        makeError(ec, "failed to remove pin tree ", root.string()));
  }

  return unit;
}

} // namespace bpfjailer
