// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/Jailer.h"

#include <time.h>

#include <cstdint>
#include <filesystem>
#include <random>

// Ahead of the skeleton, in its own block so the formatter keeps it there: the
// generated rodata struct only forward-declares `struct bpfj_uuid`.
#include "bpfj/enforce/RoleId.h"

#include "bpfj/enforce/RoleGate.h"

// For unload(), which disarms the fs-verity keyrings before removing the map
// that names them; the one enforcer with state the pin tree does not own.
#include "bpfj/enforce/VerityEnforcer.h"

#include "bpfj/enforce/bpf/jailer.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

namespace fs = std::filesystem;

// Held by the jailer rather than an enforcer because nothing in BPF reads it;
// bpfjsrv opens the pins and checks a caller's roles before enrolling it.
constexpr RoleGate kEnrollGate{
    .rolesMap = "bpfj_enroll_roles",
    .accessMap = "bpfj_enroll_access",
    .configured = &RolePolicy::hasEnroll,
    .targets = &RolePolicy::enroll,
};

/// @brief A random version 4 uuid, which only has to be unique rather than
/// unguessable, naming a pod in a map the jailer owns.
[[nodiscard]] struct bpfj_uuid makeUuid4() noexcept {
  std::random_device rd;
  std::uniform_int_distribution<unsigned int> byte(0, 255);

  struct bpfj_uuid uuid{};
  for (auto& b : uuid.uuid) {
    b = static_cast<unsigned char>(byte(rd));
  }

  // Version 4, variant 1, matching bpfj_make_uuid4 on the BPF side.
  uuid.uuid[6] = static_cast<unsigned char>((uuid.uuid[6] & 0x0f) | 0x40);
  uuid.uuid[8] = static_cast<unsigned char>((uuid.uuid[8] & 0x3f) | 0x80);
  return uuid;
}

/// @brief Put the base role's pod in bpfj_pod_map, here rather than in BPF so
/// it exists before the seeding iterator runs. Its one reference belongs to
/// the load and is never given back, the pod being the floor for the jailer's
/// lifetime; unload takes the whole map with it.
[[nodiscard]] Expected<> createBasePod(
    bpfj::libbpf::BpfSkelBase& skel,
    const std::string& role,
    const struct bpfj_uuid& uuid) noexcept {
  auto roleId = makeRoleId(role);
  if (!roleId) {
    return makeUnexpected(makeError(
        roleId.error().code(), "base-role: ", roleId.error().message()));
  }

  auto map = skel.getMap("bpfj_pod_map");
  if (!map) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory, "no map named bpfj_pod_map"));
  }

  struct bpfj_pod pod{};
  pod.role_id = *roleId;
  pod.uuid = uuid;
  pod.refs = 1;
  pod.enrollment_source = BPFJ_ENROLL_BASE_ROLE;
  bpfj_var_array_init(&pod.var_array);

  // CLOCK_MONOTONIC, matching the bpf_ktime_get_ns() BPF stamps with.
  struct timespec ts{};
  if (::clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    pod.creation_time_ns =
        static_cast<std::int64_t>(ts.tv_sec) * 1000000000 + ts.tv_nsec;
  }

  return map->updateElem(uuid, pod, BPF_NOEXIST);
}

/// @brief Publish the roles that terminate a pod-stack walk, from here rather
/// than each enforcer since the map is shared and the walk order is a property
/// of the jail. A role absent from the map reads as not overriding.
[[nodiscard]] Expected<> writeOverrideRoles(
    bpfj::libbpf::BpfSkelBase& skel,
    const Policy& policy) noexcept {
  auto map = skel.getMap("bpfj_pod_override_map");
  if (!map) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory,
        "no map named bpfj_pod_override_map"));
  }

  for (const auto& [name, rolePolicy] : policy.roles) {
    if (!rolePolicy.overrideStacked) {
      continue;
    }

    auto roleId = makeRoleId(name);
    if (!roleId) {
      return makeUnexpected(roleId.error());
    }

    if (auto res = map->updateElem(*roleId, std::uint8_t{1}); !res) {
      return res;
    }
  }

  return unit;
}

} // namespace

Expected<> Jailer::load(const PinConfig& cfg, const Policy& policy) noexcept {
  // Before makeTree rather than inside it: the links going is what detaches
  // whatever was running, so removing only the map pins would leave those
  // programs attached to unreachable maps.
  if (auto res = unload(cfg); !res) {
    return res;
  }

  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<jailer_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  // One path from the binary's own xattr, plus optionally the base role.
  skel.rodata().bpfj_enroll_from_xattr = 1;

  // Before load(), since the uuid travels through rodata, frozen at load.
  const bool hasBaseRole = !policy.baseRole.empty();
  const struct bpfj_uuid baseUuid = makeUuid4();
  if (hasBaseRole) {
    skel.rodata().bpfj_base_role_enabled = 1;
    skel.rodata().bpfj_base_role_uuid = baseUuid;
  }

  if (auto res = pins::pinSharedMaps(skel, cfg.mapDir()); !res) {
    return res;
  }

  if (auto res = pins::pinScratchMaps(skel, cfg.mapDir()); !res) {
    return res;
  }

  if (auto res = gate::pinMaps(skel, kEnrollGate, cfg.mapDir()); !res) {
    return res;
  }

  if (auto res = skel.load(); !res) {
    return res;
  }

  if (auto res = heap::init(created.value()); !res) {
    return res;
  }

  // Before attach, so no hook can run against a half-written map and read an
  // overriding role as an ordinary one.
  if (auto res = writeOverrideRoles(skel, policy); !res) {
    return res;
  }

  if (auto res = gate::writePolicy(skel, kEnrollGate, policy); !res) {
    return res;
  }

  // Before attach, so the seeding walk and a fork racing it both find it.
  if (hasBaseRole) {
    if (auto res = createBasePod(skel, policy.baseRole, baseUuid); !res) {
      return res;
    }
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }

  // After attach, so anything forked from here on is covered by
  // bpfj_jailer_fork whether or not the walk reaches it. Unpinned, the walk
  // being over once this returns.
  if (hasBaseRole) {
    bpfj::libbpf::BpfLink seed(skel.links().bpfj_jailer_seed_base_role);
    if (auto res = seed.iter(); !res) {
      return makeUnexpected(res.error());
    }
  }

  // An attached link that is not pinned dies with this process, and for
  // bpfj_jailer_free that means pods created and never released.
  const auto linkDir = cfg.linkDir();
  if (auto res = pins::pinLink(
          skel.links().bpfj_jailer_fork, "bpfj_jailer_fork", linkDir);
      !res) {
    return res;
  }

  if (auto res = pins::pinLink(
          skel.links().bpfj_jailer_exec, "bpfj_jailer_exec", linkDir);
      !res) {
    return res;
  }

  return pins::pinLink(
      skel.links().bpfj_jailer_free, "bpfj_jailer_free", linkDir);
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
