// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/UnprivRoles.h"

#include <bpf/bpf.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "bpfj/enforce/bpf/types.h"
#pragma GCC diagnostic pop

namespace bpfjailer {

namespace {

constexpr std::string_view kUnprivEnrollMap = "bpfj_unpriv_enroll_map";

struct RoleIdLess {
  bool operator()(const bpfj_role_id& lhs, const bpfj_role_id& rhs)
      const noexcept {
    return std::memcmp(lhs.id, rhs.id, sizeof(lhs.id)) < 0;
  }
};

/// @brief `name` as a map key, rejecting one too long to be represented.
[[nodiscard]] Expected<bpfj_role_id> makeRoleKey(
    std::string_view name) noexcept {
  if (name.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "a role id is empty"));
  }

  // Truncating instead would silently map two different roles onto one key,
  // and the shorter of them would inherit the other's access.
  if (name.size() >= ROLE_ID_LEN) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "role '",
        name,
        "' must be at most ",
        std::to_string(ROLE_ID_LEN - 1),
        " characters"));
  }

  bpfj_role_id key{};
  std::memcpy(key.id, name.data(), name.size());
  return key;
}

/// @brief Every key currently in the map.
[[nodiscard]] Expected<std::vector<bpfj_role_id>> currentKeys(
    const Fd& map) noexcept {
  std::vector<bpfj_role_id> keys;
  std::set<bpfj_role_id, RoleIdLess> seen;

  bpfj_role_id curr{};
  bpfj_role_id next{};
  const void* from = nullptr;
  while (::bpf_map_get_next_key(map.get(), from, &next) == 0) {
    // Deleting the key a walk resumes from makes the kernel restart at the
    // first one, so a key arriving twice means the walk wrapped. Nothing is
    // deleted during this walk, but the guard costs one comparison and keeps a
    // concurrent publisher from turning this into a loop with no end.
    if (!seen.insert(next).second) {
      break;
    }

    keys.push_back(next);
    curr = next;
    from = &curr;
  }

  return keys;
}

} // namespace

Expected<> publishUnprivRoles(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  auto map = pins::openPinnedMap(cfg, kUnprivEnrollMap);
  if (!map) {
    return makeUnexpected(map.error());
  }

  std::set<bpfj_role_id, RoleIdLess> wanted;
  for (const auto& [name, role] : policy.roles) {
    if (!role.unprivEnroll) {
      continue;
    }

    auto key = makeRoleKey(name);
    if (!key) {
      return makeUnexpected(key.error());
    }

    constexpr std::uint8_t kAllowed = 1;
    if (::bpf_map_update_elem(map->get(), &*key, &kAllowed, BPF_ANY) != 0) {
      return makeUnexpected(makeErrnoError(
          "failed to allow unprivileged enrollment of role ", name));
    }

    wanted.insert(*key);
  }

  auto keys = currentKeys(*map);
  if (!keys) {
    return makeUnexpected(keys.error());
  }

  for (const bpfj_role_id& key : *keys) {
    if (wanted.count(key) != 0) {
      continue;
    }

    if (::bpf_map_delete_elem(map->get(), &key) != 0 && errno != ENOENT) {
      return makeUnexpected(makeErrnoError(
          "failed to withdraw unprivileged enrollment of role ",
          std::string(key.id, ::strnlen(key.id, ROLE_ID_LEN))));
    }
  }

  return unit;
}

Expected<bool> unprivEnrollAllowed(
    const PinConfig& cfg,
    std::string_view role) noexcept {
  auto key = makeRoleKey(role);
  if (!key) {
    return makeUnexpected(key.error());
  }

  auto map = pins::openPinnedMap(cfg, kUnprivEnrollMap);
  if (!map) {
    return makeUnexpected(map.error());
  }

  std::uint8_t allowed = 0;
  if (::bpf_map_lookup_elem(map->get(), &*key, &allowed) != 0) {
    if (errno == ENOENT) {
      return false;
    }

    return makeUnexpected(makeErrnoError(
        "failed to read the unprivileged enrollment policy for role ", role));
  }

  return allowed != 0;
}

} // namespace bpfjailer
