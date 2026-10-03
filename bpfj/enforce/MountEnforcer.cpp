// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/MountEnforcer.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bpfj/enforce/bpf/types.h"
#include "bpfj/enforce/bpf/types_mount_enforce.h" // @manual
#include "bpfj/match/bpf/types_mount.h" // @manual

// The generated skeleton embeds bpfj_mount_cache by value.
#include "bpfj/enforce/bpf/mount_enforce.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/StrMap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/match/FileMatchCached.h"

namespace bpfjailer {

namespace {

[[nodiscard]] bool configured(const RolePolicy& role) noexcept {
  return !role.mount.empty() || role.hasUmount;
}

[[nodiscard]] std::uint8_t pathSpecificity(std::string_view path) noexcept {
  std::uint8_t specificity = 0;
  std::size_t begin = 0;
  while (begin < path.size()) {
    while (begin < path.size() && path[begin] == '/') {
      ++begin;
    }
    const auto end = path.find('/', begin);
    const auto component = path.substr(
        begin,
        end == std::string_view::npos ? path.size() - begin : end - begin);
    if (!component.empty() && component != "*") {
      if (specificity != std::numeric_limits<std::uint8_t>::max()) {
        ++specificity;
      }
    }
    if (end == std::string_view::npos) {
      break;
    }
    begin = end + 1;
  }
  return specificity;
}

[[nodiscard]] struct bpfj_role_id roleId(std::string_view name) noexcept {
  struct bpfj_role_id role{};
  const auto size = std::min(name.size(), sizeof(role.id) - 1);
  std::memcpy(role.id, name.data(), size);
  return role;
}

} // namespace

Expected<> MountEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (std::none_of(
          policy.roles.begin(), policy.roles.end(), [](const auto& item) {
            return configured(item.second);
          })) {
    return unit;
  }
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  using Skel = bpfj::libbpf::BpfSkel<mount_enforce_bpf>;
  using Matcher = FileMatchCached<mount_enforce_bpf>;
  auto created = Skel::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto obj = created.value();
  auto& skel = *obj;
  if (auto res = pins::pinSharedMaps(skel, cfg.mapDir()); !res) {
    return res;
  }
  if (auto res = skel.load(); !res) {
    return res;
  }
  if (auto res = heap::init(obj); !res) {
    return res;
  }

  std::unordered_map<std::string, __u32> variableIds;
  for (std::size_t i = 0; i < policy.vars.size(); ++i) {
    variableIds.emplace(policy.vars[i], static_cast<__u32>(i + 1));
  }
  const GlobKeyResolver resolveVariable =
      [ids = std::move(variableIds)](
          std::string_view name) -> err::Expected<__u32> {
    if (name.starts_with('$')) {
      name.remove_prefix(1);
    }
    const auto found = ids.find(std::string(name));
    if (found == ids.end()) {
      return err::Error(
          std::errc::invalid_argument,
          "mount path references undeclared variable '" + std::string(name) +
              "'");
    }
    return found->second;
  };

  auto matchLru =
      std::make_shared<Matcher::Lru>(obj, skel.bss().bpfj_mount_match_lru);
  std::deque<struct bpfj_file_matcher*> slots;
  std::vector<std::unique_ptr<Matcher>> matchers;
  std::map<std::string, void*> roleMatchers;
  std::uint32_t nextRule = 1;
  const int typesFd = bpf_map__fd(skel.maps().bpfj_mount_types);
  const int umountFd = bpf_map__fd(skel.maps().bpfj_umount_roles);

  for (const auto& [name, role] : policy.roles) {
    if (role.hasUmount) {
      const auto id = roleId(name);
      const std::uint8_t allowed = role.umount ? 1 : 0;
      if (::bpf_map_update_elem(umountFd, &id, &allowed, BPF_NOEXIST) != 0) {
        return makeUnexpected(
            makeErrnoError("failed to publish umount policy for role ", name));
      }
    }
    if (role.mount.empty()) {
      continue;
    }

    std::map<std::string, struct bpfj_mount_path_entry> paths;
    for (const auto& [path, types] : role.mount) {
      if (nextRule == 0) {
        return makeUnexpected(
            makeError(std::errc::value_too_large, "too many mount path rules"));
      }
      const std::uint32_t rule = nextRule++;
      const std::string compiledPath = path == "/" ? "/*" : path;
      paths.emplace(
          compiledPath,
          bpfj_mount_path_entry{
              .rule_id = rule,
              .specificity = pathSpecificity(path),
              .has_types = types.empty() ? std::uint8_t{0} : std::uint8_t{1},
          });
      for (const auto& type : types) {
        struct bpfj_mount_type_key key{.rule_id = rule};
        std::memcpy(key.type, type.data(), type.size());
        const std::uint8_t allowed = 1;
        if (::bpf_map_update_elem(typesFd, &key, &allowed, BPF_NOEXIST) != 0) {
          return makeUnexpected(makeErrnoError(
              "failed to publish filesystem type '",
              type,
              "' for mount destination ",
              path));
        }
      }
    }

    auto& slot = slots.emplace_back(nullptr);
    auto matcher = std::make_unique<Matcher>();
    if (auto res = matcher->init(
            obj,
            resolveVariable,
            Matcher::SharedMaps{.match = matchLru},
            slot,
            paths);
        !res) {
      return res.error();
    }
    roleMatchers.emplace(name, slot);
    matchers.push_back(std::move(matcher));
  }

  StrMap<Skel> matcherMap{obj, skel.bss().bpfj_mount_matchers, false};
  if (auto res = matcherMap.init(roleMatchers); !res) {
    return res.error();
  }
  if (auto res = skel.attach(); !res) {
    return res;
  }

  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_mount_new, "bpfj_mount_new"},
      {skel.links().bpfj_mount_remount, "bpfj_mount_remount"},
      {skel.links().bpfj_mount_move_source, "bpfj_mount_move_source"},
      {skel.links().bpfj_mount_remount_relay, "bpfj_mount_remount_relay"},
      {skel.links().bpfj_remount, "bpfj_remount"},
      {skel.links().bpfj_umount, "bpfj_umount"},
      {skel.links().bpfj_move_mount_destination, "bpfj_move_mount_destination"},
      {skel.links().bpfj_move_mount_source, "bpfj_move_mount_source"},
      {skel.links().bpfj_pivot_root_new, "bpfj_pivot_root_new"},
      {skel.links().bpfj_pivot_root_old, "bpfj_pivot_root_old"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, cfg.linkDir()); !res) {
      return res;
    }
  }
  for (auto& matcher : matchers) {
    matcher->release();
  }
  matchLru->release();
  return unit;
}

} // namespace bpfjailer
