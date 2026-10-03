// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/enforce/PodVars.h"
#include "bpfj/err/Error.h"
#include "bpfj/lib/GlobMap.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

template <heap::BpfSkelWithHeap Skel>
Expected<std::map<std::string, std::uint32_t>> compileIpcPatterns(
    const std::shared_ptr<Skel>& skel,
    struct bpfj_glob_map*& slot,
    struct bpfj_glob_run*& run0,
    struct bpfj_glob_run*& run1,
    struct bpfj_glob_run*& run2,
    struct bpfj_glob_run*& run3,
    const Policy& policy,
    std::vector<std::string> RolePolicy::* patterns) noexcept {
  std::map<std::string, std::uint32_t> ids;
  std::vector<std::pair<std::string, std::uint64_t>> entries;
  std::uint32_t nextId = 1;
  for (const auto& [role, rolePolicy] : policy.roles) {
    const auto& rolePatterns = rolePolicy.*patterns;
    if (rolePatterns.empty()) {
      continue;
    }
    ids.emplace(role, nextId);
    for (const auto& pattern : rolePatterns) {
      entries.emplace_back(pattern, nextId);
    }
    ++nextId;
  }

  if (auto res = heap::init(skel); res.hasError()) {
    return makeUnexpected(res.error());
  }
  if (entries.empty()) {
    return ids;
  }

  const GlobKeyResolver resolve =
      [&policy](std::string_view name) -> err::Expected<__u32> {
    for (std::size_t i = 0; i < policy.vars.size(); ++i) {
      if (policy.vars[i] == name) {
        return static_cast<__u32>(i + 1);
      }
    }
    return err::Error(
        std::errc::invalid_argument,
        "glob references undeclared variable '" + std::string(name) + "'");
  };

  GlobMap<Skel> compiled(skel, slot, false);
  if (auto res = compiled.init(resolve, std::move(entries)); res.hasError()) {
    return makeUnexpected(res.error());
  }
  struct bpfj_glob_run** runs[] = {&run0, &run1, &run2, &run3};
  for (auto** run : runs) {
    *run = heap::alloc<struct bpfj_glob_run>(skel);
    if (*run == nullptr) {
      return makeUnexpected(makeError(
          std::errc::not_enough_memory,
          "failed to reserve IPC glob matcher run"));
    }
  }
  return ids;
}

inline Expected<> publishIpcPatternIds(
    const PinConfig& cfg,
    const std::map<std::string, std::uint32_t>& ids,
    std::uint32_t bpfj_role_policy::* member) noexcept {
  auto rolePolicies = pins::openPinnedMap(cfg, "bpfj_role_policies");
  if (!rolePolicies) {
    return makeUnexpected(rolePolicies.error());
  }
  for (const auto& [role, id] : ids) {
    auto policy = lookupRolePolicy(*rolePolicies, role);
    if (!policy) {
      return makeUnexpected(policy.error());
    }
    if (!*policy) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "IPC glob role is missing from the arena policy catalog: ",
          role));
    }
    const_cast<struct bpfj_role_policy*>(*policy)->*member = id;
  }
  return unit;
}

} // namespace bpfjailer
