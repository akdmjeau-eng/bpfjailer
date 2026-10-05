// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/err/Error.h"
#include "bpfj/lib/GlobMap.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

[[nodiscard]] inline std::uint64_t ipcPatternPriority(
    std::string_view pattern,
    bool allowed) noexcept {
  std::uint32_t specific = 0;
  for (std::size_t i = 0; i < pattern.size(); ++i) {
    if (pattern[i] == '\\' && i + 1 < pattern.size()) {
      ++specific;
      ++i;
      continue;
    }
    if (pattern[i] == '*' || pattern[i] == '?') {
      continue;
    }
    if (pattern[i] == '$' && i + 1 < pattern.size() && pattern[i + 1] == '{') {
      const auto close = pattern.find('}', i + 2);
      if (close != std::string_view::npos) {
        ++specific;
        i = close;
        continue;
      }
    }
    ++specific;
  }
  const auto length = std::min<std::size_t>(pattern.size(), 0xffff);
  const std::uint64_t priority =
      (static_cast<std::uint64_t>(specific) << 16) | length;
  return (priority << 1) | static_cast<std::uint64_t>(allowed);
}

template <heap::BpfSkelWithHeap Skel>
Expected<> compileIpcPatterns(
    const std::shared_ptr<Skel>& skel,
    struct bpfj_glob_run*& run0,
    struct bpfj_glob_run*& run1,
    struct bpfj_glob_run*& run2,
    struct bpfj_glob_run*& run3,
    const Policy& policy,
    std::map<std::string, bool> RolePolicy::* patterns,
    const struct bpfj_ipc_pattern_set __arena* bpfj_role_policy::*
        published) noexcept {
  struct RoleRange {
    std::string_view role;
    std::uint32_t first;
    std::uint32_t count;
  };
  std::vector<RoleRange> ranges;
  std::vector<std::pair<std::string, std::uint64_t>> entries;
  for (const auto& [role, rolePolicy] : policy.roles) {
    const auto& rolePatterns = rolePolicy.*patterns;
    if (rolePatterns.empty()) {
      continue;
    }
    const auto first = static_cast<std::uint32_t>(entries.size());
    for (const auto& [pattern, allowed] : rolePatterns) {
      entries.emplace_back(
          pattern.substr(1), ipcPatternPriority(pattern.substr(1), allowed));
    }
    ranges.push_back(
        RoleRange{
            .role = role,
            .first = first,
            .count = static_cast<std::uint32_t>(rolePatterns.size()),
        });
  }

  if (auto res = heap::init(skel); res.hasError()) {
    return makeUnexpected(res.error());
  }
  if (entries.empty()) {
    return unit;
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

  struct bpfj_glob_map* matcher = nullptr;
  GlobMap<Skel> compiled(skel, matcher, false);
  if (auto res = compiled.init(resolve, std::move(entries)); res.hasError()) {
    return makeUnexpected(res.error());
  }
  struct bpfj_glob_run** runs[] = {&run0, &run1, &run2, &run3};
  std::vector<std::pair<struct bpfj_role_policy*, struct bpfj_ipc_pattern_set*>>
      selectors;
  auto cleanup = makeGuard([&] {
    for (auto [rolePolicy, selector] : selectors) {
      (void)rolePolicy;
      heap::free(skel, selector);
    }
    for (auto** run : runs) {
      heap::free(skel, *run);
      *run = nullptr;
    }
    compiled.destroy();
  });
  for (auto** run : runs) {
    *run = heap::alloc<struct bpfj_glob_run>(skel);
    if (*run == nullptr) {
      return makeUnexpected(makeError(
          std::errc::not_enough_memory,
          "failed to reserve IPC glob matcher run"));
    }
    bpfj_glob_run_init(*run);
  }
  auto* publishedPolicies = static_cast<struct bpfj_str_map*>(
      skel->bss().bpfj_heap_ctrl->role_policies);
  for (const auto& range : ranges) {
    auto foundPolicy = lookupRolePolicy(publishedPolicies, range.role);
    if (!foundPolicy) {
      return makeUnexpected(foundPolicy.error());
    }
    if (*foundPolicy == nullptr) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "IPC glob role is missing from the arena role map: ",
          range.role));
    }
    auto* rolePolicy = const_cast<struct bpfj_role_policy*>(*foundPolicy);
    auto* selector = heap::alloc<struct bpfj_ipc_pattern_set>(skel);
    if (selector == nullptr) {
      return makeUnexpected(makeError(
          std::errc::not_enough_memory,
          "failed to reserve IPC glob pattern selector"));
    }
    selector->map = matcher;
    selector->first_accept = range.first;
    selector->num_accepts = range.count;
    selectors.emplace_back(rolePolicy, selector);
  }
  for (auto [rolePolicy, selector] : selectors) {
    rolePolicy->*published = selector;
  }
  cleanup.dismiss();
  return unit;
}

} // namespace bpfjailer
