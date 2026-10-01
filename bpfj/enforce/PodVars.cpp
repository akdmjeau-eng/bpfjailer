// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/PodVars.h"

#include <bpf/bpf.h>

#include <cstring>

#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kVarMap = "bpfj_var_map";

} // namespace

Expected<Fd> openVarMap(const PinConfig& cfg) noexcept {
  return pins::openPinnedMap(cfg, kVarMap);
}

Expected<> publishVarNames(
    const PinConfig& cfg,
    std::span<const std::string> names) noexcept {
  // Slot 0 means "no name", so the names need one more slot than there are
  // names.
  if (names.size() + 1 > BPFJ_VAR_MAP_SIZE) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "a policy may declare at most ",
        std::to_string(BPFJ_VAR_MAP_SIZE - 1),
        " vars, got ",
        std::to_string(names.size())));
  }

  auto varMap = openVarMap(cfg);
  if (!varMap) {
    return makeUnexpected(varMap.error());
  }

  for (std::uint32_t i = 0; i < names.size(); ++i) {
    const std::string_view name = names[i];
    if (name.size() >= BPFJ_VAR_NAME_LEN) {
      return makeUnexpected(makeError(
          std::errc::value_too_large,
          "variable name ",
          name,
          " must be at most ",
          std::to_string(BPFJ_VAR_NAME_LEN - 1),
          " characters"));
    }

    bpfj_var_name entry{};
    std::memcpy(entry.name, name.data(), name.size());

    const std::uint32_t id = i + 1;
    if (::bpf_map_update_elem(varMap->get(), &id, &entry, BPF_ANY) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to publish variable name ", name));
    }
  }

  return unit;
}

Expected<std::vector<std::string>> readVarNames(const Fd& varMap) noexcept {
  std::vector<std::string> names(BPFJ_VAR_MAP_SIZE);
  for (std::uint32_t id = 1; id < BPFJ_VAR_MAP_SIZE; ++id) {
    bpfj_var_name entry{};
    if (::bpf_map_lookup_elem(varMap.get(), &id, &entry) != 0) {
      return makeUnexpected(makeErrnoError(
          "failed to read the name of variable ", std::to_string(id)));
    }

    names[id].assign(entry.name, ::strnlen(entry.name, BPFJ_VAR_NAME_LEN));
  }

  return names;
}

Expected<std::uint32_t> lookupVarId(
    const Fd& varMap,
    std::string_view name) noexcept {
  if (name.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "a variable name is empty"));
  }

  // bpfj_var_map is an array, so every slot reads back whether or not anything
  // was ever published to it, and an empty name is what an unused one holds.
  for (std::uint32_t id = 1; id < BPFJ_VAR_MAP_SIZE; ++id) {
    bpfj_var_name entry{};
    if (::bpf_map_lookup_elem(varMap.get(), &id, &entry) != 0) {
      continue;
    }

    const std::string_view published(
        entry.name, ::strnlen(entry.name, BPFJ_VAR_NAME_LEN));
    if (!published.empty() && published == name) {
      return id;
    }
  }

  return makeUnexpected(makeError(
      std::errc::invalid_argument,
      "no variable named ",
      name,
      " is published in this jail"));
}

} // namespace bpfjailer
