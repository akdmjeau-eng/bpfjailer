// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/PodVars.h"

#include <bpf/bpf.h>

#include <array>
#include <cstring>

#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kVarMap = "bpfj_var_map";

// Mirrors DefaultVars in the closed tree. Append only: an id is a position in
// this list, and renumbering one re-points every pod already enrolled against
// it without anything failing to build or load.
constexpr std::array<std::string_view, 2> kVarNames = {
    "vm_uuid",
    "root_device",
};

// Slot 0 is reserved for "no name", so the names take one more slot than there
// are of them.
static_assert(
    kVarNames.size() + 1 <= BPFJ_VAR_MAP_SIZE,
    "bpfj_var_map has no room for every name in kVarNames");

} // namespace

std::span<const std::string_view> defaultVarNames() noexcept {
  return kVarNames;
}

Expected<Fd> openVarMap(const PinConfig& cfg) noexcept {
  return pins::openPinnedMap(cfg, kVarMap);
}

Expected<> publishVarNames(const PinConfig& cfg) noexcept {
  auto varMap = openVarMap(cfg);
  if (!varMap) {
    return makeUnexpected(varMap.error());
  }

  for (std::uint32_t i = 0; i < kVarNames.size(); ++i) {
    const std::string_view name = kVarNames[i];
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
