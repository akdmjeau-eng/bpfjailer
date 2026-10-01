// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/lib/Fd.h"

namespace bpfjailer {

/// @brief A pod variable as a caller spells it, before its id is resolved.
struct PodVar {
  std::string name;
  std::string value;
};

/// @brief Open the pinned bpfj_var_map.
[[nodiscard]] Expected<Fd> openVarMap(const PinConfig& cfg) noexcept;

/// @brief Publish the policy's `vars` into the pinned bpfj_var_map. A name's id
/// is its 1-based position in `names`, so an unused slot reads back as the
/// empty name. The published list is the whole allowlist: an enrollment that
/// names anything else fails to resolve. A bpfj_var carries the id, not the
/// name, and this map lets processes that never talk to each other agree on
/// what id 1 means. bpfjsrv is a fresh process for each connection. Ids are
/// positions, so a different policy can renumber them. A replace therefore
/// translates ids by name (see readVarNames()).
[[nodiscard]] Expected<> publishVarNames(
    const PinConfig& cfg,
    std::span<const std::string> names) noexcept;

/// @brief Every name in `varMap`, indexed by id. An unused id reads back
/// empty.
[[nodiscard]] Expected<std::vector<std::string>> readVarNames(
    const Fd& varMap) noexcept;

/// @brief The id `name` was published under in `varMap`, read back from the
/// map so the answer is the running jail's rather than whatever policy this
/// binary last saw.
[[nodiscard]] Expected<std::uint32_t> lookupVarId(
    const Fd& varMap,
    std::string_view name) noexcept;

} // namespace bpfjailer
