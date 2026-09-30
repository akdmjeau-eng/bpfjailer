// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/lib/Fd.h"

namespace bpfjailer {

/// @brief A pod variable as a caller spells it, before its id is resolved.
struct PodVar {
  std::string name;
  std::string value;
};

/// @brief The variable names this build knows how to enroll against. A
/// bpfj_var carries a numeric id rather than its name, so fixing the list here
/// rather than minting an id per request is what lets two processes that never
/// talk to each other agree on what id 1 refers to -- bpfjsrv being a fresh
/// process per connection.
[[nodiscard]] std::span<const std::string_view> defaultVarNames() noexcept;

/// @brief Open the pinned bpfj_var_map.
[[nodiscard]] Expected<Fd> openVarMap(const PinConfig& cfg) noexcept;

/// @brief Publish defaultVarNames() into the pinned bpfj_var_map, an id being
/// the 1-based position in the list so an unused slot reads back as the empty
/// name. Idempotent, so re-attaching converges rather than shifting ids under
/// pods already enrolled.
[[nodiscard]] Expected<> publishVarNames(const PinConfig& cfg) noexcept;

/// @brief The id `name` was published under in `varMap`, read back from the
/// map rather than defaultVarNames() so a binary built against a different
/// list fails to resolve rather than using somebody else's id.
[[nodiscard]] Expected<std::uint32_t> lookupVarId(
    const Fd& varMap,
    std::string_view name) noexcept;

} // namespace bpfjailer
