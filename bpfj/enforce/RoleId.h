// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstring>
#include <string>

#include "bpfj/err/Error.h"

// report_event's union holds an anonymous struct, ordinary C11 but an
// extension in ISO C++, silenced here as Pods.h silences it so the enforcers
// need not include types.h raw.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "bpfj/enforce/bpf/types.h"
#pragma GCC diagnostic pop

namespace bpfjailer {

/// @brief Pack a role id into the fixed-width key the BPF maps are declared
/// with. Truncating rather than failing would be a silent bypass, an enforcer
/// reading the resulting missing entry as "not checked".
[[nodiscard]] inline Expected<struct bpfj_role_id> makeRoleId(
    const std::string& name) noexcept {
  if (name.size() >= sizeof(bpfj_role_id::id)) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "role id '",
        name,
        "' is longer than ",
        std::to_string(sizeof(bpfj_role_id::id) - 1),
        " characters"));
  }

  struct bpfj_role_id id{};
  std::memcpy(id.id, name.data(), name.size());
  return id;
}

} // namespace bpfjailer
