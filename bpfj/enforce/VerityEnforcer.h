// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <vector>

#include "bpfj/enforce/Pins.h"
#include "bpfj/enforce/ScratchMapFds.h"
#include "bpfj/err/Error.h"
#include "bpfj/fsverity/Keyctl.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief Loads, attaches and pins the fs-verity signature enforcer, giving
/// each role that lists `enforceBinaryCerts` a keyring of exactly those
/// certificates for `bpfj_key_map` to point at. As with Jailer the pins own
/// the programs, but the keyrings live in the kernel's keyring subsystem
/// rather than under the pin tree, which is why disarm() and release() exist
/// and why Jailer::unload() calls both.
class VerityEnforcer {
 public:
  /// @brief Load and attach the enforcer, pinning its links and maps under
  /// `cfg` and keying it from `policy`. Expects Jailer::load() to have run
  /// first, so this can adopt the pinned jail maps and reuse its scratch maps.
  [[nodiscard]] static Expected<> load(
      const PinConfig& cfg,
      const Policy& policy,
      const ScratchMapFds& scratchMaps) noexcept;

  /// @brief Empty this tree's `bpfj_key_map` and return the keyring serials
  /// it held, for release() once the tree's programs are gone. Unlinking the
  /// keyrings while the programs are still attached would refuse every signed
  /// binary, since a serial that no longer resolves denies; an empty map reads
  /// as unchecked instead. Driven off the map rather than off the names, so it
  /// never returns a keyring another live tree is pointing at.
  [[nodiscard]] static Expected<std::vector<keyctl::Serial>> disarm(
      const PinConfig& cfg) noexcept;

  /// @brief Unlink keyrings disarm() returned from the user keyring, which is
  /// what lets the kernel reap them. Best effort.
  static void release(const std::vector<keyctl::Serial>& serials) noexcept;
};

} // namespace bpfjailer
