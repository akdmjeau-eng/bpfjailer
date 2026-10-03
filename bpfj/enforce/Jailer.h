// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/Pins.h"
#include "bpfj/enforce/ScratchMapFds.h"
#include "bpfj/err/Error.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief Loads, attaches and pins the jailer BPF programs. The pins own the
/// jailer, so once load() returns there is no handle to keep and enforcement
/// continues until unload() removes them.
class Jailer {
 public:
  /// @brief Load and attach the jailer, pinning its links and maps under
  /// `cfg`. A `policy` naming a `baseRole` gets one pod with every running
  /// process enrolled before this returns, and everything forked afterwards
  /// inherits it. The returned FDs let the enforcers reuse the unpinned
  /// scratch maps while they load.
  ///
  /// Destructive: anything already pinned under `cfg` is torn down first and
  /// every task jailed under it released, rather than carrying a previous
  /// jailer's membership into a jail built from a different policy --
  /// `replace` is the bring-up that keeps the jail. An enforcer loading
  /// afterwards still adopts these maps.
  [[nodiscard]] static Expected<ScratchMapFds> load(
      const PinConfig& cfg,
      const Policy& policy,
      bool replacementFrozen = false,
      const Fd* generationControl = nullptr) noexcept;

  /// @brief Remove the pin tree, detaching the jailer and every enforcer
  /// under `cfg`, the tree being what holds them attached. Succeeds when
  /// nothing is loaded.
  [[nodiscard]] static Expected<> unload(const PinConfig& cfg) noexcept;
};

} // namespace bpfjailer
