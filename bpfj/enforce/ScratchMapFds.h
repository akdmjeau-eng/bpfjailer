// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <array>
#include <utility>

#include "bpfj/err/Error.h"
#include "bpfj/lib/Fd.h"

namespace bpfj::libbpf {
class BpfSkelBase;
}

namespace bpfjailer {

/// @brief Temporary ownership of the scratch pool's map FDs while one loaded
/// BPF object hands the maps to the next object.
class ScratchMapFds {
 public:
  ScratchMapFds(const ScratchMapFds&) = delete;
  ScratchMapFds& operator=(const ScratchMapFds&) = delete;
  ScratchMapFds(ScratchMapFds&&) noexcept = default;
  ScratchMapFds& operator=(ScratchMapFds&&) noexcept = default;

  /// @brief Duplicate the loaded scratch maps from `skel`.
  [[nodiscard]] static Expected<ScratchMapFds> duplicateFrom(
      bpfj::libbpf::BpfSkelBase& skel) noexcept;

  /// @brief Reuse these maps in `skel` before it is loaded.
  [[nodiscard]] Expected<> reuseIn(
      bpfj::libbpf::BpfSkelBase& skel) const noexcept;

 private:
  static constexpr std::array<const char*, 4> kMapNames = {
      "bpfj_scratch_small",
      "bpfj_scratch_large",
      "bpfj_scratch_small_claimed",
      "bpfj_scratch_large_claimed",
  };

  explicit ScratchMapFds(std::array<Fd, kMapNames.size()> fds) noexcept
      : fds_(std::move(fds)) {}

  std::array<Fd, kMapNames.size()> fds_;
};

} // namespace bpfjailer
