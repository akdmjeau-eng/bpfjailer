// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/BpfEnforcer.h"

#include <cstdint>
#include <string_view>

#include "bpfj/enforce/RoleId.h"

#include "bpfj/enforce/bpf/bpf_enforce.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kMapOwners = "bpfj_bpf_map_owners";
constexpr std::string_view kProgOwners = "bpfj_bpf_prog_owners";
constexpr std::string_view kOwnerVersion = "bpfj_bpf_owner_version";

// Sized well above what a host runs -- one devserver had 6176 maps and 269
// programs live -- because a failed insert leaves an object reading as
// unowned and therefore openable. A base role configured for bpf would put
// the whole host back in here, which is what `untracked-bpf` is for.
constexpr std::uint32_t kMaxOwnedMaps = 16384;
constexpr std::uint32_t kMaxOwnedProgs = 4096;

/// @brief Publish the layout of this build's owner records, which the next
/// build's replace reads through the pin to decide whether it can carry
/// them across.
[[nodiscard]] Expected<> writeOwnerVersion(
    bpfj::libbpf::BpfSkelBase& skel) noexcept {
  auto version = skel.getMap(kOwnerVersion.data());
  if (!version) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory,
        "the BPF owner version map is missing"));
  }

  const std::uint32_t slot = 0;
  const std::uint32_t value = BPFJ_BPF_OWNER_VERSION;
  return version->updateElem(slot, value);
}

} // namespace

Expected<> BpfEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  (void)policy;
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<bpf_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }

  const std::pair<std::string_view, std::uint32_t> owned[] = {
      {kMapOwners, kMaxOwnedMaps},
      {kProgOwners, kMaxOwnedProgs},
      // Pinned like the rest so a replace can read the running tree's copy
      // before it decides whether to carry that tree's records across.
      {kOwnerVersion, 1},
  };
  for (const auto& [name, maxEntries] : owned) {
    if (auto res = pins::pinMap(skel, name, mapDir, maxEntries); !res) {
      return res;
    }
  }

  if (auto res = skel.load(); !res) {
    return res;
  }

  if (auto res = heap::init(created.value()); !res) {
    return res;
  }

  if (auto res = writeOwnerVersion(skel); !res) {
    return res;
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }

  // Objects a configured role opened before load would be unowned and so
  // unprotected. The same one-shot walk the base role uses, over open files.
  {
    bpfj::libbpf::BpfLink seed(skel.links().bpfj_bpf_seed_owners);
    if (auto res = seed.iter(); !res) {
      return makeUnexpected(res.error());
    }
  }

  const auto linkDir = cfg.linkDir();
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_bpf_map_created, "bpfj_bpf_map_created"},
      {skel.links().bpfj_bpf_prog_loaded, "bpfj_bpf_prog_loaded"},
      {skel.links().bpfj_bpf_map_check, "bpfj_bpf_map_check"},
      {skel.links().bpfj_bpf_prog_check, "bpfj_bpf_prog_check"},
      {skel.links().bpfj_bpf_map_free, "bpfj_bpf_map_free"},
      {skel.links().bpfj_bpf_prog_free, "bpfj_bpf_prog_free"},
      // Last: this is the program that can deny bpf(2), and pinning is itself
      // a bpf(2) call.
      {skel.links().bpfj_bpf_syscall, "bpfj_bpf_syscall"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }

  return unit;
}

} // namespace bpfjailer
