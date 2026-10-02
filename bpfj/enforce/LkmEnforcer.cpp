// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/LkmEnforcer.h"

#include <string_view>

#include "bpfj/enforce/bpf/lkm_enforce.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

Expected<> LkmEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  (void)policy;
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<lkm_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }
  if (auto res = skel.load(); !res) {
    return res;
  }
  if (auto res = heap::init(created.value()); !res) {
    return res;
  }
  if (auto res = skel.attach(); !res) {
    return res;
  }

  const auto linkDir = cfg.linkDir();
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_kernel_module_request, "bpfj_kernel_module_request"},
      {skel.links().bpfj_kernel_load_data, "bpfj_kernel_load_data"},
      {skel.links().bpfj_kernel_read_file, "bpfj_kernel_read_file"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }

  return unit;
}

} // namespace bpfjailer
