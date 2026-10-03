// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/ProcEnforcer.h"

#include "bpfj/enforce/bpf/proc_enforce.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

Expected<> ProcEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  (void)policy;
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<proc_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  if (auto res = pins::pinSharedMaps(skel, cfg.mapDir()); !res) {
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

  return pins::pinLink(
      skel.links().bpfj_proc_file_open, "bpfj_proc_file_open", cfg.linkDir());
}

} // namespace bpfjailer
