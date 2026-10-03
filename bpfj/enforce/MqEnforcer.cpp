// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/MqEnforcer.h"

#include <cstdint>
#include <string_view>

#include "bpfj/enforce/IpcGlob.h"
#include "bpfj/enforce/bpf/mq_enforce.skel.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

constexpr std::uint32_t kMaxOwners = 16384;

} // namespace

Expected<> MqEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<mq_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();
  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }
  for (const auto name : {"bpfj_mq_sysv_owners", "bpfj_mq_posix_owners"}) {
    if (auto res = pins::pinMap(skel, name, mapDir, kMaxOwners); !res) {
      return res;
    }
  }
  if (auto res = skel.load(); !res) {
    return res;
  }
  auto patterns = compileIpcPatterns(
      created.value(),
      skel.bss().bpfj_mq_posix_patterns,
      skel.bss().bpfj_ipc_glob_run0,
      skel.bss().bpfj_ipc_glob_run1,
      skel.bss().bpfj_ipc_glob_run2,
      skel.bss().bpfj_ipc_glob_run3,
      policy,
      &RolePolicy::mqPosixPatterns);
  if (!patterns) {
    return makeUnexpected(patterns.error());
  }
  if (auto res = publishIpcPatternIds(
          cfg, *patterns, &bpfj_role_policy::mq_posix_pattern_id);
      !res) {
    return res;
  }
  if (auto res = skel.attach(); !res) {
    return res;
  }

  const auto linkDir = cfg.linkDir();
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_mq_sysv_alloc, "bpfj_mq_sysv_alloc"},
      {skel.links().bpfj_mq_sysv_free, "bpfj_mq_sysv_free"},
      {skel.links().bpfj_mq_sysv_associate, "bpfj_mq_sysv_associate"},
      {skel.links().bpfj_mq_sysv_msgctl, "bpfj_mq_sysv_msgctl"},
      {skel.links().bpfj_mq_sysv_send, "bpfj_mq_sysv_send"},
      {skel.links().bpfj_mq_sysv_receive, "bpfj_mq_sysv_receive"},
      {skel.links().bpfj_mq_posix_alloc, "bpfj_mq_posix_alloc"},
      {skel.links().bpfj_mq_posix_open, "bpfj_mq_posix_open"},
      {skel.links().bpfj_mq_posix_receive_fd, "bpfj_mq_posix_receive_fd"},
      {skel.links().bpfj_mq_posix_free, "bpfj_mq_posix_free"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }
  return unit;
}

} // namespace bpfjailer
