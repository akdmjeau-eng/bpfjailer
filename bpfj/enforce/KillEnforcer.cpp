// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/KillEnforcer.h"

#include "bpfj/enforce/RoleGate.h"

#include "bpfj/enforce/bpf/kill_enforce.skel.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

constexpr RoleGate kGate{
    .rolesMap = "bpfj_kill_roles",
    .accessMap = "bpfj_kill_access",
    .configured = &RolePolicy::hasKill,
    .denied = &RolePolicy::noKill,
    .targets = &RolePolicy::kill,
};

} // namespace

Expected<> KillEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<kill_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }

  if (auto res = gate::pinMaps(skel, kGate, mapDir); !res) {
    return res;
  }

  if (auto res = skel.load(); !res) {
    return res;
  }

  if (auto res = gate::writePolicy(skel, kGate, policy); !res) {
    return res;
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }

  return pins::pinLink(
      skel.links().bpfj_kill_check, "bpfj_kill_check", cfg.linkDir());
}

} // namespace bpfjailer
