// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/PtraceEnforcer.h"

#include <string_view>
#include <utility>

#include "bpfj/enforce/RoleGate.h"

#include "bpfj/enforce/bpf/ptrace_enforce.skel.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

constexpr RoleGate kGate{
    .rolesMap = "bpfj_ptrace_roles",
    .accessMap = "bpfj_ptrace_access",
    .configured = &RolePolicy::hasPtrace,
    .denied = &RolePolicy::noPtrace,
    .targets = &RolePolicy::ptrace,
};

} // namespace

Expected<> PtraceEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<ptrace_enforce_bpf>::create();
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

  const auto linkDir = cfg.linkDir();
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_ptrace_check, "bpfj_ptrace_check"},
      {skel.links().bpfj_ptrace_traceme, "bpfj_ptrace_traceme"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }

  return unit;
}

} // namespace bpfjailer
