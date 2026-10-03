// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/BpfEnforcer.h"

#include <bpf/bpf.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <string_view>

#include "bpfj/enforce/bpf/bpf_enforce.skel.h"
#include "bpfj/lib/Fd.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfProgram.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kMapOwners = "bpfj_bpf_map_owners";
constexpr std::string_view kProgOwners = "bpfj_bpf_prog_owners";

// Sized well above what a host runs -- one devserver had 6176 maps and 269
// programs live -- because a failed insert leaves an object reading as
// unowned and therefore openable. A base role configured for bpf would put
// the whole host back in here, which is what `untracked-bpf` is for.
constexpr std::uint32_t kMaxOwnedMaps = 16384;
constexpr std::uint32_t kMaxOwnedProgs = 4096;
// PIDFD_THREAD is the O_EXCL bit, without including conflicting kernel fcntl.
constexpr unsigned int kPidFdThread = O_EXCL;

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
  };
  for (const auto& [name, maxEntries] : owned) {
    if (auto res = pins::pinMap(skel, name, mapDir, maxEntries); !res) {
      return res;
    }
  }

  if (auto res = skel.load(); !res) {
    return res;
  }

  bpfj::libbpf::BpfProgram syscallProgram(skel.progs().bpfj_bpf_syscall);
  syscallProgram.setAutoattach(false);

  // The syscall hook must permit this loader after it attaches: pinning the
  // hook and enabling enforcement are themselves bpf(2) operations. Task
  // storage is keyed by pidfd at the syscall boundary and disappears with the
  // task, so this cannot turn PID reuse into a permanent privilege bypass.
  const auto loaderTid = static_cast<pid_t>(::syscall(SYS_gettid));
  const unsigned int pidFdFlags = loaderTid == ::getpid() ? 0 : kPidFdThread;
  Fd loaderPidFd(
      static_cast<int>(::syscall(SYS_pidfd_open, loaderTid, pidFdFlags)));
  if (!loaderPidFd.hasFd()) {
    return makeUnexpected(
        makeErrnoError("failed to open a pidfd for the BPF enforcer loader"));
  }
  const int loaderKey = loaderPidFd.get();
  constexpr std::uint8_t kLoader = 1;
  if (::bpf_map_update_elem(
          ::bpf_map__fd(skel.maps().bpfj_bpf_loader_tasks),
          &loaderKey,
          &kLoader,
          BPF_ANY) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to mark the BPF enforcer loader task"));
  }

  if (auto res = heap::init(created.value()); !res) {
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
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }

  // This program can deny bpf(2), including the calls used to attach and pin
  // links. Keep it detached until every other BPF operation is complete.
  auto syscallLink = syscallProgram.attach();
  if (!syscallLink) {
    return makeUnexpected(syscallLink.error());
  }
  if (auto res = pins::pinLink(syscallLink->get(), "bpfj_bpf_syscall", linkDir);
      !res) {
    (void)syscallLink->destroy();
    return res;
  }
  if (auto res = syscallLink->destroy(); !res) {
    return res;
  }
  skel.bss().bpfj_bpf_enforcing = true;

  return unit;
}

} // namespace bpfjailer
