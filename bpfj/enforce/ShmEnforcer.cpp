// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/ShmEnforcer.h"

#include <bpf/bpf.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/enforce/IpcGlob.h"
#include "bpfj/enforce/bpf/shm_enforce.skel.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

constexpr std::uint32_t kMaxOwners = 16384;
constexpr std::uint32_t kMaxMounts = 4096;
constexpr long kTmpfsMagic = 0x01021994;
constexpr std::string_view kMountMap = "bpfj_shm_posix_mounts";
constexpr std::string_view kDeviceMap = "bpfj_shm_posix_devices";

[[nodiscard]] std::uint64_t kernelDev(dev_t dev) noexcept {
  return (static_cast<std::uint64_t>(major(dev)) << 20) |
      static_cast<std::uint64_t>(minor(dev));
}
struct MountRegistration {
  bpfj_shm_mount_key key{};
  std::uint64_t dev = 0;
};

Expected<std::optional<MountRegistration>> inspectPosixShmMount(
    pid_t pid) noexcept {
  const std::string prefix = "/proc/" + std::to_string(pid);
  struct stat namespaceStat{};
  if (::stat((prefix + "/ns/mnt").c_str(), &namespaceStat) != 0) {
    return makeUnexpected(makeErrnoError(
        "failed to inspect pid ", std::to_string(pid), " mount namespace"));
  }

  std::ifstream mountInfo(prefix + "/mountinfo");
  if (!mountInfo) {
    return makeUnexpected(makeErrnoError(
        "failed to read pid ", std::to_string(pid), " mount table"));
  }

  std::optional<std::uint64_t> mountId;
  std::string line;
  while (std::getline(mountInfo, line)) {
    std::istringstream fields(line);
    std::string id;
    std::string parent;
    std::string device;
    std::string root;
    std::string mountPoint;
    if (!(fields >> id >> parent >> device >> root >> mountPoint) ||
        mountPoint != "/dev/shm") {
      continue;
    }

    std::uint64_t parsed = 0;
    const auto [end, error] =
        std::from_chars(id.data(), id.data() + id.size(), parsed);
    if (error != std::errc{} || end != id.data() + id.size()) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "invalid /dev/shm mount id '",
          id,
          "' for pid ",
          std::to_string(pid)));
    }
    mountId = parsed;
    break;
  }

  if (!mountId) {
    return std::optional<MountRegistration>{};
  }

  struct stat objectStat{};
  const std::string path = prefix + "/root/dev/shm";
  if (::stat(path.c_str(), &objectStat) != 0) {
    return makeUnexpected(makeErrnoError("failed to inspect ", path));
  }
  struct statfs filesystem{};
  if (::statfs(path.c_str(), &filesystem) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to inspect filesystem ", path));
  }
  if (filesystem.f_type != kTmpfsMagic) {
    return std::optional<MountRegistration>{};
  }

  return std::optional<MountRegistration>{MountRegistration{
      .key =
          {
              .namespace_ino = static_cast<std::uint64_t>(namespaceStat.st_ino),
              .mount_id = *mountId,
          },
      .dev = kernelDev(objectStat.st_dev),
  }};
}

Expected<> publishMount(
    int mounts,
    int devices,
    const MountRegistration& registration) noexcept {
  if (::bpf_map_update_elem(
          mounts, &registration.key, &registration.dev, BPF_ANY) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to publish a POSIX shared-memory mount"));
  }

  const std::uint8_t yes = 1;
  if (::bpf_map_update_elem(devices, &registration.dev, &yes, BPF_ANY) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to publish a POSIX shared-memory device"));
  }
  return unit;
}

} // namespace

Expected<> registerPosixShmMount(const PinConfig& cfg, pid_t pid) noexcept {
  auto mounts = pins::openPinnedMap(cfg, kMountMap);
  if (!mounts &&
      mounts.error().code() ==
          std::make_error_code(std::errc::no_such_file_or_directory)) {
    return unit;
  }
  if (!mounts) {
    return makeUnexpected(mounts.error());
  }

  auto devices = pins::openPinnedMap(cfg, kDeviceMap);
  if (!devices) {
    return makeUnexpected(devices.error());
  }

  auto registration = inspectPosixShmMount(pid);
  if (!registration) {
    return makeUnexpected(registration.error());
  }
  return *registration
      ? publishMount(mounts->get(), devices->get(), **registration)
      : Expected<>{unit};
}

Expected<> ShmEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<shm_enforce_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();
  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }
  for (const auto name : {
           "bpfj_shm_sysv_owners",
           "bpfj_shm_posix_owners",
           "bpfj_shm_posix_pending",
       }) {
    if (auto res = pins::pinMap(skel, name, mapDir, kMaxOwners); !res) {
      return res;
    }
  }
  if (auto res = pins::pinMap(skel, kMountMap, mapDir, kMaxMounts); !res) {
    return res;
  }
  if (auto res = pins::pinMap(skel, kDeviceMap, mapDir, kMaxMounts); !res) {
    return res;
  }

  if (auto res = skel.load(); !res) {
    return res;
  }
  if (auto res = compileIpcPatterns(
          created.value(),
          skel.bss().bpfj_ipc_glob_run0,
          skel.bss().bpfj_ipc_glob_run1,
          skel.bss().bpfj_ipc_glob_run2,
          skel.bss().bpfj_ipc_glob_run3,
          policy,
          &RolePolicy::shmPosixPatterns,
          &bpfj_role_policy::shm_posix_patterns);
      !res) {
    return res;
  }
  auto registration = inspectPosixShmMount(::getpid());
  if (!registration) {
    return makeUnexpected(registration.error());
  }
  if (*registration) {
    auto mounts = skel.getMap(kMountMap.data());
    auto devices = skel.getMap(kDeviceMap.data());
    if (!mounts || !devices) {
      return makeUnexpected(makeError(
          std::errc::no_such_file_or_directory,
          "POSIX shared-memory classifier maps are missing"));
    }
    if (auto res = publishMount(
            ::bpf_map__fd(mounts->get()),
            ::bpf_map__fd(devices->get()),
            **registration);
        !res) {
      return res;
    }
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }

  const auto linkDir = cfg.linkDir();
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_shm_sysv_alloc, "bpfj_shm_sysv_alloc"},
      {skel.links().bpfj_shm_sysv_free, "bpfj_shm_sysv_free"},
      {skel.links().bpfj_shm_sysv_associate, "bpfj_shm_sysv_associate"},
      {skel.links().bpfj_shm_sysv_ctl, "bpfj_shm_sysv_ctl"},
      {skel.links().bpfj_shm_sysv_attach, "bpfj_shm_sysv_attach"},
      {skel.links().bpfj_shm_posix_alloc, "bpfj_shm_posix_alloc"},
      {skel.links().bpfj_shm_posix_open, "bpfj_shm_posix_open"},
      {skel.links().bpfj_shm_posix_receive_fd, "bpfj_shm_posix_receive_fd"},
      {skel.links().bpfj_shm_posix_permission, "bpfj_shm_posix_permission"},
      {skel.links().bpfj_shm_posix_mmap, "bpfj_shm_posix_mmap"},
      {skel.links().bpfj_shm_posix_mprotect, "bpfj_shm_posix_mprotect"},
      {skel.links().bpfj_shm_posix_unlink, "bpfj_shm_posix_unlink"},
      {skel.links().bpfj_shm_posix_truncate, "bpfj_shm_posix_truncate"},
      {skel.links().bpfj_shm_posix_file_truncate,
       "bpfj_shm_posix_file_truncate"},
      {skel.links().bpfj_shm_posix_free, "bpfj_shm_posix_free"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }
  return unit;
}

} // namespace bpfjailer
