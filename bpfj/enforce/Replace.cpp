// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/Replace.h"

#include <bpf/bpf.h>
#include <dirent.h>
#include <signal.h>
#include <sys/syscall.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "bpfj/enforce/BpfEnforcer.h"
#include "bpfj/enforce/Jailer.h"
#include "bpfj/enforce/KillEnforcer.h"
#include "bpfj/enforce/PodVars.h"
// For bpfj_pod and bpfj_uuid: Pods.h is where C++ pulls the shared ABI header
// in, with the pedantic warning silenced around it.
#include "bpfj/enforce/Pods.h"
#include "bpfj/enforce/PtraceEnforcer.h"
#include "bpfj/enforce/UnprivRoles.h"
#include "bpfj/enforce/VerityEnforcer.h"
#include "bpfj/enforce/bpf/replace.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/var/bpf/var.h"

namespace bpfjailer {

namespace {

namespace fs = std::filesystem;

constexpr std::string_view kTaskMap = "bpfj_task_map";
constexpr std::string_view kOldTaskMap = "bpfj_old_task_map";
constexpr std::string_view kReplaceFrozenMap = "bpfj_replace_frozen";
constexpr std::string_view kActiveEnrollsMap = "bpfj_active_enrolls";
constexpr std::string_view kMapOwners = "bpfj_bpf_map_owners";
constexpr std::string_view kProgOwners = "bpfj_bpf_prog_owners";
constexpr std::string_view kOwnerVersion = "bpfj_bpf_owner_version";

// The tree the replacement is built in, beside the one being replaced.
constexpr std::string_view kNewSuffix = "-new";

struct ReplacePodValue {
  struct bpfj_pod* pod = nullptr;
};

struct ReplacePodKey {
  struct bpfj_pod* oldPod = nullptr;
};

[[nodiscard]] Expected<ResolvedPolicyVar> translatedVar(
    const struct bpfj_var* var,
    const struct bpfj_var_catalog* catalog) noexcept {
  if (var == nullptr || bpfj_var_get_name(var) == nullptr) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument, "pod variable has no published name"));
  }

  const std::string_view name = bpfj_var_get_name(var);
  auto translated = lookupVar(catalog, name);
  if (!translated) {
    return makeUnexpected(makeError(
        translated.error().code(),
        "pod carries variable '",
        name,
        "', which the new policy does not declare in vars"));
  }

  return translated;
}

[[nodiscard]] Expected<Fd> openPidFd(pid_t pid) noexcept {
  const int fd = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
  if (fd < 0) {
    return makeUnexpected(
        makeErrnoError("failed to open pidfd for pid ", std::to_string(pid)));
  }

  return Fd(fd);
}

[[nodiscard]] Expected<bpfj_pid_data>
readPidData(const Fd& taskMap, const Fd& pidFd, pid_t pid) noexcept {
  bpfj_pid_data pidData{};
  const int key = pidFd.get();
  if (::bpf_map_lookup_elem(taskMap.get(), &key, &pidData) == 0) {
    return pidData;
  }

  if (errno != ENOENT) {
    return makeUnexpected(makeErrnoError(
        "failed to read jail membership of pid ", std::to_string(pid)));
  }

  return bpfj_pid_data{.version = BPFJ_PID_DATA_VERSION};
}

[[nodiscard]] Expected<std::vector<pid_t>> runningPids() noexcept {
  DIR* dir = ::opendir("/proc");
  if (dir == nullptr) {
    return makeUnexpected(makeErrnoError("failed to open /proc"));
  }

  std::vector<pid_t> pids;
  while (const struct dirent* entry = ::readdir(dir)) {
    char* end = nullptr;
    const long value = std::strtol(entry->d_name, &end, 10);
    if (end == entry->d_name || *end != '\0' || value <= 0) {
      continue;
    }
    pids.push_back(static_cast<pid_t>(value));
  }

  ::closedir(dir);
  return pids;
}

/// @brief Copy `src`'s arena-backed vars into a freshly allocated flat pod,
/// translating ids by name so a new policy can renumber the allowlist without
/// changing what a running pod means.
[[nodiscard]] Expected<struct bpfj_pod*> translatePod(
    const bpfj_pod& src,
    PodArena& newArena,
    const struct bpfj_var_catalog* catalog) noexcept {
  const auto count = std::min<std::size_t>(src.var_array.count, BPFJ_VAR_MAX);
  std::uint32_t blobSize = bpfj_var_align_up(sizeof(struct bpfj_pod));
  blobSize += bpfj_var_align_up(sizeof(struct bpfj_var) * count);
  for (std::size_t i = 0; i < count; ++i) {
    const auto* var = bpfj_var_array_at(&src.var_array, i);
    if (var == nullptr) {
      return makeUnexpected(makeError(
          std::errc::bad_address,
          "pod ",
          uuidToString(src.uuid),
          " has an unreadable variable blob"));
    }
    blobSize += bpfj_var_align_up(bpfj_var_payload_size(var));
  }

  auto blob = newArena.alloc(blobSize);
  if (!blob) {
    return makeUnexpected(blob.error());
  }

  auto* dst = static_cast<struct bpfj_pod*>(*blob);
  *dst = src;
  dst->refs = 0;
  bpfj_var_array_init(&dst->var_array);
  if (count == 0) {
    return dst;
  }

  auto* outVars = reinterpret_cast<struct bpfj_var*>(
      static_cast<unsigned char*>(*blob) +
      bpfj_var_align_up(sizeof(struct bpfj_pod)));
  std::uint32_t valueOff = bpfj_var_align_up(sizeof(struct bpfj_pod)) +
      bpfj_var_align_up(sizeof(struct bpfj_var) * count);
  for (std::size_t i = 0; i < count; ++i) {
    const auto* oldVar = bpfj_var_array_at(&src.var_array, i);
    auto translated = translatedVar(oldVar, catalog);
    if (!translated) {
      (void)newArena.free(*blob);
      return makeUnexpected(makeError(
          translated.error().code(),
          "pod ",
          uuidToString(src.uuid),
          ": ",
          translated.error().message()));
    }

    const std::uint32_t payloadSize = bpfj_var_payload_size(oldVar);
    outVars[i] = {
        .id = translated->id,
        .type = oldVar->type,
        .size = oldVar->size,
        .reserved = oldVar->reserved,
        .name = translated->name,
        .val = static_cast<unsigned char*>(*blob) + valueOff,
    };
    std::memcpy(outVars[i].val, bpfj_var_value_ptr(oldVar), payloadSize);
    valueOff += bpfj_var_align_up(payloadSize);
  }

  dst->var_array.vars = outVars;
  dst->var_array.count = static_cast<__u8>(count);
  return dst;
}

/// @brief Copy the old tree's pods into the new arena, less its base role,
/// which Jailer::load has already remade and reseeded. Refs are zeroed on the
/// way across and counted back up by the backfill iterator. Variables cross by
/// name (see translatePod()), and the backfill finds the translated pod again
/// by the old pod pointer value so it never has to dereference the old arena.
[[nodiscard]] Expected<std::size_t> copyPods(
    const PinConfig& oldCfg,
    const PinConfig& newCfg,
    int replacePodsMapFd) noexcept {
  auto oldTaskMap = pins::openPinnedMap(oldCfg, kTaskMap);
  if (!oldTaskMap) {
    return makeUnexpected(oldTaskMap.error());
  }

  auto oldArena = PodArena::open(oldCfg);
  if (!oldArena) {
    return makeUnexpected(oldArena.error());
  }
  (void)oldArena;
  auto newArena = PodArena::open(newCfg);
  if (!newArena) {
    return makeUnexpected(newArena.error());
  }
  std::vector<void*> newPods;
  auto rollbackPods = makeGuard([&] {
    for (void* const pod : newPods) {
      (void)newArena->free(pod);
    }
  });
  std::optional<const struct bpfj_var_catalog*> newCatalog;

  std::set<std::uintptr_t> seen;
  auto pids = runningPids();
  if (!pids) {
    return makeUnexpected(pids.error());
  }

  std::size_t copied = 0;
  for (const pid_t pid : *pids) {
    auto pidFd = openPidFd(pid);
    if (!pidFd) {
      continue;
    }

    auto pidData = readPidData(*oldTaskMap, *pidFd, pid);
    if (!pidData) {
      continue;
    }

    const std::uint8_t count =
        std::min<std::uint8_t>(pidData->num_pods, BPFJ_MAX_POD_PER_PID);
    for (std::uint8_t i = 0; i < count; ++i) {
      const auto* pod = pidData->pods[i];
      if (pod == nullptr ||
          !seen.insert(reinterpret_cast<std::uintptr_t>(pod)).second ||
          pod->enrollment_source == BPFJ_ENROLL_BASE_ROLE) {
        continue;
      }

      if (pod->var_array.count != 0 && !newCatalog) {
        auto read = readVarCatalog(newCfg, *newArena);
        if (!read) {
          return makeUnexpected(read.error());
        }
        newCatalog = *read;
      }

      auto translated =
          translatePod(*pod, *newArena, newCatalog ? *newCatalog : nullptr);
      if (!translated) {
        return makeUnexpected(translated.error());
      }
      newPods.push_back(*translated);

      const ReplacePodKey key{.oldPod = const_cast<struct bpfj_pod*>(pod)};
      const ReplacePodValue entry{.pod = *translated};
      if (::bpf_map_update_elem(replacePodsMapFd, &key, &entry, BPF_ANY) != 0) {
        return makeUnexpected(
            makeErrnoError("failed to record a carried pod for backfill"));
      }
      ++copied;
    }
  }

  rollbackPods.dismiss();
  return copied;
}

// BPF object ownership records are carried across the way the pods are: a
// pinned object is held by its pin rather than anyone's fd, so bpf_enforce's
// seeding walk cannot see the jailer's own maps, and a rebuilt tree would read
// as "nothing is owned".

/// @brief Whether the old tree has a bpf_enforce in it at all; the tests bring
/// enforcers up one at a time, so partial trees are not hypothetical.
[[nodiscard]] bool tracksOwnership(const PinConfig& cfg) noexcept {
  std::error_code ec;
  return fs::exists(fs::path(cfg.mapPath(kMapOwners)), ec);
}

/// @brief Refuse a running tree whose records this build cannot read, since
/// carrying an unknown layout across would write nonsense into the map the
/// gate reads and skipping it would silently unprotect what the old tree owned.
[[nodiscard]] Expected<> checkOwnerVersion(const PinConfig& cfg) noexcept {
  if (!tracksOwnership(cfg)) {
    return unit;
  }

  auto map = pins::openPinnedMap(cfg, kOwnerVersion);
  if (!map) {
    if (map.error().code() !=
        std::make_error_code(std::errc::no_such_file_or_directory)) {
      return makeUnexpected(map.error());
    }

    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running jailer records BPF ownership but publishes no layout "
        "version for it, so this build cannot carry those records across; "
        "detach and attach to move to it, which releases the jail"));
  }

  const std::uint32_t slot = 0;
  std::uint32_t version = 0;
  if (::bpf_map_lookup_elem(map->get(), &slot, &version) != 0) {
    return makeUnexpected(makeErrnoError(
        "failed to read the running jailer's BPF ownership layout version"));
  }

  if (version != BPFJ_BPF_OWNER_VERSION) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running jailer records BPF ownership in layout v",
        std::to_string(version),
        ", and this build reads v",
        std::to_string(BPFJ_BPF_OWNER_VERSION),
        "; detach and attach to move to it, which releases the jail"));
  }

  return unit;
}

/// @brief Carry one owner map's records into the new tree's copy.
[[nodiscard]] Expected<std::size_t> copyOwnerMap(int from, int to) noexcept {
  // Same guard as copyPods(), and the free hook deletes from this map, so a
  // restarted walk is not hypothetical here.
  std::set<std::uint64_t> seen;

  std::size_t copied = 0;
  std::uint64_t curr = 0;
  std::uint64_t next = 0;
  const void* cursor = nullptr;
  while (::bpf_map_get_next_key(from, cursor, &next) == 0) {
    if (!seen.insert(next).second) {
      break;
    }

    struct bpfj_bpf_owner owner{};
    if (::bpf_map_lookup_elem(from, &next, &owner) == 0) {
      if (::bpf_map_update_elem(to, &next, &owner, BPF_ANY) != 0) {
        return makeUnexpected(
            makeErrnoError("failed to copy a BPF ownership record across"));
      }
      ++copied;
    }

    curr = next;
    cursor = &curr;
  }

  return copied;
}

/// @brief Carry both owner maps into the new tree, whose own objects the live
/// enforcer's create hook already recorded in the old map. Runs before the old
/// tree is unloaded, so the new tree's bpf_map_free hook prunes the records for
/// the objects that unload frees.
[[nodiscard]] Expected<std::size_t> copyBpfOwners(
    const PinConfig& oldCfg,
    const PinConfig& newCfg) noexcept {
  if (!tracksOwnership(oldCfg)) {
    return std::size_t{0};
  }

  std::size_t copied = 0;
  for (const auto& name : {kMapOwners, kProgOwners}) {
    auto from = pins::openPinnedMap(oldCfg, name);
    if (!from) {
      return makeUnexpected(from.error());
    }

    auto to = pins::openPinnedMap(newCfg, name);
    if (!to) {
      return makeUnexpected(to.error());
    }

    auto one = copyOwnerMap(from->get(), to->get());
    if (!one) {
      return makeUnexpected(one.error());
    }
    copied += *one;
  }

  return copied;
}

/// @brief Read one of the iterator's single-slot counters.
[[nodiscard]] Expected<std::size_t> readCounter(
    struct bpf_map* map,
    std::string_view what) noexcept {
  const std::uint32_t zero = 0;
  std::uint64_t value = 0;
  if (::bpf_map_lookup_elem(::bpf_map__fd(map), &zero, &value) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to read the backfill ", what, " count"));
  }

  return static_cast<std::size_t>(value);
}

[[nodiscard]] Expected<> setReplaceFrozen(
    const PinConfig& cfg,
    bool frozen) noexcept {
  auto map = pins::openPinnedMap(cfg, kReplaceFrozenMap);
  if (!map) {
    return makeUnexpected(map.error());
  }

  const std::uint32_t slot = 0;
  const std::uint8_t value = frozen ? 1 : 0;
  if (::bpf_map_update_elem(map->get(), &slot, &value, BPF_ANY) != 0) {
    return makeUnexpected(makeErrnoError(
        "failed to ",
        frozen ? "freeze" : "thaw",
        " enrollments in ",
        cfg.root()));
  }

  return unit;
}

[[nodiscard]] bool pidIsAlive(std::uint32_t pid) noexcept {
  return ::kill(static_cast<pid_t>(pid), 0) == 0 || errno != ESRCH;
}

[[nodiscard]] Expected<> waitForActiveEnrollsToDrain(
    const PinConfig& cfg) noexcept {
  auto map = pins::openPinnedMap(cfg, kActiveEnrollsMap);
  if (!map) {
    return makeUnexpected(map.error());
  }

  using namespace std::chrono_literals;
  constexpr auto kTimeout = 5s;
  const auto deadline = std::chrono::steady_clock::now() + kTimeout;

  while (true) {
    std::uint32_t pid = 0;
    if (::bpf_map_get_next_key(map->get(), nullptr, &pid) != 0) {
      if (errno == ENOENT) {
        return unit;
      }

      return makeUnexpected(makeErrnoError(
          "failed to read the in-flight enrollments from ", cfg.root()));
    }

    if (!pidIsAlive(pid)) {
      (void)::bpf_map_delete_elem(map->get(), &pid);
      continue;
    }

    if (std::chrono::steady_clock::now() >= deadline) {
      return makeUnexpected(makeError(
          std::errc::timed_out,
          "timed out waiting for pid ",
          std::to_string(pid),
          " to finish enrolling while replacing the jailer"));
    }

    std::this_thread::sleep_for(1ms);
  }
}

struct BackfillStats {
  std::size_t pods = 0;
  std::size_t tasks = 0;
};

/// @brief Migrate each task's membership into the new tree's task map, through
/// an iterator loaded, run and dropped rather than pinned.
[[nodiscard]] Expected<BackfillStats> backfillTasks(
    const PinConfig& oldCfg,
    const PinConfig& newCfg) noexcept {
  auto created = bpfj::libbpf::BpfSkel<replace_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  // The membership being migrated into, adopted from the tree just built.
  if (auto res = pins::pinSharedMaps(skel, newCfg.mapDir()); !res) {
    return makeUnexpected(res.error());
  }

  // And the one being migrated off, under the program's second name for it;
  // both definitions must match or libbpf refuses the adoption.
  if (auto res =
          pins::pinMapAt(skel, kOldTaskMap, oldCfg.mapPath(kTaskMap), {});
      !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = skel.load(); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = heap::init(created.value()); !res) {
    return makeUnexpected(res.error());
  }

  auto pods =
      copyPods(oldCfg, newCfg, ::bpf_map__fd(skel.maps().bpfj_replace_pods));
  if (!pods) {
    return makeUnexpected(pods.error());
  }

  if (auto res = skel.attach(); !res) {
    return makeUnexpected(res.error());
  }

  // Reading to EOF is what runs the iterator over every task; it emits nothing.
  bpfj::libbpf::BpfLink link(skel.links().bpfj_replace_backfill);
  if (auto res = link.iter(); !res) {
    return makeUnexpected(res.error());
  }

  auto failed = readCounter(skel.maps().bpfj_replace_failed, "failure");
  if (!failed) {
    return makeUnexpected(failed.error());
  }

  if (*failed != 0) {
    // Swapping now would promote a jailer that silently lost part of the jail,
    // leaving those tasks running unjailed.
    return makeUnexpected(makeError(
        std::errc::not_enough_memory,
        "backfill could not migrate ",
        std::to_string(*failed),
        " task(s)"));
  }

  auto migrated = readCounter(skel.maps().bpfj_replace_migrated, "migrated");
  if (!migrated) {
    return makeUnexpected(migrated.error());
  }

  return BackfillStats{.pods = *pods, .tasks = *migrated};
}

/// @brief Everything between building the new tree and it becoming the live
/// one, so that a failure anywhere in it is one thing to take back.
[[nodiscard]] Expected<ReplaceStats> buildAndSwap(
    const PinConfig& cfg,
    const PinConfig& newCfg,
    const Policy& policy) noexcept {
  std::error_code ec;
  const bool hasOld = fs::exists(fs::path(cfg.root()), ec);

  // Before anything is built, so the only cost of refusing is the parse.
  if (hasOld) {
    if (auto res = checkOwnerVersion(cfg); !res) {
      return makeUnexpected(res.error());
    }
  }

  // Destructive, which clears a tree left by a run that died before its swap,
  // and seeds the new base role onto every task before the backfill merges the
  // old membership on top.
  if (auto res = Jailer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = VerityEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = KillEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = PtraceEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  // Last, as in `attach`: this one can deny bpf(2), and everything above still
  // needs the syscall to pin its links.
  if (auto res = BpfEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  // Filled before anything reads them: an enrollment naming a variable
  // resolves it against this allowlist catalog, and bpfjsrv refuses a role
  // missing from the other.
  if (auto res = publishVarNames(newCfg, policy.vars); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = publishUnprivRoles(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  ReplaceStats stats;

  if (hasOld) {
    // Fork and exec enrollment are mirrored by both attached trees; what can
    // still diverge here is a userspace enrollment through the old pins.
    if (auto res = setReplaceFrozen(cfg, true); !res) {
      return makeUnexpected(res.error());
    }
    auto thaw = makeGuard([&] { (void)setReplaceFrozen(cfg, false); });

    if (auto res = waitForActiveEnrollsToDrain(cfg); !res) {
      return makeUnexpected(res.error());
    }

    auto backfill = backfillTasks(cfg, newCfg);
    if (!backfill) {
      return makeUnexpected(backfill.error());
    }
    stats.pods = backfill->pods;
    stats.tasks = backfill->tasks;

    // Before the unload below, so the new tree's free hook prunes the records
    // for the objects that unload is about to free.
    auto owners = copyBpfOwners(cfg, newCfg);
    if (!owners) {
      return makeUnexpected(owners.error());
    }
    stats.owners = *owners;

    // Detaches the old programs, with the new ones held by newCfg's pins until
    // the rename below so no window has no jailer attached. Through unload()
    // rather than remove_all() for the old tree's keyrings, which the pins do
    // not own and which it disarms before releasing.
    if (auto res = Jailer::unload(cfg); !res) {
      return makeUnexpected(res.error());
    }

    thaw.dismiss();
  }

  // bpffs renames a directory with live pins under it and the objects keep
  // working, a pin being a name for a reference rather than the reference.
  fs::rename(newCfg.root(), cfg.root(), ec);
  if (ec) {
    return makeUnexpected(
        makeError(ec, "failed to move ", newCfg.root(), " to ", cfg.root()));
  }

  return stats;
}

} // namespace

Expected<ReplaceStats> replaceJailer(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  PinConfig newCfg = cfg;
  newCfg.pinDir = cfg.pinDir + std::string(kNewSuffix);

  auto res = buildAndSwap(cfg, newCfg, policy);
  if (!res) {
    // The half-built tree is all this created, and unload() takes its keyrings
    // with it; removing only the pins would strand them in the user keyring.
    (void)Jailer::unload(newCfg);
  }

  return res;
}

} // namespace bpfjailer
