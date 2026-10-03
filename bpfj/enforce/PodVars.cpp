// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/PodVars.h"

#include <bpf/bpf.h>
#include <sys/mman.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <vector>

#include "bpfj/enforce/ArenaMap.h"
#include "bpfj/enforce/RoleId.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kArenaMap = "bpfj_heap_arena";

std::mutex& openMutex() noexcept {
  static std::mutex mutex;
  return mutex;
}

std::array<std::size_t, arena::kSlotCount>& openCounts() noexcept {
  static std::array<std::size_t, arena::kSlotCount> counts{};
  return counts;
}

std::size_t slotIndex(std::uint64_t extra) noexcept {
  return static_cast<std::size_t>(
      (extra - arena::kWindowBase) / arena::kSlotSize);
}

} // namespace

[[nodiscard]] std::uint32_t varCatalogAllocSize(
    std::span<const std::string> names) noexcept {
  std::uint32_t size = bpfj_var_align_up(
      offsetof(struct bpfj_var_catalog, names) +
      sizeof(struct bpfj_var_name*) * names.size());
  for (const auto& name : names) {
    size += bpfj_var_align_up(
        offsetof(struct bpfj_var_name, str) + static_cast<__u32>(name.size()) +
        1);
  }
  return size;
}

[[nodiscard]] const struct bpfj_policy_catalog* readPolicyCatalogPointer(
    const PodArena& arena) noexcept {
  const auto* ctrl = arena.ctrl();
  return ctrl == nullptr
      ? nullptr
      : static_cast<const struct bpfj_policy_catalog*>(ctrl->var_catalog);
}

[[nodiscard]] Expected<struct bpfj_var_catalog*> publishVarNames(
    PodArena& arena,
    std::span<const std::string> names) noexcept {
  if (!names.empty()) {
    auto blob = arena.alloc(varCatalogAllocSize(names));
    if (!blob) {
      return makeUnexpected(blob.error());
    }

    auto* catalog = static_cast<struct bpfj_var_catalog*>(*blob);
    *catalog = {};
    catalog->count = static_cast<__u32>(names.size());
    auto* publishedNames = bpfj_var_catalog_names_mut(catalog);

    std::uint32_t nameOff = bpfj_var_align_up(
        offsetof(struct bpfj_var_catalog, names) +
        sizeof(struct bpfj_var_name*) * names.size());
    for (std::size_t i = 0; i < names.size(); ++i) {
      const auto& name = names[i];
      auto* stored = reinterpret_cast<struct bpfj_var_name*>(
          static_cast<char*>(*blob) + nameOff);
      stored->id = static_cast<__u32>(i + 1);
      stored->len = static_cast<__u32>(name.size());
      std::memcpy(stored->str, name.data(), name.size());
      stored->str[name.size()] = '\0';
      publishedNames[i] = stored;
      nameOff += bpfj_var_align_up(
          offsetof(struct bpfj_var_name, str) + stored->len + 1);
    }

    return catalog;
  }
  return nullptr;
}

[[nodiscard]] Expected<const struct bpfj_role_set*> publishRoleSet(
    PodArena& arena,
    const Fd& rolePolicies,
    const std::vector<std::string>& roles) noexcept {
  const std::uint32_t size = static_cast<std::uint32_t>(
      offsetof(struct bpfj_role_set, policies) +
      roles.size() * sizeof(struct bpfj_role_policy*));
  auto blob = arena.alloc(size);
  if (!blob) {
    return makeUnexpected(blob.error());
  }

  auto* set = static_cast<struct bpfj_role_set*>(*blob);
  set->count = static_cast<__u32>(roles.size());
  for (std::size_t i = 0; i < roles.size(); ++i) {
    auto policy = lookupRolePolicy(rolePolicies, roles[i]);
    if (!policy || !*policy) {
      (void)arena.free(set);
      return !policy ? makeUnexpected(policy.error())
                     : makeUnexpected(makeError(
                           std::errc::invalid_argument,
                           "role list names unknown role ",
                           roles[i]));
    }
    set->policies[i] = *policy;
  }
  return set;
}

Expected<> publishPolicyCatalog(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  if (readPolicyCatalogPointer(*arena) != nullptr) {
    return makeUnexpected(makeError(
        std::errc::file_exists, "the arena policy catalog is already set"));
  }

  const std::uint32_t catalogSize = static_cast<std::uint32_t>(
      offsetof(struct bpfj_policy_catalog, policies) +
      policy.roles.size() * sizeof(struct bpfj_role_policy));
  auto rootBlob = arena->alloc(catalogSize);
  if (!rootBlob) {
    return makeUnexpected(rootBlob.error());
  }
  auto* catalog = static_cast<struct bpfj_policy_catalog*>(*rootBlob);
  std::memset(catalog, 0, catalogSize);
  catalog->count = static_cast<__u32>(policy.roles.size());
  catalog->runtime_owner_versions = BPFJ_RUNTIME_OWNER_VERSIONS;

  auto rolePolicies = pins::openPinnedMap(cfg, "bpfj_role_policies");
  if (!rolePolicies) {
    return makeUnexpected(rolePolicies.error());
  }

  std::size_t index = 0;
  for (const auto& [name, source] : policy.roles) {
    auto id = makeRoleId(name);
    if (!id) {
      return makeUnexpected(id.error());
    }
    auto& out = catalog->policies[index++];
    out.role_id = *id;
    out.min_seq = source.minSeq;
    out.flags = (source.overrideStacked ? BPFJ_POLICY_OVERRIDE_STACKED : 0) |
        (source.unprivEnroll ? BPFJ_POLICY_UNPRIV_ENROLL : 0) |
        (source.noLkm ? BPFJ_POLICY_NO_LKM : 0) |
        (source.hasMinSeq ? BPFJ_POLICY_HAS_MIN_SEQ : 0);
    out.bpf_mode = source.noBpf ? BPFJ_POLICY_DENY
        : source.hasBpf ? (source.untrackedBpf ? BPFJ_POLICY_ALLOW_UNTRACKED
                                               : BPFJ_POLICY_ALLOW)
                        : BPFJ_POLICY_UNCONFIGURED;
    out.mq_sysv_mode = source.noMqSysv ? BPFJ_POLICY_DENY
        : source.hasMqSysv             ? BPFJ_POLICY_ALLOW
                                       : BPFJ_POLICY_UNCONFIGURED;
    out.mq_posix_mode = source.noMqPosix ? BPFJ_POLICY_DENY
        : source.hasMqPosix              ? BPFJ_POLICY_ALLOW
                                         : BPFJ_POLICY_UNCONFIGURED;
    out.shm_sysv_mode = source.noShmSysv ? BPFJ_POLICY_DENY
        : source.hasShmSysv              ? BPFJ_POLICY_ALLOW
                                         : BPFJ_POLICY_UNCONFIGURED;
    out.shm_posix_mode = source.noShmPosix ? BPFJ_POLICY_DENY
        : source.hasShmPosix               ? BPFJ_POLICY_ALLOW
                                           : BPFJ_POLICY_UNCONFIGURED;
    out.kill_mode = source.noKill ? BPFJ_POLICY_DENY
        : source.hasKill          ? BPFJ_POLICY_ALLOW
                                  : BPFJ_POLICY_UNCONFIGURED;
    out.ptrace_mode = source.noPtrace ? BPFJ_POLICY_DENY
        : source.hasPtrace            ? BPFJ_POLICY_ALLOW
                                      : BPFJ_POLICY_UNCONFIGURED;
    out.keyring_mode = source.noKeyring ? BPFJ_POLICY_DENY
        : source.hasKeyring             ? BPFJ_POLICY_ALLOW
                                        : BPFJ_POLICY_UNCONFIGURED;

    const struct bpfj_role_policy_ref ref{.policy = &out};
    if (::bpf_map_update_elem(
            rolePolicies->get(), &out.role_id, &ref, BPF_NOEXIST) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to publish arena policy for role ", name));
    }
  }

  index = 0;
  for (const auto& [name, source] : policy.roles) {
    (void)name;
    auto& out = catalog->policies[index++];
    const struct {
      enum bpfj_policy_gate gate;
      bool configured;
      const std::vector<std::string>* roles;
    } sets[] = {
        {BPFJ_POLICY_GATE_BPF, source.hasBpf, &source.bpf},
        {BPFJ_POLICY_GATE_KILL, source.hasKill, &source.kill},
        {BPFJ_POLICY_GATE_PTRACE, source.hasPtrace, &source.ptrace},
        {BPFJ_POLICY_GATE_KEYRING, source.hasKeyring, &source.keyring},
        {BPFJ_POLICY_GATE_ENROLL, source.hasEnroll, &source.enroll},
        {BPFJ_POLICY_GATE_MQ_SYSV, source.hasMqSysv, &source.mqSysv},
        {BPFJ_POLICY_GATE_MQ_POSIX, source.hasMqPosix, &source.mqPosix},
        {BPFJ_POLICY_GATE_SHM_SYSV, source.hasShmSysv, &source.shmSysv},
        {BPFJ_POLICY_GATE_SHM_POSIX, source.hasShmPosix, &source.shmPosix},
    };
    for (const auto& set : sets) {
      if (!set.configured) {
        continue;
      }
      auto published = publishRoleSet(*arena, *rolePolicies, *set.roles);
      if (!published) {
        return makeUnexpected(published.error());
      }
      out.gates[set.gate] = *published;
    }
  }

  auto vars = publishVarNames(*arena, policy.vars);
  if (!vars) {
    return makeUnexpected(vars.error());
  }
  catalog->vars = *vars;
  arena->ctrl()->var_catalog = catalog;
  return unit;
}

Expected<const struct bpfj_policy_catalog*> readPolicyCatalog(
    const PodArena& arena) noexcept {
  if (!arena.valid()) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "policy catalog read needs an open arena"));
  }
  return readPolicyCatalogPointer(arena);
}

Expected<const struct bpfj_role_policy*> lookupRolePolicy(
    const Fd& rolePolicies,
    const struct bpfj_role_id& role) noexcept {
  struct bpfj_role_policy_ref ref{};
  if (::bpf_map_lookup_elem(rolePolicies.get(), &role, &ref) == 0) {
    return ref.policy;
  }
  if (errno == ENOENT) {
    return nullptr;
  }
  return makeUnexpected(makeErrnoError("failed to look up arena role policy"));
}

Expected<const struct bpfj_role_policy*> lookupRolePolicy(
    const Fd& rolePolicies,
    std::string_view role) noexcept {
  auto id = makeRoleId(std::string(role));
  if (!id) {
    return makeUnexpected(id.error());
  }
  return lookupRolePolicy(rolePolicies, *id);
}

Expected<const struct bpfj_var_catalog*> readVarCatalog(
    const PodArena& arena) noexcept {
  if (!arena.valid()) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "variable catalog read needs an open arena"));
  }

  const auto* catalog = readPolicyCatalogPointer(arena);
  return catalog == nullptr ? nullptr : catalog->vars;
}

Expected<ResolvedPolicyVar> lookupVar(
    const struct bpfj_var_catalog* catalog,
    std::string_view name) noexcept {
  if (name.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "a variable name is empty"));
  }

  const std::uint32_t count = catalog == nullptr ? 0 : catalog->count;
  const auto* publishedNames = bpfj_var_catalog_names(catalog);
  for (std::uint32_t at = 0; at < count; ++at) {
    const auto* published = publishedNames[at];
    if (published != nullptr && published->len == name.size() &&
        std::string_view(published->str, published->len) == name) {
      return ResolvedPolicyVar{.id = published->id, .name = published};
    }
  }

  return makeUnexpected(makeError(
      std::errc::invalid_argument,
      "no variable named ",
      name,
      " is published in this jail"));
}

struct bpfj_heap_control* PodArena::ctrl() noexcept {
  return reinterpret_cast<struct bpfj_heap_control*>(base_);
}

const struct bpfj_heap_control* PodArena::ctrl() const noexcept {
  return reinterpret_cast<const struct bpfj_heap_control*>(base_);
}

PodArena::~PodArena() noexcept {
  reset();
}

PodArena::PodArena(PodArena&& other) noexcept
    : owner_{std::move(other.owner_)},
      base_{other.base_},
      mapExtra_{other.mapExtra_} {
  other.base_ = nullptr;
  other.mapExtra_ = 0;
}

PodArena& PodArena::operator=(PodArena&& other) noexcept {
  if (this != &other) {
    reset();
    owner_ = std::move(other.owner_);
    base_ = other.base_;
    mapExtra_ = other.mapExtra_;
    other.base_ = nullptr;
    other.mapExtra_ = 0;
  }
  return *this;
}

Expected<PodArena> PodArena::open(const PinConfig& cfg) noexcept {
  if (auto res = arena::ensureWindowReserved(); !res) {
    return makeUnexpected(res.error());
  }

  auto fd = pins::openPinnedMap(cfg, kArenaMap);
  if (!fd) {
    return makeUnexpected(fd.error());
  }

  auto extra = arena::pinnedMapExtra(*fd);
  if (!extra) {
    return makeUnexpected(extra.error());
  }

  const std::size_t index = slotIndex(*extra);
  {
    std::lock_guard<std::mutex> guard(openMutex());
    if (openCounts()[index] == 0) {
      void* const mapped = ::mmap(
          reinterpret_cast<void*>(*extra),
          arena::kSlotSize,
          PROT_READ | PROT_WRITE,
          MAP_SHARED | MAP_FIXED,
          fd->get(),
          0);
      if (mapped == MAP_FAILED) {
        return makeUnexpected(
            makeErrnoError("failed to mmap pinned arena at fixed address"));
      }
    }
    ++openCounts()[index];
  }

  PodArena arena;
  arena.owner_ = std::shared_ptr<void>(
      reinterpret_cast<void*>(*extra), [extra = *extra](void*) {
        std::lock_guard<std::mutex> guard(openMutex());
        auto& counts = openCounts();
        const std::size_t slot = slotIndex(extra);
        if (counts[slot] == 0) {
          return;
        }
        --counts[slot];
        if (counts[slot] == 0) {
          (void)::munmap(reinterpret_cast<void*>(extra), arena::kSlotSize);
          (void)arena::restorePlaceholder(extra);
        }
      });
  arena.base_ = reinterpret_cast<void*>(*extra);
  arena.mapExtra_ = *extra;
  return arena;
}

Expected<void*> PodArena::alloc(std::uint32_t size) noexcept {
  const long offset = heap::alloc(base_, size);
  if (offset <= BPFJ_HEAP_NULL) {
    return makeUnexpected(
        makeError(std::errc::not_enough_memory, "failed to allocate pod vars"));
  }

  void* const ptr = heap::offsetToPtr(base_, static_cast<__u32>(offset));
  if (ptr == nullptr) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "pod vars allocation lies outside the arena"));
  }
  return ptr;
}

Expected<> PodArena::free(void* ptr) noexcept {
  const long res = heap::free(base_, ptr);
  if (res != 0) {
    return makeUnexpected(
        makeError(std::errc(-res), "failed to free pod vars from arena"));
  }
  return unit;
}

void PodArena::reset() noexcept {
  owner_.reset();
  base_ = nullptr;
  mapExtra_ = 0;
}

} // namespace bpfjailer
