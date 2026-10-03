// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/ArenaMap.h"

#include <bpf/bpf.h>
#include <sys/mman.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace bpfjailer::arena {

namespace {

namespace fs = std::filesystem;

constexpr std::string_view kArenaMapName = "bpfj_heap_arena";
static_assert(sizeof(void*) == sizeof(std::uint64_t));
static_assert((kWindowBase % BPFJ_HEAP_PAGE_SIZE) == 0);
static_assert((kSlotSize % BPFJ_HEAP_PAGE_SIZE) == 0);

struct WindowState {
  std::once_flag once;
  std::optional<Error> error;
};

WindowState& windowState() noexcept {
  static WindowState state;
  return state;
}

std::string hex(std::uint64_t value) noexcept {
  char buf[19];
  std::snprintf(buf, sizeof(buf), "0x%016llx", (unsigned long long)value);
  return buf;
}

void reserveWindowOnce() noexcept {
  void* const mapped = ::mmap(
      reinterpret_cast<void*>(kWindowBase),
      kWindowSize,
      PROT_NONE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
      -1,
      0);
  if (mapped == MAP_FAILED) {
    windowState().error = makeErrnoError(
        "failed to reserve arena window at ",
        hex(kWindowBase),
        " (",
        std::to_string(kWindowSize),
        " bytes)");
    return;
  }

  if (reinterpret_cast<std::uint64_t>(mapped) != kWindowBase) {
    (void)::munmap(mapped, kWindowSize);
    windowState().error = makeError(
        std::errc::address_not_available,
        "arena window reserved at ",
        hex(reinterpret_cast<std::uint64_t>(mapped)),
        ", expected ",
        hex(kWindowBase));
  }
}

[[nodiscard]] std::size_t slotIndex(std::uint64_t extra) noexcept {
  return static_cast<std::size_t>((extra - kWindowBase) / kSlotSize);
}

Expected<std::optional<std::uint64_t>> pinnedMapExtraAt(
    const fs::path& path) noexcept {
  const int fd = ::bpf_obj_get(path.c_str());
  if (fd < 0) {
    if (errno == ENOENT) {
      return std::optional<std::uint64_t>{};
    }
    return makeUnexpected(
        makeErrnoError("failed to open pinned arena map ", path.string()));
  }

  Fd wrapped(fd);
  auto extra = pinnedMapExtra(wrapped);
  if (!extra) {
    return makeUnexpected(extra.error());
  }

  return std::optional<std::uint64_t>{*extra};
}

Expected<std::uint64_t> chooseMapExtra(const fs::path& mapDir) noexcept {
  std::array<bool, kSlotCount> used{};

  std::error_code ec;
  const fs::directory_iterator end;
  for (fs::directory_iterator it(mapDir.parent_path().parent_path(), ec);
       !ec && it != end;
       it.increment(ec)) {
    if (!it->is_directory(ec)) {
      if (ec) {
        break;
      }
      continue;
    }

    auto extra = pinnedMapExtraAt(it->path() / "maps" / kArenaMapName);
    if (!extra) {
      return makeUnexpected(extra.error());
    }
    if (*extra) {
      used[slotIndex(**extra)] = true;
    }
  }
  if (ec) {
    return makeUnexpected(makeError(
        ec,
        "failed to scan arena pins under ",
        mapDir.parent_path().parent_path().string()));
  }

  for (std::size_t i = 0; i < kSlotCount; ++i) {
    if (!used[i]) {
      return kWindowBase + i * kSlotSize;
    }
  }

  return makeUnexpected(makeError(
      std::errc::no_buffer_space,
      "no free arena slot remains in the reserved window"));
}

} // namespace

Expected<> ensureWindowReserved() noexcept {
  auto& state = windowState();
  std::call_once(state.once, reserveWindowOnce);
  if (state.error) {
    return makeUnexpected(*state.error);
  }

  return unit;
}

Expected<std::uint64_t> validateMapExtra(std::uint64_t extra) noexcept {
  if (extra == 0) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "arena map_extra is zero"));
  }

  if ((extra % BPFJ_HEAP_PAGE_SIZE) != 0) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "arena map_extra ",
        hex(extra),
        " is not page aligned"));
  }

  if (extra < kWindowBase || extra >= kWindowBase + kWindowSize) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "arena map_extra ",
        hex(extra),
        " lies outside the reserved window [",
        hex(kWindowBase),
        ", ",
        hex(kWindowBase + kWindowSize),
        ")"));
  }

  if (extra + kSlotSize > kWindowBase + kWindowSize) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "arena map_extra ",
        hex(extra),
        " overruns the reserved window"));
  }

  if (((extra - kWindowBase) % kSlotSize) != 0) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "arena map_extra ",
        hex(extra),
        " is not slot aligned"));
  }

  return extra;
}

Expected<std::uint64_t> pinnedMapExtra(const Fd& fd) noexcept {
  struct bpf_map_info info{};
  __u32 len = sizeof(info);
  if (::bpf_obj_get_info_by_fd(fd.get(), &info, &len) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to read pinned arena map info"));
  }

  return validateMapExtra(info.map_extra);
}

Expected<std::uint32_t> generationForMapExtra(std::uint64_t extra) noexcept {
  auto valid = validateMapExtra(extra);
  if (!valid) {
    return makeUnexpected(valid.error());
  }
  return static_cast<std::uint32_t>(slotIndex(*valid) + 1);
}

Expected<> prepareMap(
    bpfj::libbpf::BpfSkelBase& skel,
    const fs::path& mapDir) noexcept {
  auto map = skel.getMap(kArenaMapName.data());
  if (!map) {
    return unit;
  }

  if (auto res = ensureWindowReserved(); !res) {
    return res;
  }

  const fs::path arenaPath = mapDir / kArenaMapName;
  auto current = pinnedMapExtraAt(arenaPath);
  if (!current) {
    return makeUnexpected(current.error());
  }

  std::uint64_t extra = 0;
  if (*current) {
    extra = **current;
  } else {
    auto chosen = chooseMapExtra(mapDir);
    if (!chosen) {
      return makeUnexpected(chosen.error());
    }
    extra = *chosen;
  }
  if (auto res = map->setMapExtra(extra); !res) {
    return makeUnexpected(res.error());
  }

  return unit;
}

Expected<> restorePlaceholder(std::uint64_t extra) noexcept {
  auto valid = validateMapExtra(extra);
  if (!valid) {
    return makeUnexpected(valid.error());
  }

  void* const mapped = ::mmap(
      reinterpret_cast<void*>(*valid),
      kSlotSize,
      PROT_NONE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
      -1,
      0);
  if (mapped == MAP_FAILED) {
    return makeUnexpected(
        makeErrnoError("failed to restore arena placeholder at ", hex(*valid)));
  }

  return unit;
}

namespace {

__attribute__((constructor)) void reserveArenaWindowEarly() {
  (void)ensureWindowReserved();
}

} // namespace

} // namespace bpfjailer::arena
