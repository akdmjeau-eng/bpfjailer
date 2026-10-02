// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <cstdint>
#include <vector>

#include "bpfj/enforce/ArenaMap.h"
#include "bpfj/enforce/Jailer.h"
#include "bpfj/enforce/Pins.h"
#include "bpfj/lib/Heap.h"

namespace heap = bpfjailer::heap;

namespace {

struct Arena {
  std::vector<std::uint8_t> buf =
      std::vector<std::uint8_t>(BPFJ_HEAP_MAX_ARENA_SIZE);
  void* base{buf.data()};
  bpfj_heap_control* ctrl{reinterpret_cast<bpfj_heap_control*>(base)};

  Arena() {
    __builtin_memset(base, 0, BPFJ_HEAP_INIT_PAGES * BPFJ_HEAP_PAGE_SIZE);
    bpfj_heap_init_arena(base, BPFJ_HEAP_INIT_PAGES * BPFJ_HEAP_PAGE_SIZE);
    bpfjailer::lock::init(ctrl->lock);
  }
};

} // namespace

TEST(Heap, AllocFreeReturnsToZero) {
  Arena arena;

  const long first = heap::alloc(arena.base, 64);
  const long second = heap::alloc(arena.base, 128);
  ASSERT(first > 0);
  ASSERT(second > 0);
  ASSERT(first != second);
  ASSERT(arena.ctrl->current_used > 0);

  ASSERT_EQ(heap::free(arena.base, static_cast<__u32>(first)), 0);
  ASSERT_EQ(heap::free(arena.base, static_cast<__u32>(second)), 0);
  ASSERT_EQ(arena.ctrl->current_used, 0U);
}

TEST(Heap, ReusesAFreedBlock) {
  Arena arena;

  const long first = heap::alloc(arena.base, 64);
  ASSERT(first > 0);
  ASSERT_EQ(heap::free(arena.base, static_cast<__u32>(first)), 0);

  const long reused = heap::alloc(arena.base, 64);
  ASSERT_EQ(reused, first);
  ASSERT_EQ(heap::free(arena.base, static_cast<__u32>(reused)), 0);
  ASSERT_EQ(arena.ctrl->current_used, 0U);
}

TEST(Heap, UserspaceGrowMakesLaterAllocsSucceed) {
  Arena arena;

  const __u32 initSize = arena.ctrl->arena_size;
  std::vector<__u32> offsets;
  constexpr __u32 kChunk = 64 * 1024;

  for (int i = 0; i < 16; ++i) {
    const long off = heap::alloc(arena.base, kChunk);
    ASSERT(off > 0);
    offsets.push_back(static_cast<__u32>(off));
  }

  ASSERT(arena.ctrl->arena_size > initSize);

  for (const __u32 off : offsets) {
    ASSERT_EQ(heap::free(arena.base, off), 0);
  }
  ASSERT_EQ(arena.ctrl->current_used, 0U);
}

TEST(ArenaMap, IndependentPinTreesUseDifferentSlots) {
  const auto policy = bpfjailer::test::policyOf("roles:\n  svc:\n");
  const auto first = bpfjailer::test::testPins();
  ASSERT_OK(bpfjailer::Jailer::load(first, policy));

  auto second = first;
  second.pinDir += "-independent";
  ASSERT_OK(bpfjailer::Jailer::load(second, policy));

  auto firstMap = bpfjailer::pins::openPinnedMap(first, "bpfj_heap_arena");
  ASSERT(firstMap);
  auto secondMap = bpfjailer::pins::openPinnedMap(second, "bpfj_heap_arena");
  ASSERT(secondMap);

  auto firstExtra = bpfjailer::arena::pinnedMapExtra(*firstMap);
  ASSERT_OK(firstExtra);
  auto secondExtra = bpfjailer::arena::pinnedMapExtra(*secondMap);
  ASSERT_OK(secondExtra);
  ASSERT(*firstExtra != *secondExtra);
}
