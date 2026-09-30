// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <chrono>
#include <cstddef>
#include <functional>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}

#include "bpfj/libbpf-cpp/BpfMap.h"

namespace bpfj::libbpf {

namespace detail {

// Capacity is configured in fixed 4096-byte units rather than native pages, so
// a 64 KiB-page host gets the same buffer as an x86 one from the same setting.
// Returns the BPF_MAP_TYPE_RINGBUF max_entries value, rounded up to the
// native-page-aligned power of two the kernel requires.
[[nodiscard]] Expected<std::uint32_t> ringBufferByteSize(
    std::size_t configured4KPages,
    std::size_t nativePageBytes) noexcept;

} // namespace detail

class RingBuffer {
 public:
  using EventCallback = std::function<void(void*, std::size_t)>;

  RingBuffer(
      BpfMap map,
      std::size_t configured4KPages,
      EventCallback handleEvent) noexcept;

  ~RingBuffer() noexcept;

  RingBuffer(const RingBuffer&) = delete;
  RingBuffer& operator=(const RingBuffer&) = delete;

  RingBuffer(RingBuffer&& other) noexcept = delete;
  RingBuffer& operator=(RingBuffer&& other) noexcept = delete;

  // Call this function in the pre load phase
  Expected<> load() noexcept;

  // Call this function in the pre attach phase
  Expected<> attach() noexcept;

  // Call this function in the post detach phase
  void detach() noexcept;

  Expected<int> poll(std::chrono::milliseconds timeout) noexcept;

  Expected<int> consume() noexcept;

  int fd() noexcept;

 private:
  static int handleBpfEvent(void* ctx, void* data, std::size_t size) noexcept;

  BpfMap map_;
  std::size_t configured4KPages_{0};
  struct ring_buffer* ringBuffer_{nullptr};
  std::function<void(void*, std::size_t)> handleEvent_;
};

} // namespace bpfj::libbpf
