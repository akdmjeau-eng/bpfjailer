// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/libbpf-cpp/RingBuffer.h"

#include "bpfj/lib/Log.h"

#include <algorithm>
#include <bit>

namespace bpfj::libbpf {

namespace detail {
namespace {
constexpr std::size_t kConfiguredPageBytes = 4096;
// Largest power of two representable in the uint32_t max_entries field.
constexpr std::size_t kMaxRingBufferBytes = std::size_t{1} << 31;
} // namespace

Expected<std::uint32_t> ringBufferByteSize(
    std::size_t configured4KPages,
    std::size_t nativePageBytes) noexcept {
  if (configured4KPages == 0 || nativePageBytes == 0 ||
      !std::has_single_bit(nativePageBytes)) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "Invalid ring buffer sizing: configured4KPages=",
        std::to_string(configured4KPages),
        ", nativePageBytes=",
        std::to_string(nativePageBytes)));
  }

  if (configured4KPages > kMaxRingBufferBytes / kConfiguredPageBytes) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "Ring buffer configured size is too large: ",
        std::to_string(configured4KPages),
        " * ",
        std::to_string(kConfiguredPageBytes),
        " bytes"));
  }

  // Never round below the requested capacity, and never below one native page
  // (the kernel rejects a ring buffer that is not native-page-aligned).
  const std::size_t requestedBytes =
      std::max(configured4KPages * kConfiguredPageBytes, nativePageBytes);
  if (requestedBytes > kMaxRingBufferBytes) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "Ring buffer size exceeds ",
        std::to_string(kMaxRingBufferBytes),
        " bytes: ",
        std::to_string(requestedBytes)));
  }

  // The kernel also requires a power-of-two size; rounding up preserves at
  // least the configured capacity.
  return static_cast<std::uint32_t>(std::bit_ceil(requestedBytes));
}

} // namespace detail

RingBuffer::RingBuffer(
    BpfMap map,
    std::size_t configured4KPages,
    EventCallback handleEvent) noexcept
    : map_(std::move(map)),
      configured4KPages_(configured4KPages),
      handleEvent_(std::move(handleEvent)) {}

RingBuffer::~RingBuffer() noexcept {
  detach();
}

// Call this function in the pre load phase
Expected<> RingBuffer::load() noexcept {
  const auto nativePageBytes = ::sysconf(_SC_PAGESIZE);
  if (nativePageBytes <= 0) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "Unable to determine native page size for ring buffer ",
        map_.name()));
  }

  auto byteSize = detail::ringBufferByteSize(
      configured4KPages_, static_cast<std::size_t>(nativePageBytes));
  if (!byteSize) {
    return makeUnexpected(byteSize.error());
  }

  BPFJ_LOG(INFO) << "Sizing ring buffer " << map_.name()
                 << ": configured4KPages=" << configured4KPages_
                 << ", nativePageBytes=" << nativePageBytes
                 << ", bytes=" << *byteSize;

  return map_.setMaxEntries(*byteSize);
}

// Call this function in the pre attach phase
Expected<> RingBuffer::attach() noexcept {
  ringBuffer_ = ring_buffer__new(
      map_.fd(), handleBpfEvent, static_cast<void*>(this), nullptr);
  if (!ringBuffer_) {
    return makeUnexpected(Error::fromErrno("Failed to create ring buffer"));
  }

  return unit;
}

// Call this function in the post detach phase
void RingBuffer::detach() noexcept {
  if (ringBuffer_) {
    ring_buffer__free(ringBuffer_);
    ringBuffer_ = nullptr;
  }
}

Expected<int> RingBuffer::poll(std::chrono::milliseconds timeout) noexcept {
  auto ret = ring_buffer__poll(ringBuffer_, static_cast<int>(timeout.count()));
  if (ret < 0) {
    return makeUnexpected(makeError(
        std::errc(-ret), "Failed to poll ring buffer: ", map_.name()));
  }

  return ret;
}

Expected<int> RingBuffer::consume() noexcept {
  auto ret = ring_buffer__consume(ringBuffer_);
  if (ret < 0) {
    return makeUnexpected(makeError(
        std::errc(-ret), "Failed to consume ring buffer: ", map_.name()));
  }

  return ret;
}

int RingBuffer::fd() noexcept {
  return ring_buffer__epoll_fd(ringBuffer_);
}

int RingBuffer::handleBpfEvent(
    void* ctx,
    void* data,
    std::size_t size) noexcept {
  if (!ctx || !data) {
    return 0;
  }
  auto buf = static_cast<RingBuffer*>(ctx);
  buf->handleEvent_(data, size);
  return 0;
}

} // namespace bpfj::libbpf
