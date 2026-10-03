// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "ctl/Options.h"
#include "log/BpfLog.h"

const char* argp_program_version = "bpfjlog 0.1";

namespace {

using bpfjailer::PinConfig;
using bpfjailer::ctl::parsePinOnly;
using bpfjailer::pins::openPinnedMap;

volatile std::sig_atomic_t gRunning = 1;
constexpr std::string_view kLogMapName = "bpfj_log_map";
constexpr std::string_view kEventMapName = "bpfj_event_map";

constexpr char kDoc[] =
    "bpfjlog -- print BPF log and enforcer event ring buffers from bpffs"
    "\vConsumes the pinned bpfj_log_map and bpfj_event_map ring buffers. BPF "
    "log records go to stderr and structured enforcer events go to stdout "
    "until the process is signalled to stop.";

enum class RecordKind {
  BpfLog,
  Event,
};

struct CallbackContext {
  RecordKind kind;
  std::string_view mapName;
};

struct RingBuffers {
  bpfjailer::Fd logMap;
  bpfjailer::Fd eventMap;
  struct ring_buffer* consumer = nullptr;
  std::uint32_t logMapId = 0;
  std::uint32_t eventMapId = 0;

  RingBuffers(
      bpfjailer::Fd log,
      bpfjailer::Fd event,
      struct ring_buffer* ringBuffer,
      std::uint32_t logId,
      std::uint32_t eventId) noexcept
      : logMap(std::move(log)),
        eventMap(std::move(event)),
        consumer(ringBuffer),
        logMapId(logId),
        eventMapId(eventId) {}

  RingBuffers(const RingBuffers&) = delete;
  RingBuffers& operator=(const RingBuffers&) = delete;

  RingBuffers(RingBuffers&& other) noexcept
      : logMap(std::move(other.logMap)),
        eventMap(std::move(other.eventMap)),
        consumer(std::exchange(other.consumer, nullptr)),
        logMapId(other.logMapId),
        eventMapId(other.eventMapId) {}

  ~RingBuffers() {
    if (consumer != nullptr) {
      ::ring_buffer__free(consumer);
    }
  }
};

void handleStopSignal(int /* signum */) {
  gRunning = 0;
}

int handleEvent(void* ctx, void* data, std::size_t size) noexcept {
  try {
    const auto* callback = static_cast<const CallbackContext*>(ctx);
    if (callback == nullptr) {
      std::cerr << "bpfjlog: missing callback context" << std::endl;
      return 0;
    }

    const bool isEvent = callback->kind == RecordKind::Event;
    auto line = isEvent ? bpfjailer::log::formatBpfEvent(data, size)
                        : bpfjailer::log::formatBpfLog(data, size);
    if (!line) {
      std::cerr << "bpfjlog: " << callback->mapName << ": " << line.error()
                << std::endl;
      return 0;
    }

    if (isEvent) {
      std::cout << *line << std::endl;
    } else {
      std::cerr << *line << std::endl;
    }
  } catch (const std::exception& ex) {
    std::cerr << "bpfjlog: failed to format log message: " << ex.what()
              << std::endl;
  } catch (...) {
    std::cerr << "bpfjlog: failed to format log message" << std::endl;
    return 0;
  }
  return 0;
}

bool installSignalHandlers() {
  return std::signal(SIGINT, handleStopSignal) != SIG_ERR &&
      std::signal(SIGTERM, handleStopSignal) != SIG_ERR;
}

[[nodiscard]] bpfjailer::Expected<std::uint32_t> mapId(
    int fd,
    std::string_view name) {
  struct bpf_map_info info{};
  std::uint32_t size = sizeof(info);
  if (::bpf_obj_get_info_by_fd(fd, &info, &size) != 0) {
    return bpfjailer::makeUnexpected(
        bpfjailer::makeErrnoError("failed to inspect ", name));
  }
  return info.id;
}

[[nodiscard]] bpfjailer::Expected<> addMap(
    struct ring_buffer* ringBuffer,
    int fd,
    CallbackContext* ctx,
    std::string_view mapName) {
  if (::ring_buffer__add(ringBuffer, fd, handleEvent, ctx) == 0) {
    return bpfjailer::unit;
  }

  return bpfjailer::makeUnexpected(
      bpfjailer::makeErrnoError("failed to attach to ", mapName));
}

[[nodiscard]] bpfjailer::Expected<RingBuffers> openRingBuffers(
    const PinConfig& cfg,
    CallbackContext& logCtx,
    CallbackContext& eventCtx) {
  auto logMap = openPinnedMap(cfg, kLogMapName);
  if (!logMap) {
    return bpfjailer::makeUnexpected(logMap.error());
  }
  auto eventMap = openPinnedMap(cfg, kEventMapName);
  if (!eventMap) {
    return bpfjailer::makeUnexpected(eventMap.error());
  }
  auto logId = mapId(logMap->get(), kLogMapName);
  if (!logId) {
    return bpfjailer::makeUnexpected(logId.error());
  }
  auto eventId = mapId(eventMap->get(), kEventMapName);
  if (!eventId) {
    return bpfjailer::makeUnexpected(eventId.error());
  }

  struct ring_buffer* consumer =
      ::ring_buffer__new(logMap->get(), handleEvent, &logCtx, nullptr);
  if (consumer == nullptr) {
    return bpfjailer::makeUnexpected(
        bpfjailer::makeErrnoError("failed to attach to ", kLogMapName));
  }
  if (auto added = addMap(consumer, eventMap->get(), &eventCtx, kEventMapName);
      !added) {
    ::ring_buffer__free(consumer);
    return bpfjailer::makeUnexpected(added.error());
  }

  return RingBuffers{
      std::move(*logMap), std::move(*eventMap), consumer, *logId, *eventId};
}

[[nodiscard]] bool pinsChanged(
    const PinConfig& cfg,
    const RingBuffers& current) {
  auto logMap = openPinnedMap(cfg, kLogMapName);
  auto eventMap = openPinnedMap(cfg, kEventMapName);
  if (!logMap || !eventMap) {
    return false;
  }

  auto logId = mapId(logMap->get(), kLogMapName);
  auto eventId = mapId(eventMap->get(), kEventMapName);
  return logId && eventId &&
      (*logId != current.logMapId || *eventId != current.eventMapId);
}

void drainRingBuffers(struct ring_buffer* consumer) {
  while (gRunning != 0 && ::ring_buffer__poll(consumer, 0) > 0) {
  }
}

} // namespace

int main(int argc, char** argv) {
  PinConfig cfg;
  parsePinOnly(argc, argv, kDoc, cfg);

  if (!installSignalHandlers()) {
    std::cerr << "bpfjlog: failed to install signal handlers: "
              << std::strerror(errno) << std::endl;
    return 1;
  }

  CallbackContext logCtx{RecordKind::BpfLog, kLogMapName};
  CallbackContext eventCtx{RecordKind::Event, kEventMapName};
  bool connected = false;
  while (gRunning != 0) {
    auto buffers = openRingBuffers(cfg, logCtx, eventCtx);
    if (!buffers) {
      if (!connected) {
        std::cerr << "bpfjlog: " << buffers.error() << std::endl;
        return 1;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }
    connected = true;

    auto nextPinCheck =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    bool pollFailed = false;
    while (gRunning != 0) {
      const int ret = ::ring_buffer__poll(buffers->consumer, 250);
      if (ret < 0 && ret != -EINTR) {
        std::cerr << "bpfjlog: ring buffer poll failed: " << std::strerror(-ret)
                  << std::endl;
        pollFailed = true;
        break;
      }
      const auto now = std::chrono::steady_clock::now();
      if (now >= nextPinCheck) {
        nextPinCheck = now + std::chrono::milliseconds(250);
        if (pinsChanged(cfg, *buffers)) {
          drainRingBuffers(buffers->consumer);
          break;
        }
      }
    }
    if (pollFailed) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  return 0;
}
