// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <argp.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>

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

int pollLoop(struct ring_buffer* ringBuffer) {
  while (gRunning != 0) {
    const int ret = ::ring_buffer__poll(ringBuffer, 1000);
    if (ret >= 0) {
      continue;
    }

    if (ret == -EINTR) {
      continue;
    }

    const auto err = std::error_code(-ret, std::generic_category());
    std::cerr << "bpfjlog: failed to poll ring buffers: " << err.message()
              << std::endl;
    return 1;
  }

  return 0;
}

bool installSignalHandlers() {
  return std::signal(SIGINT, handleStopSignal) != SIG_ERR &&
      std::signal(SIGTERM, handleStopSignal) != SIG_ERR;
}

bool addMap(
    struct ring_buffer* ringBuffer,
    int fd,
    CallbackContext* ctx,
    std::string_view mapName) {
  if (::ring_buffer__add(ringBuffer, fd, handleEvent, ctx) == 0) {
    return true;
  }

  std::cerr << "bpfjlog: failed to attach to " << mapName << ": "
            << std::strerror(errno) << std::endl;
  return false;
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

  auto logMap = openPinnedMap(cfg, kLogMapName);
  if (!logMap) {
    std::cerr << "bpfjlog: " << logMap.error() << std::endl;
    return 1;
  }

  auto eventMap = openPinnedMap(cfg, kEventMapName);
  if (!eventMap) {
    std::cerr << "bpfjlog: " << eventMap.error() << std::endl;
    return 1;
  }

  CallbackContext logCtx{RecordKind::BpfLog, kLogMapName};
  CallbackContext eventCtx{RecordKind::Event, kEventMapName};

  struct ring_buffer* ringBuffer =
      ::ring_buffer__new(logMap->get(), handleEvent, &logCtx, nullptr);
  if (!ringBuffer) {
    std::cerr << "bpfjlog: failed to attach to " << kLogMapName << ": "
              << std::strerror(errno) << std::endl;
    return 1;
  }

  if (!addMap(ringBuffer, eventMap->get(), &eventCtx, kEventMapName)) {
    ::ring_buffer__free(ringBuffer);
    return 1;
  }

  const int rc = pollLoop(ringBuffer);
  ::ring_buffer__free(ringBuffer);
  return rc;
}
