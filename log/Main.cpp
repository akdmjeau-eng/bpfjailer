// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <argp.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
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

constexpr char kDoc[] =
    "bpfjlog -- print BPF log messages from the pinned bpfj_log_map ring buffer"
    "\vConsumes the shared logging_bpf ring buffer and writes each record to "
    "stderr until it is signalled to stop.";

void handleStopSignal(int /* signum */) {
  gRunning = 0;
}

int handleEvent(void* /* ctx */, void* data, std::size_t size) noexcept {
  try {
    auto line = bpfjailer::log::formatBpfLog(data, size);
    if (!line) {
      std::cerr << "bpfjlog: " << line.error() << std::endl;
      return 0;
    }

    std::cerr << *line << std::endl;
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
    std::cerr << "bpfjlog: failed to poll " << kLogMapName << ": "
              << err.message() << std::endl;
    return 1;
  }

  return 0;
}

bool installSignalHandlers() {
  return std::signal(SIGINT, handleStopSignal) != SIG_ERR &&
      std::signal(SIGTERM, handleStopSignal) != SIG_ERR;
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

  auto map = openPinnedMap(cfg, kLogMapName);
  if (!map) {
    std::cerr << "bpfjlog: " << map.error() << std::endl;
    return 1;
  }

  struct ring_buffer* ringBuffer =
      ::ring_buffer__new(map->get(), handleEvent, nullptr, nullptr);
  if (!ringBuffer) {
    std::cerr << "bpfjlog: failed to attach to " << kLogMapName << ": "
              << std::strerror(errno) << std::endl;
    return 1;
  }

  const int rc = pollLoop(ringBuffer);
  ::ring_buffer__free(ringBuffer);
  return rc;
}
