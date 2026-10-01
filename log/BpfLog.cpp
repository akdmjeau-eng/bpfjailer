// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "log/BpfLog.h"

#include <algorithm>
#include <string_view>

#include "bpfj/lib/bpf/logging.h"

namespace bpfjailer::log {

namespace {

[[nodiscard]] std::string_view boundedString(
    const char* buf,
    std::size_t size) noexcept {
  const char* end = std::find(buf, buf + size, '\0');
  return std::string_view(buf, static_cast<std::size_t>(end - buf));
}

} // namespace

std::string severityName(int severity) {
  switch (severity) {
    case BPFJ_SEV_NONE:
      return "none";
    case BPFJ_SEV_FATAL:
      return "fatal";
    case BPFJ_SEV_WARNING:
      return "warning";
    case BPFJ_SEV_INFO:
      return "info";
    default:
      return "unknown(" + std::to_string(severity) + ")";
  }
}

std::string formatBpfLog(const struct bpfj_log& entry) {
  const auto file = boundedString(entry.file, sizeof(entry.file));
  const auto msg = boundedString(entry.msg, sizeof(entry.msg));

  std::string line = "BPF Message: ";
  line += file;
  line += ":";
  line += std::to_string(entry.line);
  line += ": sev=";
  line += severityName(entry.severity);
  line += " code=";
  line += std::to_string(entry.code);
  line += " cpu=";
  line += std::to_string(entry.cpu);
  line += ": ";
  line += msg;
  return line;
}

Expected<std::string> formatBpfLog(const void* data, std::size_t size) {
  if (data == nullptr) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "bpf log record was null"));
  }

  if (size < sizeof(struct bpfj_log)) {
    return makeUnexpected(makeError(
        std::errc::argument_out_of_domain,
        "bpf log record was ",
        std::to_string(size),
        " bytes, expected at least ",
        std::to_string(sizeof(struct bpfj_log))));
  }

  return formatBpfLog(*static_cast<const struct bpfj_log*>(data));
}

} // namespace bpfjailer::log
