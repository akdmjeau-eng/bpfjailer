// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstddef>
#include <string>

#include "bpfj/err/Error.h"

struct bpfj_log;
struct bpfj_event;

namespace bpfjailer::log {

[[nodiscard]] std::string severityName(int severity);
[[nodiscard]] std::string eventTypeName(int type);

[[nodiscard]] std::string formatBpfLog(const struct bpfj_log& entry);
[[nodiscard]] std::string formatBpfEvent(const struct bpfj_event& entry);

[[nodiscard]] Expected<std::string> formatBpfLog(
    const void* data,
    std::size_t size);

[[nodiscard]] Expected<std::string> formatBpfEvent(
    const void* data,
    std::size_t size);

} // namespace bpfjailer::log
