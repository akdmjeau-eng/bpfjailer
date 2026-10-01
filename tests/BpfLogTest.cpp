// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <cstring>
#include <string>

#include "bpfj/lib/bpf/logging.h"
#include "log/BpfLog.h"

namespace {

void copyString(char* dst, std::size_t size, const char* src) {
  std::strncpy(dst, src, size);
  dst[size - 1] = '\0';
}

} // namespace

TEST(BpfLog, FormatsStructuredRecords) {
  struct bpfj_log entry{};
  copyString(entry.file, sizeof(entry.file), "heap.h");
  copyString(entry.msg, sizeof(entry.msg), "arena lock timed out");
  entry.line = 47;
  entry.severity = BPFJ_SEV_WARNING;
  entry.code = 16;
  entry.cpu = 3;

  const std::string expected =
      "BPF Message: heap.h:47: sev=warning code=16 cpu=3: arena lock timed out";
  ASSERT_EQ(bpfjailer::log::formatBpfLog(entry), expected);
}

TEST(BpfLog, RejectsShortRecords) {
  char truncated[8]{};
  auto formatted = bpfjailer::log::formatBpfLog(truncated, sizeof(truncated));

  ASSERT(!formatted);
  ASSERT(
      formatted.error().message().find("expected at least") !=
      std::string::npos);
}
