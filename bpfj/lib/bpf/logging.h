// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// Constants for logging
#define BPFJ_LOG_LEN 128

#define BPFJ_LOG_FILE_LEN 64

// Severity levels for BPF log messages, mirroring bpfjailer::ErrorSeverity in
// ErrorLogger.h.
#define BPFJ_SEV_NONE (-1) // Regular log message (no Scribe/Scuba)
#define BPFJ_SEV_FATAL 0
#define BPFJ_SEV_WARNING 1
#define BPFJ_SEV_INFO 2

// Log structure definition
struct bpfj_log {
  char msg[BPFJ_LOG_LEN];
  char file[BPFJ_LOG_FILE_LEN];
  int code; // 0 indicates no error, just log message
  int line;
  int severity; // BPFJ_SEV_* — controls routing to ErrorLogger/Scuba
  __u32 cpu;
};
