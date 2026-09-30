// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/lib/bpf/logging.h"

// Logging macros and ringbuffer map definition, shared by the enforce and match
// modules.

volatile bool bpfj_dbg_mode = 0;
volatile bool bpfj_verbose_mode = 0;

// Internal implementation macro - takes file, line, severity as parameters
#define BPFJ_LOG_IMPL(CODE, FILE, LINE, SEV, FMT, ...)                        \
  {                                                                           \
    struct bpfj_log* ev = bpf_ringbuf_reserve(&bpfj_log_map, sizeof(*ev), 0); \
    if (ev) {                                                                 \
      ev->code = CODE;                                                        \
      ev->line = LINE;                                                        \
      ev->severity = SEV;                                                     \
      ev->cpu = bpf_get_smp_processor_id();                                   \
      BPF_SNPRINTF(ev->msg, sizeof(ev->msg), FMT, __VA_ARGS__);               \
      bpf_probe_read_str(ev->file, sizeof(ev->file), FILE);                   \
      bpf_ringbuf_submit(ev, 0);                                              \
    }                                                                         \
  }

// __FILE_NAME__ captures only the basename at compile time, using less stack
// than __FILE__.

// Error log — routes to ErrorLogger/Scuba with error code
#define BPFJ_LOG_ERR(CODE, FMT, ...) \
  BPFJ_LOG_IMPL(                     \
      CODE, __FILE_NAME__, __LINE__, BPFJ_SEV_WARNING, FMT, __VA_ARGS__)

// Routes to ErrorLogger/Scuba at the given severity, with no error code:
//     BPFJ_LOG_EVENT(BPFJ_SEV_WARNING, "msg %d", val)
#define BPFJ_LOG_EVENT(SEV, FMT, ...) \
  BPFJ_LOG_IMPL(0, __FILE_NAME__, __LINE__, SEV, FMT, __VA_ARGS__)

// Emits an event only ~1/N of the time, through the per-CPU PRNG so there is
// no shared counter on hot hooks like file_open, and keeping the ring buffer
// ~Nx lighter since a dropped event never reserves a slot. For high-volume,
// low-signal events that would otherwise dominate bpfjailer_errors, and N <= 1
// always emits, which also avoids the modulo by zero.
//
// Multiply a sampled line's Scuba count by N to estimate true volume.
//     BPFJ_LOG_EVENT_SAMPLED(100, BPFJ_SEV_WARNING, "msg %d", val)
#define BPFJ_LOG_EVENT_SAMPLED(N, SEV, FMT, ...)          \
  do {                                                    \
    if ((N) <= 1 || (bpf_get_prandom_u32() % (N)) == 0) { \
      BPFJ_LOG_EVENT(SEV, FMT, __VA_ARGS__);              \
    }                                                     \
  } while (0)

// Regular log — local XLOG(INFO) only, no Scribe/Scuba
#define BPFJ_LOG(FMT, ...) \
  BPFJ_LOG_IMPL(0, __FILE_NAME__, __LINE__, BPFJ_SEV_NONE, FMT, __VA_ARGS__)

#define BPFJ_DBG_LOG(FMT, ...)                                                 \
  if (bpfj_dbg_mode) {                                                         \
    BPFJ_LOG_IMPL(0, __FILE_NAME__, __LINE__, BPFJ_SEV_NONE, FMT, __VA_ARGS__) \
  }

#define BPFJ_VERBOSE_LOG(FMT, ...)                                             \
  if (bpfj_verbose_mode) {                                                     \
    BPFJ_LOG_IMPL(0, __FILE_NAME__, __LINE__, BPFJ_SEV_NONE, FMT, __VA_ARGS__) \
  }

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1);
} bpfj_log_map SEC(".maps");
