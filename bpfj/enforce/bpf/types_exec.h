// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#define BPFJ_EXEC_ALLOW_EXEC (1U << 0)
#define BPFJ_EXEC_ALLOW_SETUID (1U << 1)
#define BPFJ_EXEC_ALLOW_SHARED_OBJECT (1U << 2)

struct bpfj_exec_path_entry {
  __u32 flags;
};
