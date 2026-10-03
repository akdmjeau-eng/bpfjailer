// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/lib/bpf/types_heap.h"

#define BPFJ_MOUNT_FS_TYPE_LEN 64

struct bpfj_str_map;

struct bpfj_mount_path_entry {
  const struct bpfj_str_map __arena* types;
  __u8 specificity;
};
