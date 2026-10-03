// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#define BPFJ_FS_MODE_READ 0x1U
#define BPFJ_FS_MODE_WRITE 0x2U
#define BPFJ_FS_MODE_EXEC 0x20U

struct bpfj_fs_path_entry {
  __u32 mode;
};
