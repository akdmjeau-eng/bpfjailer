// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#define BPFJ_MOUNT_FS_TYPE_LEN 64

struct bpfj_mount_path_entry {
  __u32 rule_id;
  __u8 specificity;
  __u8 has_types;
};

struct bpfj_mount_type_key {
  __u32 rule_id;
  char type[BPFJ_MOUNT_FS_TYPE_LEN];
};
