// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#include <sys/types.h>
#endif

#define BPFJ_FILE_NAME_LEN (512 - sizeof(size_t))
#define BPFJ_FILE_MAX_RECURSION 256
#define BPFJ_FILE_MAX_ALT_PATHS 8

// Note that The entire path is 504 bytes bound today, and this manages a single
// component length
#define BPFJ_FILE_DIR_LEN 384

struct __attribute__((packed)) bpfj_file_path_str {
  size_t len;
  char str[BPFJ_FILE_NAME_LEN];
};
