// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

enum bpfj_unix_operation {
  BPFJ_UNIX_BIND = 0,
  BPFJ_UNIX_CONNECT = 1,
  BPFJ_UNIX_DGRAM = 2,
  BPFJ_UNIX_OPERATION_COUNT = 3,
};

struct bpfj_unix_path_entry {
  // -1 means this path says nothing about the operation.
  __s8 allowed[BPFJ_UNIX_OPERATION_COUNT];
  __u8 specificity;
};
