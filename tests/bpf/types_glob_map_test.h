// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

enum bpfj_glob_test_op {
  BPFJ_GLOB_TEST_LOOKUP = 1,
  BPFJ_GLOB_TEST_CONTAINS = 2,
  BPFJ_GLOB_TEST_CONTAINS_RANGE = 3,
};

struct bpfj_glob_test_req {
  __u64 wanted;
  __u32 op;
  __u32 input_off;
  __u32 len;
  __u32 first;
  __u32 count;
  __u32 reserved;
};
