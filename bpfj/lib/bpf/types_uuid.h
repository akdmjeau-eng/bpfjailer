// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#define POD_UUID_LEN 37
#define BPFJ_UUID_BYTES 16
#define BPFJ_MAX_POD_PER_PID 4

struct bpfj_uuid {
  unsigned char uuid[BPFJ_UUID_BYTES];
};

#define BPFJ_IP_PREFIX_LEN_IPV4 64
#define BPFJ_IP_PREFIX_LEN_IPV6 160
struct __attribute__((packed)) bpfj_ip_prefix {
  __u32 prefixlen;
  __s32 family;
  __u32 ip[4];
};
