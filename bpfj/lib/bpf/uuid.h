// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/lib/bpf/types_uuid.h"

static void bpfj_uuid_to_str(struct bpfj_uuid* uuid, char* str) {
  int i = 0;
  bpf_for(i, 0, BPFJ_UUID_BYTES) {
    BPF_SNPRINTF(str + i * 2, 3, "%02x", uuid->uuid[i]);
  }
}

static void bpfj_make_uuid4(struct bpfj_uuid* uuid) {
  u32* ptr = (u32*)uuid->uuid;
  for (int i = 0; i < 4; i++) {
    *ptr++ = bpf_get_prandom_u32();
  }

  // Set the version bits to 4
  uuid->uuid[6] = (uuid->uuid[6] & 0x0f) | 0x40;
  uuid->uuid[8] = (uuid->uuid[8] & 0x3f) | 0x80;
}
