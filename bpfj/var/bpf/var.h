// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/var/bpf/types_var.h"

// This map just exists to be able to get variable names in bpf if needed
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, BPFJ_VAR_MAP_SIZE);
  __type(key, __u32);
  __type(value, struct bpfj_var_name);
} bpfj_var_map SEC(".maps");

static const char* bpfj_var_get_name(struct bpfj_var* var) {
  struct bpfj_var_name* name = bpf_map_lookup_elem(&bpfj_var_map, &var->id);
  if (!name) {
    return NULL;
  }

  return name->name;
}
