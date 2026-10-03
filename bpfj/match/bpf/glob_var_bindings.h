// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/types_glob_map.h"
#include "bpfj/match/bpf/file_match_cached.h"
#include "bpfj/var/bpf/types_var.h"

_Static_assert(
    BPFJ_GLOB_MAP_MAX_VAR_LEN == BPFJ_VAR_VAL_LEN - 1,
    "a glob gadget must be exactly as wide as a string variable");
_Static_assert(
    BPFJ_VAR_MAX <= BPFJ_GLOB_MAP_MAX_BINDINGS,
    "every pod variable must fit in the glob bindings");

static __noinline void bpfj_glob_bindings_from_var_array(
    struct bpfj_glob_bindings __arena* out,
    const struct bpfj_var_array __arena* vars) {
  __u32 n = 0;
  if (vars != NULL && vars->vars != NULL) {
    __u32 count = vars->count;
    for (__u32 v = 0; v < BPFJ_VAR_MAX; ++v) {
      if (v >= count) {
        break;
      }
      struct bpfj_var __arena* var = vars->vars + v;
      if (var->type != BPFJ_VAR_TYPE_STR) {
        continue;
      }

      struct bpfj_glob_binding __arena* binding = &out->b[n];
      binding->key = var->id;
      binding->len = var->size;
      if (var->size > BPFJ_GLOB_MAP_MAX_VAR_LEN || var->val == NULL) {
        bpfj_heap_zero_arena(binding->val, BPFJ_GLOB_MAP_MAX_VAR_LEN);
      } else {
        char value[BPFJ_GLOB_MAP_MAX_VAR_LEN] = {};
        bpfj_heap_read_arena(value, BPFJ_GLOB_MAP_MAX_VAR_LEN, var->val);
        bpfj_heap_write_arena(binding->val, BPFJ_GLOB_MAP_MAX_VAR_LEN, value);
      }
      ++n;
    }
  }
  out->count = n;
}

BPFJ_FILE_MATCH_CACHED_DEFINE_BIND(
    bpfj_file_match_cached_bind_var_array,
    bpfj_glob_bindings_from_var_array,
    struct bpfj_var_array __arena)
