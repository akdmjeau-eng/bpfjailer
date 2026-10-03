// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "bpfj/lib/bpf/glob_map.h"
#include "tests/bpf/types_glob_map_test.h"

struct bpfj_glob_map __arena* bpfj_glob_test_map;
struct bpfj_glob_run __arena* bpfj_glob_test_run;
struct bpfj_glob_bindings __arena* bpfj_glob_test_bindings;

SEC("syscall")
int bpfj_glob_test(void* ctx) {
  struct bpfj_glob_test_req req = {};
  __builtin_memcpy(&req, ctx, sizeof(req));

  bpfj_heap_use_arena();
  if (bpfj_glob_test_run == NULL) {
    return -EINVAL;
  }

  void __arena* base = bpfj_heap_ctrl;
  __u32 input_off = bpfj_heap_clamp_off(req.input_off);
  const char __arena* input = (const char __arena*)base + input_off;
  bpfj_glob_run_bind(
      bpfj_glob_test_run, bpfj_glob_test_map, bpfj_glob_test_bindings);

  switch (req.op) {
    case BPFJ_GLOB_TEST_LOOKUP:
      return (int)bpfj_glob_map_lookup(bpfj_glob_test_run, input, req.len);
    case BPFJ_GLOB_TEST_CONTAINS:
      bpfj_glob_test_run->str = input;
      return (int)bpfj_glob_map_contains(
          bpfj_glob_test_run, req.len, req.wanted);
    case BPFJ_GLOB_TEST_CONTAINS_RANGE:
      bpfj_glob_test_run->str = input;
      return (int)bpfj_glob_map_contains_range(
          bpfj_glob_test_run, req.len, req.first, req.count);
    default:
      return -EINVAL;
  }
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
