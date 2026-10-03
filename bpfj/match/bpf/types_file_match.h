#pragma once

#include "bpfj/lib/bpf/types_str_map.h"
#include "bpfj/lib/bpf/types_uuid.h"
#include "bpfj/match/bpf/types_file.h"

#define BPFJ_FILE_MATCH_NAME_LEN 256
#define BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN 1024
#define BPFJ_FILE_MATCH_MAX_ITERS 64
#define BPFJ_FILE_MATCH_MAX_INITIALIZER_NODES 64

// Ceiling on a str_map lookup key that is a role id -- today the enforcer's
// role-to-matcher table. Power of two: the str_map scan masks its index
// against it.
//
// Deliberately far below BPFJ_STR_MAP_MAX_STR_LEN, because the key is staged
// into a buffer this size in the frame that does the lookup, and the enforcer
// has very little stack to spare. A role id is bounded by ROLE_ID_LEN, which
// is asserted against this where the staging happens.
#define BPFJ_FILE_MATCH_ROLE_KEY_LEN 64

struct __attribute__((packed)) bpfj_file_match_name {
  char name[BPFJ_FILE_MATCH_NAME_LEN];
};

struct __attribute__((packed)) bpfj_file_match_node {
  __s32 path_id;
  __s32 pos;
};

struct __attribute__((packed)) bpfj_file_match_indexes {
  __s32 nodes_id;
  __s32 initializer_nodes_id;
};

struct bpfj_file_match_cached_pattern_str {
  char pattern[BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN];
};

struct bpfj_file_match_cached_key {
  __u64 ino;
  __u64 subvol;
  struct bpfj_uuid uuid;
  __u64 rename_counter;
  __u32 dev;
  __u32 mount_lock;
};

struct bpfj_file_match_cached_locks {
  union {
    struct {
      __u32 rename_counter;
      __u32 mount_lock;
    };
    __u64 key;
  };
};
