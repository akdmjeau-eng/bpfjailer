// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#include "bpfj/lib/bpf/types_dyn_lru.h"
#include "bpfj/lib/bpf/types_glob_map.h"
#include "bpfj/lib/bpf/types_perf_map.h"
#include "bpfj/lib/bpf/types_str_map.h"
#include "bpfj/match/bpf/types_file_match.h"

// Capped by the dyn LRU rather than by the old LRU_HASH's 8192:
// BPFJ_DYN_LRU_MAX_CAPACITY bounds the destroy loop for the verifier and the
// index's arena footprint, and init rejects anything above it.
#define BPFJ_FILE_MATCH_CACHED_CACHE_SIZE BPFJ_DYN_LRU_MAX_CAPACITY

// How many pods one file's cache entry holds before it is wiped and started
// over.
//
// A file every pod on the host opens gets an entry per pod uuid, and until this
// cap nothing retired them short of the mount or rename view moving: uuids
// never repeat, pods come and go, and the outer LRU's clock hand protects
// exactly the hot files whose entries grow. This is the backstop, not a tuning
// knob -- 128 pods on one file is already far past anything a host should be
// doing, and the cost of hitting it is that the next open of that file walks
// again, which is what a miss costs anyway.
#define BPFJ_FILE_MATCH_CACHED_DEFAULT_MAX_CACHE_PODS 128

struct bpfj_file_matcher {
  // Maps a path component (a single dentry name) to the set of pattern nodes it
  // matches. A single bit-parallel glob NFA replaces the former literal
  // names_map, the per-node globs_perf_map, and the var_id_to_node_perf_map:
  // every distinct component pattern (literal, '*'/'?' wildcard, or ${VAR}
  // variable, bare or with a trailing pattern) is one glob pattern whose value
  // is the packed bpfj_file_match_indexes for that component. The compiled
  // header lives on the arena (userspace's GlobMap owns it), so this is just a
  // pointer to it.
  struct bpfj_glob_map __arena* glob_map;
  // Both headers live on the arena too (userspace's PerfMap owns them), so
  // these are just pointers. NULL when the policy has no such nodes at all.
  struct bpfj_perf_map __arena* nodes_perf_map;
  struct bpfj_perf_map __arena* initializer_perf_map;
  // Per path_id data: data_entry_count entries of data_entry_size bytes each,
  // flat, in one block. This used to be an array of str_maps keyed by role id,
  // because one matcher served every role and the same path could carry a
  // different entry per role. A matcher belongs to one role now, so a path has
  // exactly one entry and the path_id is the index -- no probe, no key, and no
  // per-entry allocation.
  void __arena* data_vec;
  struct bpfj_dyn_lru __arena* lru;
  // Bytes per entry, and how many of them data_vec holds. The size is whatever
  // the owning userspace matcher's value type is; BPF only ever hands the entry
  // back to a caller that knows what it is.
  __u32 data_entry_size;
  __u32 data_entry_count;
  struct bpfj_file_match_cached_pattern_str __arena*
      pattern_strs; // arena ptr to pattern_str[]
  __u32 num_pattern_strs;
  // How many pods one file's cache entry may hold before it is wiped and
  // started over. See BPFJ_FILE_MATCH_CACHED_DEFAULT_MAX_CACHE_PODS. Zero means
  // the default: the matcher block is value-initialized, so a matcher built by
  // something that does not know about this field still gets the cap.
  __u32 max_cache_pods;
  // Non-zero when at least one of this role's paths asks for a signature.
  //
  // bpfj_fs2_file_post_open_sig works out what to verify from the cache entry
  // the path match left behind, and a cache miss leaves it with no answer. For
  // a role that signs nothing that is fine -- there was nothing to check. For a
  // role that does, it is the difference between checking a signature and
  // silently not, so the miss has to deny, and this is how that half knows
  // which case it is in without a match of its own.
  __u32 has_signed_paths;
};
