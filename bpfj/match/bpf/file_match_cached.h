#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/dyn_lru.h"
#include "bpfj/lib/bpf/glob_map.h"
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/lib/bpf/perf_map.h"
#include "bpfj/lib/bpf/str_map.h"
#include "bpfj/lib/bpf/vec.h"
#include "bpfj/match/bpf/mount.h"
#include "bpfj/match/bpf/types_file_match.h"
#include "bpfj/match/bpf/types_file_match_cached.h"

#define BPFJ_FILE_MATCH_CACHED_MAX_RECURSION 2048
#define BPFJ_FILE_MATCH_CACHED_BUF_SIZE 4096
#define BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES 64
#define BPFJ_FILE_MATCH_CACHED_MAX_DIR_DESCENDANTS 128

#define BPFJ_FILE_MATCH_CACHED_MAX_RETRIES 32
#define BPFJ_FILE_MATCH_CACHED_MAX_CHILD_DENTRIES 8

// Linux packs a dentry name's hash and length into qstr::hash_len. Keep this
// header self-contained rather than depending on the closed file walker for
// its stringhash.h compatibility macro.
static __always_inline u32 bpfj_file_hashlen_len(u64 hashlen) {
  return (u32)(hashlen >> 32);
}

#define BTRFS_I(_inode)                                                   \
  _Generic(                                                               \
      _inode,                                                             \
      struct inode*: container_of(_inode, struct btrfs_inode, vfs_inode), \
      const struct inode*: (const struct btrfs_inode*)container_of(       \
          _inode, const struct btrfs_inode, vfs_inode))

#define BTRFS_FIRST_FREE_OBJECTID 256ULL

extern const void rename_lock __ksym;
extern const void btrfs_file_inode_operations __ksym;
extern const void btrfs_dir_inode_operations __ksym;

volatile __u64 bpfj_file_match_cached_cache_hit_counter;
volatile __u64 bpfj_file_match_cached_cache_miss_counter;
// Times a file's cache entry was wiped for holding max_cache_pods pods. A
// backstop firing is worth seeing, so it is a counter and not just a log line.
volatile __u64 bpfj_file_match_cached_cache_pod_cap_counter;

// Public API

// Declares the scope-guarded run state as `_name`, NULL if it could not be
// allocated. Unparenthesized: the guard pastes _name##_heap_guard for the
// owning handle.
//
// Its own guard rather than BPFJ_HEAP_ALLOC_GUARD's, because the state owns two
// vecs now: the plain guard frees the struct, which would strand their buffers.
#define BPFJ_FILE_MATCH_CACHED_ALLOC(_name)                                   \
  __attribute__((cleanup(                                                     \
      bpfj_file_match_cached_state_free))) void __arena* _name##_heap_guard = \
      bpfj_file_match_cached_state_alloc();                                   \
  struct bpfj_file_match_cached_state __arena* _name = _name##_heap_guard

#define _BPFJ_FILE_MATCH_CACHED(                                  \
    _name, _matcher, _mount_cache, _dentry, _uuid, _bind, _vars)  \
  ({                                                              \
    long _out = -ENOMEM;                                          \
    if (_name) {                                                  \
      _bind(_name, _matcher, (uintptr_t)(_dentry), _uuid, _vars); \
      _out = file_match_cached(_matcher, _name, _mount_cache);    \
    }                                                             \
    _out;                                                         \
  })

// Run a cached match against the run state _name, evaluating to the match
// count (or a negative errno).
//
// _name is declared by BPFJ_FILE_MATCH_CACHED_ALLOC, which scope-guards the
// arena allocation: it is freed when that scope ends. The accessors below take
// it explicitly, so they can be used from any function the pointer reaches --
// they no longer have to share a scope with the match itself.
//
// _uuid: pointer to a single struct bpfj_uuid identifying the var bindings.
// _bind: a bind function declared by BPFJ_FILE_MATCH_CACHED_DEFINE_BIND for
//        the caller's var type, which fills in the ${NAME} bindings from
//        _vars.
// _vars: the caller's variables, handed to _bind as is.
#define BPFJ_FILE_MATCH_CACHED(                                  \
    _name, _matcher, _mount_cache, _dentry, _uuid, _bind, _vars) \
  _BPFJ_FILE_MATCH_CACHED(                                       \
      _name, _matcher, _mount_cache, _dentry, _uuid, _bind, _vars)

#define BPFJ_FILE_MATCH_CACHED_GET_POS(_name, _index) \
  ({ bpfj_file_match_cached_pos(_name, _index); })

// The data entry the match at _match_idx landed on, or NULL if the matcher
// carries none for it.
#define BPFJ_FILE_MATCH_CACHED_LOOKUP(_name, _match_idx) \
  ({ bpfj_file_match_cached_lookup(_name, _match_idx); })

// Bounded by the arena scratch, not by sizeof(_buf): the walked path is
// assembled into a pattern_str, so a larger destination would read past it.
#define BPFJ_FILE_MATCH_CACHED_PRINT(_name, _buf)                           \
  ({                                                                        \
    BPFJ_HEAP_ALLOC_GUARD(struct bpfj_file_match_cached_pattern_str, _str); \
    long _ret = -ENOMEM;                                                    \
    if (_str) {                                                             \
      _ret = bpfj_file_match_cached_get_walked_path(_name, _str);           \
      if (_ret == 0) {                                                      \
        bpfj_heap_read_arena(                                               \
            _buf,                                                           \
            sizeof(_buf) < BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN           \
                ? sizeof(_buf)                                              \
                : BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN,                   \
            _str->pattern);                                                 \
      }                                                                     \
    }                                                                       \
    _ret;                                                                   \
  })

// Defines `_name(const struct role_id*)`, returning the matcher that `_map`
// registers for that role, or NULL if it registers none -- which is also the
// "this role has no policy here" answer an enforcer wants.
//
// A macro that defines a function, rather than a function taking the table,
// for two reasons. The table is a per-object global. And the staging buffer
// has to be sized by a compile-time constant: the str map compares the search
// key as ordinary memory of a size the verifier can pin down, which a role id
// sitting in a map value is not, so the id is copied into a local first.
// Expanding at the call site also means `struct role_id` and ROLE_ID_LEN
// resolve there, and this header does not have to reach into the enforcers'
// types for them.
//
// static __noinline, so the staging buffer gets a frame of its own rather than
// the hook's; static rather than global, so the arena pointer it returns keeps
// its provenance in the caller.
#define BPFJ_FILE_MATCH_CACHED_DEFINE_MATCHER_FOR(_name, _map)         \
  static __noinline struct bpfj_file_matcher __arena* _name(           \
      const struct role_id* role) {                                    \
    _Static_assert(                                                    \
        ROLE_ID_LEN <= BPFJ_FILE_MATCH_ROLE_KEY_LEN,                   \
        "a role id must fit in the staged lookup key");                \
                                                                       \
    char _key[BPFJ_FILE_MATCH_ROLE_KEY_LEN] = {};                      \
    u32 _i;                                                            \
    bpf_for(_i, 0, ROLE_ID_LEN) {                                      \
      _key[_i & (BPFJ_FILE_MATCH_ROLE_KEY_LEN - 1)] =                  \
          role->id[_i & (ROLE_ID_LEN - 1)];                            \
    }                                                                  \
    /* The scan is bounded by the whole buffer, so make sure it finds  \
     * a terminator even if the role id filled its own. */             \
    _key[BPFJ_FILE_MATCH_ROLE_KEY_LEN - 1] = '\0';                     \
                                                                       \
    void __arena* _out = NULL;                                         \
    if (bpfj_str_map_lookup_strlen(                                    \
            (_map), _key, BPFJ_FILE_MATCH_ROLE_KEY_LEN, &_out) != 0) { \
      return NULL;                                                     \
    }                                                                  \
                                                                       \
    return _out;                                                       \
  }

// Takes the cache rather than a matcher: the cache is shared by every matcher
// built against a policy, and a rename retires an entry for all of them at
// once. There is no one matcher to ask.
#define BPFJ_FILE_MATCH_CACHED_INVALIDATE_ON_RENAME(_lru, _dentry) \
  ({ bpfj_file_match_cached_check_invalidate_cache_on_rename(_lru, _dentry); })

// IMPLEMENTATION

// Iterator for traversing the graph.
struct bpfj_file_match_cached_iter {
  struct bpfj_file_match_node node;
  bool is_being_dropped;
  bool was_matched_this_cycle;
};

struct bpfj_file_match_cached_lock {
  __u32 mount_lock;
  __u32 rename_lock;
};

struct bpfj_file_match_cached_state {
  // Current matching state, of struct bpfj_file_match_cached_iter. A vec and
  // not iters[BPFJ_FILE_MATCH_MAX_ITERS]: that array was 640 of this struct's
  // ~1336 bytes and a typical match fills a handful of it. The cap survives as
  // the bound on every loop that walks this, and as a ceiling on what a push
  // will add -- it is no longer what the state costs.
  struct bpfj_vec iters;

  // The dentries walked, leaf first, of uintptr_t. Only read to reconstruct the
  // matched path for an event; another 512 bytes as a fixed array.
  struct bpfj_vec saved_dentries;

  // The ${NAME} bindings this match's globs resolve against
  struct bpfj_glob_bindings bindings;

  // The UUID of the pod for caching
  struct bpfj_uuid uuid;

  // The dentry being matched
  struct dentry* leaf;

  // The canonical mount selected from the target namespace. It starts empty:
  // the hook's mount belongs to the caller's namespace and bind aliases must
  // not decide which policy path is matched.
  uintptr_t mount;

  // The matcher
  struct bpfj_file_matcher __arena* matcher;

  // Namespace whose root bounds the walk. The descriptor is owned by this
  // invocation rather than task storage because these hooks are not sleepable.
  struct bpfj_mount_descriptor mount_descriptor;
  struct bpfj_shared_ptr mount_snapshot;
  struct bpfj_mount_fallback mount_fallback;

  // Scratch for the component NFA, owned by the walk to avoid another
  // allocation on the verifier's deepest path.
  struct bpfj_glob_run glob_run;
};

// The iters' sizes are the counts now, so there is no separate count to keep in
// step with them.
static __always_inline __u32 bpfj_file_match_cached_count(
    struct bpfj_file_match_cached_state __arena* state) {
  return bpfj_vec_size(&state->iters);
}

static __always_inline struct bpfj_file_match_cached_iter __arena*
bpfj_file_match_cached_iter_at(
    struct bpfj_file_match_cached_state __arena* state,
    __u32 index) {
  return bpfj_vec_at(&state->iters, index);
}

// Whether this matcher caches its matches at all.
//
// A matcher whose lru is NULL is walked every time. That is not a degenerate
// state -- it is how an enforcer opts out. A cache is not free: it holds
// entries, and it needs a rename hook to retire them, which runs on every
// rename on the host whether or not this enforcer's paths were involved. For
// hooks rare enough that the walk is cheaper than that, not caching is the
// right answer, and then there is nothing to invalidate either.
static __always_inline bool bpfj_file_match_cached_caches(
    struct bpfj_file_match_cached_state __arena* state) {
  return state->matcher != NULL && state->matcher->lru != NULL;
}

// The position the iter at `index` reached, or -1 if there is no such iter.
static __always_inline s32 bpfj_file_match_cached_pos(
    struct bpfj_file_match_cached_state __arena* state,
    __u32 index) {
  if (state == NULL) {
    return -1;
  }

  struct bpfj_file_match_cached_iter __arena* iter =
      bpfj_file_match_cached_iter_at(state, index);
  return iter != NULL ? iter->node.pos : -1;
}

// What the cache holds for one (file, pod): the counts, then the iters, then
// the dentries, in a single block sized to what the walk actually produced.
//
// One block and not a copy of the run state, which is what it used to be. Two
// reasons. A run state carries vecs now, and dyn_map releases a value as an
// opaque refcounted block -- bpfj_shared_ptr_release_arena, no destructor hook,
// on a chain already at the eight-frame limit -- so anything the value pointed
// at elsewhere would leak on eviction. And a state is ~216 bytes before its
// buffers, where a typical match needs the counts plus three iters and a dozen
// dentries: well under two hundred, against the 1336 a cache entry used to
// cost. The map's val_size is recorded at init and never read again, so entries
// of differing sizes are already fine.
//
// The dentries come before the iters because they need eight-byte alignment and
// an iter is ten bytes: putting the odd-sized array last keeps both aligned,
// and the heap rounds a payload up to whole words, so the copy that rounds up
// with it lands exactly at the end of the block.
struct bpfj_file_match_cached_entry {
  __u32 iter_count;
  __u32 dentry_count;
};

static __always_inline __u32
bpfj_file_match_cached_entry_size(__u32 iter_count, __u32 dentry_count) {
  return (__u32)sizeof(struct bpfj_file_match_cached_entry) +
      dentry_count * (__u32)sizeof(uintptr_t) +
      iter_count * (__u32)sizeof(struct bpfj_file_match_cached_iter);
}

static __always_inline uintptr_t __arena* bpfj_file_match_cached_entry_dentries(
    struct bpfj_file_match_cached_entry __arena* entry) {
  return (uintptr_t __arena*)(entry + 1);
}

static __always_inline struct bpfj_file_match_cached_iter __arena*
bpfj_file_match_cached_entry_iters(
    struct bpfj_file_match_cached_entry __arena* entry) {
  return (
      struct
      bpfj_file_match_cached_iter __arena*)(bpfj_file_match_cached_entry_dentries(
                                                entry) +
                                            entry->dentry_count);
}

// The pod cap this matcher was built with. Zero means the field was never set,
// which is the case for a matcher built by something older than it: fall back
// to the default rather than reading that as "no cap".
static __always_inline __u32
bpfj_file_match_cached_max_pods(struct bpfj_file_matcher __arena* matcher) {
  if (matcher == NULL) {
    return BPFJ_FILE_MATCH_CACHED_DEFAULT_MAX_CACHE_PODS;
  }

  __u32 max_pods = matcher->max_cache_pods;
  return max_pods != 0 ? max_pods
                       : BPFJ_FILE_MATCH_CACHED_DEFAULT_MAX_CACHE_PODS;
}

// Allocate a run state with both its vecs init'd. __noinline so the allocation
// and the two inits sit in a frame of their own: every hook opens with this,
// and a hook's frame is the first one on the chain through file_match_cached
// that is at the verifier's combined-stack limit.
static __noinline void __arena* bpfj_file_match_cached_state_alloc(void) {
  bpfj_heap_use_arena();

  struct bpfj_file_match_cached_state __arena* state =
      BPFJ_HEAP_ALLOC(sizeof(*state));
  if (state == NULL) {
    return NULL;
  }

  bpfj_vec_init(&state->iters, sizeof(struct bpfj_file_match_cached_iter));
  bpfj_vec_init(&state->saved_dentries, sizeof(uintptr_t));
  state->leaf = NULL;
  state->mount = 0;
  state->matcher = NULL;
  state->mount_descriptor.ns_ino = 0;
  state->mount_descriptor.namespace_addr = 0;
  state->mount_descriptor.mount_lock = 0;
  state->mount_snapshot.buf = NULL;
  state->mount_snapshot.refcount = NULL;
  state->mount_fallback.parent_vfsmount = 0;
  state->mount_fallback.mountpoint = 0;
  return state;
}

// The cleanup half of BPFJ_FILE_MATCH_CACHED_ALLOC: the vecs first, then the
// struct they live in.
static void bpfj_file_match_cached_state_free(void __arena** ptr) {
  if (ptr == NULL || *ptr == NULL) {
    return;
  }

  struct bpfj_file_match_cached_state __arena* state = *ptr;
  bpfj_shared_ptr_release_arena(&state->mount_snapshot);
  bpfj_vec_destroy(&state->iters);
  bpfj_vec_destroy(&state->saved_dentries);
  BPFJ_HEAP_FREE(state);
  *ptr = NULL;
}

struct bpfj_file_match_cached_glob_results {
  __u64 results[BPFJ_GLOB_MAP_MAX_RESULTS];
};

struct bpfj_file_match_cached_dir_walk {
  __u32 count;
  __u32 _pad;
  struct bpfj_file_match_cached_key
      entries[BPFJ_FILE_MATCH_CACHED_MAX_DIR_DESCENDANTS];
};

// We don't use the seqcount directly for caching because it flips too often
// (with every rename), instead we invalidate individual cache entries from
// renames. The global counter is only bumped as a fallback when a directory has
// too many descendants to walk individually.
static __u64 bpfj_file_match_cached_rename_counter = 0;

#ifndef S_IFMT
#define S_IFMT 0170000
#endif

#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif

// __noinline for the same reason as bpfj_mount_seqcount: its BPF_CORE_READ
// scratch would otherwise sit in file_match_cached's frame, which is on the
// deep chain.
__noinline u32 bpfj_file_match_cached_rename_seqcount() {
  return BPF_CORE_READ(
      ((const seqlock_t*)&rename_lock), seqcount.seqcount.sequence);
}

// Process node matching and initializer logic for one matched component
// pattern, identified by its packed bpfj_file_match_indexes.
__noinline int bpfj_file_match_cached_process_indexes(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    __u64 packed_indexes) {
  struct bpfj_file_match_indexes indexes;
  __builtin_memcpy(&indexes, &packed_indexes, sizeof(indexes));
  if (indexes.nodes_id < 0) {
    return 0;
  }

  const struct bpfj_perf_map __arena* nodes_perf_map = matcher->nodes_perf_map;
  const struct bpfj_perf_map __arena* initializer_perf_map =
      matcher->initializer_perf_map;

  void __arena* base = (void __arena*)bpfj_heap_ctrl;

  BPFJ_DBG_LOG("file_match_cached: matched name");

  u32 i = 0;
  u64 inner_off = 0;
  bool has_nodes = bpfj_perf_map_lookup(
                       nodes_perf_map, (u64)indexes.nodes_id, &inner_off) == 0;

  if (has_nodes) {
    u32 hdr_off = (u32)inner_off;
    hdr_off = bpfj_heap_clamp_off(hdr_off);
    // The inner header is read in place now that the lookup takes an arena
    // pointer; it used to be copied field-wise onto the stack first.
    __arena const struct bpfj_perf_map* inner_map =
        (__arena const struct bpfj_perf_map*)((char __arena*)base + hdr_off);
    __u32 count = bpfj_file_match_cached_count(state);
    bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
      if (i >= count) {
        break;
      }

      struct bpfj_file_match_cached_iter __arena* iter =
          bpfj_file_match_cached_iter_at(state, i);
      if (iter == NULL) {
        break;
      }
      // Composed field-wise rather than copied: a struct copy out of arena
      // memory loses the address space and the verifier rejects the load.
      // Little-endian, so this is the same u64 the copy produced.
      u64 node_key =
          (u64)(__u32)iter->node.path_id | ((u64)(__u32)iter->node.pos << 32);
      u64 dummy = 0;
      if (bpfj_perf_map_lookup(inner_map, node_key, &dummy) == 0) {
        iter->was_matched_this_cycle = true;
      }
    }
  }

  // Add any new iters from initializers
  if (indexes.initializer_nodes_id < 0) {
    return 0;
  }

  u64 init_arr_off = 0;
  if (bpfj_perf_map_lookup(
          initializer_perf_map,
          (u64)indexes.initializer_nodes_id,
          &init_arr_off) != 0) {
    BPFJ_DBG_LOG("file_match_cached: Invalid initializer node");
    return 0;
  }

  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_INITIALIZER_NODES) {
    u32 elem_off = (u32)init_arr_off + i * sizeof(s32);
    elem_off = bpfj_heap_clamp_off(elem_off);
    s32 path_id_val = *(__arena const s32*)((char __arena*)base + elem_off);
    if (path_id_val < 0) {
      break;
    }

    // Note: duplicate iters may be created for the same path_id when several
    // component patterns trigger the same initializer. This trades iter slot
    // efficiency for verifier complexity budget — the O(64*64) dedup scan was
    // too expensive for the verifier.

    BPFJ_DBG_LOG("file_match_cached: Adding new iter %d,0", path_id_val);

    // The cap is still enforced, just not by running out of array: every loop
    // that walks the iters is bounded by it, so anything past it would be
    // invisible to them.
    if (bpfj_file_match_cached_count(state) >= BPFJ_FILE_MATCH_MAX_ITERS) {
      BPFJ_DBG_LOG("file_match_cached: Ran out of iters");
      break;
    }

    // emplace_back and not push_back: this is inside a bpf_for, and it is the
    // one that brings no iterator of its own. It also replaces the scan for a
    // tombstoned slot the fixed array needed -- appending is where the end is.
    struct bpfj_file_match_cached_iter __arena* mem =
        bpfj_vec_emplace_back(&state->iters);
    if (mem == NULL) {
      BPFJ_DBG_LOG("file_match_cached: Could not grow iters");
      break;
    }

    // Field-wise: a struct copy into arena memory drops the address space.
    mem->node.path_id = path_id_val;
    mem->node.pos = 0;
    mem->is_being_dropped = false;
    mem->was_matched_this_cycle = true;
  }

  return 0;
}

// Drop the iters marked for purging, keeping the rest in order.
//
// One compacting pass, where the fixed array needed a shift-down per dropped
// iter and a tombstone to mark the new end -- the vec's size is the end, so
// truncating to the survivors is the whole of it.
long bpfj_file_match_cached_purge(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  __u32 count = bpfj_file_match_cached_count(state);
  __u32 kept = 0;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }

    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      break;
    }
    if (iter->is_being_dropped) {
      continue;
    }

    if (kept != i) {
      struct bpfj_file_match_cached_iter __arena* dst =
          bpfj_file_match_cached_iter_at(state, kept);
      if (dst == NULL) {
        break;
      }
      // Field-wise, for the usual reason, and a plain copy rather than a heap
      // helper because this is inside a bpf_for.
      dst->node.path_id = iter->node.path_id;
      dst->node.pos = iter->node.pos;
      dst->was_matched_this_cycle = iter->was_matched_this_cycle;
      dst->is_being_dropped = iter->is_being_dropped;
    }
    ++kept;
  }

  bpfj_vec_truncate(&state->iters, kept);
  return 0;
}

// Finalize iters after all matching for a dentry step: an iter that matched the
// current component advances to the next position; one that did not is marked
// for purging. was_matched_this_cycle is reset so iters must re-match on the
// next dentry step or be dropped. The root dentry (which may carry a non-path
// name like a btrfs subvol ID) is skipped at the top of the walk loop so iters
// are never tested against it.
long bpfj_file_match_cached_finalize(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  __u32 count = bpfj_file_match_cached_count(state);
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }

    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      break;
    }

    if (iter->was_matched_this_cycle) {
      iter->node.pos += 1;
      iter->is_being_dropped = false;
    } else {
      iter->is_being_dropped = true;
    }
    iter->was_matched_this_cycle = false;
  }

  return 0;
}

// Finalize pod masks then purge dead iters. Called once per dentry step.
long bpfj_file_match_cached_finalize_and_purge(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    uintptr_t dentry) {
  bpfj_file_match_cached_finalize(state);

  // The walk step index used to be the slot index; appending makes them the
  // same thing, and the vec's size is the depth.
  if (bpfj_vec_size(&state->saved_dentries) <
      BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES) {
    uintptr_t __arena* slot = bpfj_vec_emplace_back(&state->saved_dentries);
    if (slot != NULL) {
      *slot = dentry;
    }
  }

  bpfj_file_match_cached_purge(state);

  return 0;
}

// Match a dentry name against every component pattern (literal, '*'/'?'
// wildcard, or ${VAR} variable) via the single glob NFA, then fold each
// matching pattern's nodes/initializers into the active iters. Replaces the
// former three-way lookup (names_map literal, globs_perf_map per-node, and
// var_id_to_node_perf_map per-pod).
// `run` is the walk's run state, bound once in file_match_cached against the
// compiled map and this match's variable bindings. A run bound to a NULL header
// -- nothing compiled -- matches nothing.
__noinline long bpfj_file_match_cached_nodes(
    struct bpfj_glob_run __arena* run __arg_arena,
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    struct bpfj_file_match_name __arena* name __arg_arena,
    long size) {
  BPFJ_HEAP_ALLOC_GUARD(struct bpfj_file_match_cached_glob_results, results);
  if (!results) {
    return -ENOMEM;
  }

  u64 len = size - 1; // Drop null term
  if (len > BPFJ_FILE_MATCH_NAME_LEN) {
    len = BPFJ_FILE_MATCH_NAME_LEN;
  }

  long n = bpfj_glob_map_lookup(run, name->name, (u32)len, results->results);
  if (n < 0) {
    return n;
  }

  u32 i = 0;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_RESULTS) {
    if (i >= (u32)n) {
      break;
    }

    bpfj_file_match_cached_process_indexes(matcher, state, results->results[i]);
  }

  return 0;
}

__noinline long bpfj_file_match_cached_move_up(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    uintptr_t dentry,
    uintptr_t root,
    uintptr_t* out __arg_nonnull) {
  if (dentry == root) {
    BPFJ_DBG_LOG("file_match_cached: Reached root");
    *out = 0;
    return 0;
  }

  struct dentry* parent = BPF_CORE_READ((struct dentry*)dentry, d_parent);
  struct dentry* gparent = BPF_CORE_READ(parent, d_parent);

  uintptr_t curr_mount_vfsmnt = state->mount;
  if (curr_mount_vfsmnt != 0) {
    struct mount* curr_mount =
        container_of((struct vfsmount*)curr_mount_vfsmnt, struct mount, mnt);
    struct mnt_namespace* curr_namespace = BPF_CORE_READ(curr_mount, mnt_ns);
    uintptr_t mount_root =
        (uintptr_t)BPF_CORE_READ((struct vfsmount*)curr_mount_vfsmnt, mnt_root);
    uintptr_t mountpoint = (uintptr_t)BPF_CORE_READ(curr_mount, mnt_mountpoint);
    if ((uintptr_t)curr_namespace == state->mount_descriptor.namespace_addr &&
        mount_root == (uintptr_t)parent) {
      struct mount* parent_mount = BPF_CORE_READ(curr_mount, mnt_parent);
      uintptr_t parent_mount_vfsmnt =
          parent_mount ? (uintptr_t)&parent_mount->mnt : 0;
      if (mountpoint == (uintptr_t)parent) {
        BPFJ_DBG_LOG("file_match_cached: Reached root mount");
        *out = 0;
        return 0;
      }

      bool parent_is_subvol_root =
          BPF_CORE_READ(parent, d_inode, i_op) == &btrfs_dir_inode_operations &&
          BPF_CORE_READ(parent, d_inode, i_ino) == BTRFS_FIRST_FREE_OBJECTID;
      if (parent_is_subvol_root) {
        state->mount = parent_mount_vfsmnt;
        if (mountpoint == root) {
          BPFJ_DBG_LOG("file_match_cached: Reached parent root mount");
          *out = 0;
          return 0;
        }
        *out = mountpoint;
        BPFJ_DBG_LOG("file_match_cached: Found mount, moving up to %p", *out);
        return 0;
      }

      if (gparent == parent && mountpoint != 0) {
        state->mount = parent_mount_vfsmnt;
        if (mountpoint == root) {
          BPFJ_DBG_LOG("file_match_cached: Reached parent root mount");
          *out = 0;
          return 0;
        }
        if (mountpoint == (uintptr_t)parent) {
          BPFJ_DBG_LOG("file_match_cached: Reached root mount");
          *out = 0;
          return 0;
        }

        *out = mountpoint;
        BPFJ_DBG_LOG(
            "file_match_cached: Crossing same-ns root mount to %p", *out);
        return 0;
      }
    }
  }

  // We skip the root node, because it is not a real node, it is covered by the
  // mount
  if (gparent == parent) {
    BPFJ_DBG_LOG("file_match_cached: Reached dentry root");
    if ((uintptr_t)parent == root) {
      BPFJ_DBG_LOG("file_match_cached: Dentry root is target root, stopping");
      *out = 0;
      return 0;
    }
    long ret = bpfj_mount_find_parent(
        state->mount_snapshot.buf, (uintptr_t)parent, &state->mount_fallback);
    if (ret == 0) {
      uintptr_t mountpoint = state->mount_fallback.mountpoint;
      state->mount = state->mount_fallback.parent_vfsmount;
      if (mountpoint == root || mountpoint == (uintptr_t)parent) {
        *out = 0;
        return 0;
      }
      *out = mountpoint;
      return 0;
    }
    if (ret != -ENOENT) {
      return ret;
    }
  } else {
    // If the parent IS the root, stop here instead of returning it as the
    // next dentry to process. The root dentry's name (e.g. a btrfs subvol
    // ID) is not a path component and would spuriously fail to match.
    if ((uintptr_t)parent == root) {
      BPFJ_DBG_LOG("file_match_cached: Parent is root, stopping");
      *out = 0;
      return 0;
    }
    bool parent_is_subvol_root =
        BPF_CORE_READ(parent, d_inode, i_op) == &btrfs_dir_inode_operations &&
        BPF_CORE_READ(parent, d_inode, i_ino) == BTRFS_FIRST_FREE_OBJECTID;
    if (parent_is_subvol_root) {
      long ret = bpfj_mount_find_parent(
          state->mount_snapshot.buf, (uintptr_t)parent, &state->mount_fallback);
      if (ret == 0) {
        uintptr_t mountpoint = state->mount_fallback.mountpoint;
        state->mount = state->mount_fallback.parent_vfsmount;
        if (mountpoint == root) {
          *out = 0;
          return 0;
        }
        if (mountpoint != 0 && mountpoint != (uintptr_t)parent) {
          *out = mountpoint;
          return 0;
        }
      } else if (ret != -ENOENT) {
        return ret;
      }
    }
    BPFJ_DBG_LOG("file_match_cached: Moving up to %p", parent);
    *out = (uintptr_t)parent;
    return 0;
  }

  // A dentry-tree root that no mount is rooted at: there is nowhere left to
  // climb, and the walk stopped before it could reach `root`. The components
  // gathered so far are a path inside some other namespace's filesystem, not a
  // path in the target namespace, so matching them against the target's policy
  // would compare unrelated paths -- a private-ns tmpfs holding /data/inner
  // would match a rule written for the root ns /data/inner.
  //
  // -EXDEV is the signal v1 gives for exactly this ("not our namespace", see
  // file.h:502 ending the walk and file.h:611 reporting it), and both fs2
  // callers already treat it as benign and allow without logging. Returning the
  // raw -ENOENT instead is what made every containerized open on the fs2 path
  // log "Error matching" and fail open.
  return -EXDEV;
}

__attribute__((noinline)) long bpfj_file_match_cached_save_name(
    struct bpfj_file_match_name __arena* name __arg_arena,
    uintptr_t dentry) {
  if (!dentry) {
    return -EINVAL;
  }

  // TODO this is gross
  void* hash_len_ptr = (unsigned char*)dentry +
      offsetof(struct dentry, d_name) + offsetof(struct qstr, hash_len);
  u64 hash_len = 0;
  bpf_probe_read_kernel(&hash_len, sizeof(hash_len), hash_len_ptr);

  size_t len = bpfj_file_hashlen_len(hash_len) + 1;
  len = len < sizeof(name->name) ? len : sizeof(name->name);

  void* name_dptr = (unsigned char*)dentry + offsetof(struct dentry, d_name) +
      offsetof(struct qstr, name);
  const unsigned char* name_ptr = NULL;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), name_dptr);
  long ret = bpfj_heap_read_kernel(name->name, len, (__u64)(uintptr_t)name_ptr);
  if (ret < 0) {
    return ret;
  }

  BPFJ_DBG_LOG("file_match_cached: read name=%s", name->name);

  // Check for the root node which has the name "/". It is the only node that
  // can have a slash in the name. We just replace it with an empty name,
  // because having a / in the name is confusing.
  ret = len;
  if (ret == 2 && name->name[0] == '/') {
    --ret;
    name->name[0] = '\0';
  }

  return ret;
}

long bpfj_file_match_cached_init(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  // Clearing keeps both buffers, which is what makes a retry cheap: the
  // capacity the last attempt grew to is still there. It also replaces
  // tombstoning all 64 iter slots, because there is no slot that is not an
  // element any more.
  bpfj_vec_clear(&state->iters);
  bpfj_vec_clear(&state->saved_dentries);
  state->mount = 0;
  bpfj_shared_ptr_release_arena(&state->mount_snapshot);
  state->mount_descriptor.ns_ino = 0;
  state->mount_descriptor.namespace_addr = 0;
  state->mount_descriptor.mount_lock = 0;
  state->mount_fallback.parent_vfsmount = 0;
  state->mount_fallback.mountpoint = 0;

  BPFJ_DBG_LOG("file_match_cached: Initialized");

  return 0;
}

__attribute__((noinline)) long bpfj_file_match_cached_get_root(pid_t pid) {
  struct task_struct* task = bpf_task_from_pid(pid);
  if (!task) {
    return 0;
  }

  struct dentry* root = task->fs->root.dentry;
  bpf_task_release(task);

  // Force the verifier to treat pointer as a scalar
  long out = 0;
  bpf_probe_read_kernel(&out, sizeof(out), &root);
  return out;
}

// static __always_inline, not a global subprogram: the run state is written
// field-wise here, and an __arg_arena parameter does not survive the global
// call boundary on 6.11 -- the verifier hands the callee a scalar and rejects
// the first store through it. Inlined, the pointer keeps the provenance it has
// in the caller, which is the frame that allocated it.
static __always_inline long bpfj_file_match_cached_setup(
    struct bpfj_file_match_cached_state __arena* state,
    struct bpfj_uuid* uuid __arg_nonnull) {
  bpfj_heap_use_arena();
  bpfj_heap_zero_arena(&state->bindings, sizeof(state->bindings));

  if (uuid) {
    bpfj_heap_write_arena(&state->uuid, sizeof(state->uuid), uuid);
  } else {
    bpfj_heap_zero_arena(&state->uuid, sizeof(state->uuid));
  }

  return 0;
}

// Bind the run state to a matcher and a dentry, without running the match or
// filling in its variable bindings. BPFJ_FILE_MATCH_CACHED_DEFINE_BIND builds
// the variant that does both, which is what a match needs; this one is for a
// cache check, which evaluates no glob.
//
// Out of line, and split from the match it precedes, purely for stack. Inlined,
// the binding's scratch lands in the caller's frame, and the caller is frame
// one of the chain through file_match_cached that sits at the verifier's
// 512-byte combined limit. This calls nothing, so out of line it is a leaf and
// its frame never joins that chain -- where an out-of-line wrapper around the
// match itself would just move the whole chain a frame deeper.
//
// static, not global: bpfj_file_match_cached_setup has to be inlined into it
// (see the note there about __arg_arena and the global call boundary), and that
// only holds if this keeps the caller's provenance too.
static __noinline void bpfj_file_match_cached_bind(
    struct bpfj_file_match_cached_state __arena* state,
    struct bpfj_file_matcher __arena* matcher,
    uintptr_t dentry,
    struct bpfj_uuid* uuid) {
  bpfj_file_match_cached_setup(state, uuid);
  state->leaf = (struct dentry*)dentry;
  state->matcher = matcher;
}

// Declare `_fn`, bpfj_file_match_cached_bind plus filling in the state's glob
// bindings from a `const _vars_type*` through `_binder`, which takes
// (struct bpfj_glob_bindings __arena* out, const _vars_type* vars). One per var
// type, since BPF cannot call through a pointer.
//
// One call rather than a bind followed by the binder: the hook calling them is
// frame one of the chain at the 512-byte limit, and a second call there costs
// it a spill slot that chain does not have.
#define BPFJ_FILE_MATCH_CACHED_DEFINE_BIND(_fn, _binder, _vars_type) \
  static __noinline void _fn(                                        \
      struct bpfj_file_match_cached_state __arena* state,            \
      struct bpfj_file_matcher __arena* matcher,                     \
      uintptr_t dentry,                                              \
      struct bpfj_uuid* uuid,                                        \
      const _vars_type* vars) {                                      \
    bpfj_file_match_cached_setup(state, uuid);                       \
    _binder(&state->bindings, vars);                                 \
    state->leaf = (struct dentry*)dentry;                            \
    state->matcher = matcher;                                        \
  }

static u64 bpfj_file_match_cached_subvol(struct inode* inode) {
  if (BPF_CORE_READ(inode, i_op) != &btrfs_file_inode_operations) {
    return 0;
  }

  struct btrfs_root* root = BPF_CORE_READ(BTRFS_I(inode), root);
  if (!root) {
    return 0;
  }

  return BPF_CORE_READ(root, root_key.objectid);
}

long bpfj_file_match_cached_build_key(
    struct bpfj_file_match_cached_key __arena* key __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  // Field-wise: a memset of arena memory drops the address space. _pad matters
  // -- the key is hashed as raw words, so its padding has to be deterministic.
  key->ino = 0;
  key->subvol = 0;
  key->dev = 0;
  key->_pad = 0;

  struct dentry* dentry = state->leaf;

  // TODO: remove BPF_CORE_READ
  key->dev = BPF_CORE_READ((struct dentry*)dentry, d_sb, s_dev);
  key->ino = BPF_CORE_READ((struct dentry*)dentry, d_inode, i_ino);
  key->subvol = bpfj_file_match_cached_subvol(
      BPF_CORE_READ((struct dentry*)dentry, d_inode));

  return 0;
}

// GLOBAL (__noinline), and deliberately not inlined into either caller: the
// five-argument BPF_SNPRINTF below needs a 40-byte argument array on the stack,
// and both callers are folded into file_match_cached, which sits on the
// program's deepest matcher call chain. Out of line, the two arrays live in a
// leaf frame that the mount and glob traversal paths never enter. The key is
// read back from the scratch map rather than passed in, so this needs no
// argument but the label.
//
// Returns a scalar (unused) because a global subprogram must, same as
// bpfj_file_match_cached_process_indexes.
__noinline long bpfj_file_match_cached_log_key(
    struct bpfj_file_match_cached_key __arena* key __arg_arena,
    int saving) {
  if (saving) {
    BPFJ_LOG(
        "file_match_cached: Saving to cache with key: "
        "dev=0x%lu ino=%lu subvol=%lu",
        key->dev,
        key->ino,
        key->subvol);
  } else {
    BPFJ_LOG(
        "file_match_cached: Checking cache with key: "
        "dev=0x%lu ino=%lu subvol=%lu",
        key->dev,
        key->ino,
        key->subvol);
  }

  return 0;
}

long bpfj_file_match_cached_check_file_cache(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  BPFJ_HEAP_ALLOC_GUARD(struct bpfj_file_match_cached_key, key);
  if (!key) {
    return -ENOMEM;
  }

  bpfj_file_match_cached_build_key(key, state);

  if (bpfj_dbg_mode) {
    bpfj_file_match_cached_log_key(key, false);
  }

  struct bpfj_file_match_cached_locks locks = {
      .mount_lock = bpfj_mount_seqcount(),
      .rename_counter = bpfj_file_match_cached_rename_counter,
  };

  BPFJ_DYN_LRU_LOOKUP_GUARD(cached_results_ptr);
  long ret = BPFJ_DYN_LRU_LOOKUP(
      cached_results_ptr, state->matcher->lru, (u64 __arena*)key);
  if (ret < 0) {
    __sync_fetch_and_add(&bpfj_file_match_cached_cache_miss_counter, 1);
    return ret;
  }

  struct bpfj_dyn_map __arena* cached_results = cached_results_ptr.buf;

  // Check locks
  if (cached_results->extra != locks.key) {
    // Lock mismatch
    __sync_fetch_and_add(&bpfj_file_match_cached_cache_miss_counter, 1);
    return -ENOENT;
  }

  // state->uuid is already arena memory of exactly the key's width, and the
  // map copies whatever key it is given, so there is nothing to stage: the
  // block this used to allocate cost a frame slot on the deep chain and an
  // alloc/free pair per lookup.
  BPFJ_SHARED_PTR_GUARD(cached_state_ptr, NULL);
  ret = bpfj_dyn_map_lookup(
      cached_results, (u64 __arena*)&state->uuid, &cached_state_ptr.ptr);
  if (ret < 0) {
    __sync_fetch_and_add(&bpfj_file_match_cached_cache_miss_counter, 1);
    return ret;
  }

  struct bpfj_file_match_cached_entry __arena* entry =
      BPFJ_SHARED_PTR_BUF(cached_state_ptr);

  __u32 iter_count = entry->iter_count;
  __u32 dentry_count = entry->dentry_count;
  if (iter_count > BPFJ_FILE_MATCH_MAX_ITERS ||
      dentry_count > BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES) {
    // Counts come back out of the arena, and every loop that walks these is
    // bounded by the caps, so an entry claiming more than that would be read
    // short. Treat it as a miss rather than as a partial answer.
    __sync_fetch_and_add(&bpfj_file_match_cached_cache_miss_counter, 1);
    return -ENOENT;
  }

  BPFJ_DBG_LOG("file_match_cached: Cache hit: %p", entry);
  __sync_fetch_and_add(&bpfj_file_match_cached_cache_hit_counter, 1);

  // Only the walk's output. This used to copy the whole run state over itself,
  // which also replaced the matcher, uuid and variable bindings that bind had
  // just put there -- harmless only because the entry was keyed by the uuid
  // whose state it was. Restoring the two vecs leaves the inputs alone.
  long res = bpfj_vec_assign(
      &state->saved_dentries,
      bpfj_file_match_cached_entry_dentries(entry),
      dentry_count);
  if (res < 0) {
    return res;
  }

  res = bpfj_vec_assign(
      &state->iters, bpfj_file_match_cached_entry_iters(entry), iter_count);
  if (res < 0) {
    return res;
  }

  return (long)iter_count;
}

long bpfj_file_match_cached_save_file_cache(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  BPFJ_HEAP_ALLOC_GUARD(struct bpfj_file_match_cached_key, key);
  if (!key) {
    return -ENOMEM;
  }

  bpfj_file_match_cached_build_key(key, state);

  if (bpfj_dbg_mode) {
    bpfj_file_match_cached_log_key(key, true);
  }

  // Check if a cached val exists already
  BPFJ_DYN_LRU_LOOKUP_GUARD(cached_results_ptr);
  long ret = BPFJ_DYN_LRU_LOOKUP(
      cached_results_ptr, state->matcher->lru, (u64 __arena*)key);
  if (ret < 0 && ret != -ENOENT) {
    // Error
    return ret;
  }

  struct bpfj_file_match_cached_locks locks = {
      .mount_lock = bpfj_mount_seqcount(),
      .rename_counter = bpfj_file_match_cached_rename_counter,
  };

  // bpfj_dyn_map_insert takes ownership of both blocks it is handed, so each
  // gets its own allocation with exactly one owner. Neither the run state nor a
  // pointer into it will do: that block belongs to the caller's scope guard,
  // which frees it when the hook returns, leaving the cached entry pointing at
  // memory the next match reallocates.
  struct bpfj_uuid __arena* uuid = BPFJ_HEAP_ALLOC(sizeof(*uuid));
  if (!uuid) {
    return -ENOMEM;
  }
  bpfj_heap_copy_arena(uuid, &state->uuid, sizeof(*uuid));

  __u32 iter_count = bpfj_file_match_cached_count(state);
  __u32 dentry_count = bpfj_vec_size(&state->saved_dentries);

  struct bpfj_file_match_cached_entry __arena* cached = BPFJ_HEAP_ALLOC(
      bpfj_file_match_cached_entry_size(iter_count, dentry_count));
  if (!cached) {
    BPFJ_HEAP_FREE(uuid);
    return -ENOMEM;
  }

  cached->iter_count = iter_count;
  cached->dentry_count = dentry_count;
  if (dentry_count != 0) {
    bpfj_heap_copy_arena(
        bpfj_file_match_cached_entry_dentries(cached),
        state->saved_dentries.buf,
        dentry_count * (__u32)sizeof(uintptr_t));
  }
  if (iter_count != 0) {
    bpfj_heap_copy_arena(
        bpfj_file_match_cached_entry_iters(cached),
        state->iters.buf,
        iter_count * (__u32)sizeof(struct bpfj_file_match_cached_iter));
  }

  if (ret == 0) {
    // Only now: on -ENOENT the guard holds NULL, and the lock check below
    // would be reading through it.
    struct bpfj_dyn_map __arena* cached_results = cached_results_ptr.buf;

    if (cached_results->extra != locks.key) {
      // Everything under this key was resolved against a mount/rename view
      // that has since moved, so drop it and re-stamp.
      bpfj_dyn_map_wipe(cached_results);
      cached_results->extra = locks.key;
    } else if (
        BPFJ_DYN_READ_ONCE(cached_results->size) >=
        bpfj_file_match_cached_max_pods(state->matcher)) {
      // This file has collected as many pods as it is allowed to. Nothing else
      // retires them -- see the cap's own comment -- so the entry starts over
      // rather than growing without a bound. Wiping rather than evicting one
      // pod because there is no recency here to evict by, and because a wipe is
      // what this map already knows how to do.
      __sync_fetch_and_add(&bpfj_file_match_cached_cache_pod_cap_counter, 1);
      BPFJ_DBG_LOG("file_match_cached: Pod cap reached, wiping cache entry");
      bpfj_dyn_map_wipe(cached_results);
      cached_results->extra = locks.key;
    }

    // TODO avoid overwriting state each time
    return bpfj_dyn_map_insert(cached_results, (u64 __arena*)uuid, cached);
  }

  // Need to insert a new map
  struct bpfj_dyn_map __arena* map = BPFJ_HEAP_ALLOC(sizeof(*map));
  if (!map) {
    BPFJ_HEAP_FREE(cached);
    BPFJ_HEAP_FREE(uuid);
    return -ENOMEM;
  }
  ret = bpfj_dyn_map_init(
      map,
      BPFJ_DYN_MAP_MIN_CAPACITY,
      sizeof(*uuid),
      // The smallest an entry can be, not the width of one: entries are tail
      // allocated and vary. The map records this and never reads it back -- the
      // block header is what the free goes by -- but init rejects a zero.
      sizeof(struct bpfj_file_match_cached_entry));
  if (ret < 0) {
    BPFJ_HEAP_FREE(map);
    BPFJ_HEAP_FREE(cached);
    BPFJ_HEAP_FREE(uuid);
    return ret;
  }

  // Stamp the view this map was built under, before it is reachable: a lookup
  // compares against this to decide the entry is still valid, so an unstamped
  // map would read as permanently stale and never hit.
  map->extra = locks.key;

  ret = bpfj_dyn_map_insert(map, (u64 __arena*)uuid, cached);
  if (ret < 0) {
    bpfj_dyn_map_free(map);
    return ret;
  }

  // map is cleaned up on insert fail
  // This can drop another write at the same time. That is fine because this is
  // just a cache
  return bpfj_dyn_lru_insert(state->matcher->lru, (u64 __arena*)key, map);
}

__noinline long bpfj_file_match_cached_dbg_print(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  __u32 count = bpfj_file_match_cached_count(state);
  BPFJ_LOG("file_match_cached: Done, found %u matches", count);

  __arena const struct bpfj_file_match_cached_pattern_str* pattern_strs =
      matcher->pattern_strs;
  __u32 num_pattern_strs = matcher->num_pattern_strs;

  if (pattern_strs == NULL || num_pattern_strs == 0) {
    return 0;
  }

  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }

    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      break;
    }
    BPFJ_LOG(
        "file_match_cached: Iter %d,%d", iter->node.path_id, iter->node.pos);

    if ((__u32)iter->node.path_id >= num_pattern_strs) {
      BPFJ_LOG("file_match_cached: Failed to lookup pattern string");
      continue;
    }

    __arena const struct bpfj_file_match_cached_pattern_str* pattern_str =
        pattern_strs + (__u32)iter->node.path_id;

    BPFJ_LOG("file_match_cached: matched pattern: %s", pattern_str->pattern);
  }

  return 0;
}

long bpfj_file_match_cached_get_walked_path(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    struct bpfj_file_match_cached_pattern_str __arena* str __arg_arena) {
  char __arena* path = str->pattern;

  // Every bound below is the size of `path`, which is a pattern_str and NOT
  // BPFJ_FILE_MATCH_CACHED_BUF_SIZE: the two differ, and bounding a write to
  // the larger one runs off the end of the block and corrupts the arena heap.
  // Masks require a power of two.
  _Static_assert(
      (BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN &
       (BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN - 1)) == 0,
      "pattern_str length must be a power of two to mask against");
  _Static_assert(
      BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN > BPFJ_FILE_MATCH_NAME_LEN,
      "a single component has to fit in the walked-path buffer");

  u32 off = 0;
  u32 i;
  __u32 depth = bpfj_vec_size(&state->saved_dentries);
  BPFJ_DBG_LOG("file_match_cached: Saved dentries depth: %u", depth);
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES) {
    if (i >= depth) {
      break;
    }

    // Walked leaf first, so the path is assembled from the far end back.
    uintptr_t __arena* saved =
        bpfj_vec_at(&state->saved_dentries, depth - i - 1);
    if (saved == NULL) {
      break;
    }

    uintptr_t dentry = *saved;
    const unsigned char* name_ptr =
        BPF_CORE_READ((struct dentry*)dentry, d_name.name);
    if (!name_ptr) {
      continue;
    }

    BPFJ_DBG_LOG(
        "file_match_cached: Saved dentry %u name: %s", depth - i - 1, name_ptr);

    u64 hash_len_val = BPF_CORE_READ((struct dentry*)dentry, d_name.hash_len);
    u32 len = bpfj_file_hashlen_len(hash_len_val);
    len &= (BPFJ_FILE_MATCH_NAME_LEN - 1);

    char c = '\0';
    bpf_probe_read_kernel(&c, sizeof(c), name_ptr);
    if (c == '\0' || c == '/') {
      // Skip empty and root names
      continue;
    }

    off &= (BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN - 1);
    if (off >=
        BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN - BPFJ_FILE_MATCH_NAME_LEN) {
      break;
    }
    path[off++] = '/';

    long ret =
        bpfj_heap_read_kernel(path + off, len, (__u64)(uintptr_t)name_ptr);
    if (ret < 0) {
      return ret;
    }

    off += len;
  }

  off &= (BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN - 1);
  path[off] = '\0';

  BPFJ_DBG_LOG("file_match_cached: Walked path: %s", path);

  return 0;
}

static long bpfj_file_match_cached_cache_iter(
    struct bpf_map* map,
    const void* key,
    void* value,
    void* ctx) {
  struct bpfj_file_match_cached_key* lookup_key_ptr = ctx;
  const struct bpfj_file_match_cached_key* key_ptr = key;
  struct bpfj_file_match_cached_state* value_ptr = value;
  if (key_ptr->dev == lookup_key_ptr->dev &&
      key_ptr->ino == lookup_key_ptr->ino &&
      key_ptr->subvol == lookup_key_ptr->subvol) {
    // We are renaming the same file, so we need to invalidate the cache entry
    bpf_map_delete_elem(map, key);
  }

  return 0;
}

static __noinline long bpfj_file_match_cached_collect_descendants(
    struct dentry* dir_dentry,
    struct bpfj_file_match_cached_dir_walk __arena* walk __arg_arena) {
  walk->count = 0;

  // A rename preserves the renamed directory's own inode identity
  // (dev/ino/subvol), so its cached decision is stale at the new path. Seed it
  // as the first entry to invalidate alongside its descendants; otherwise a
  // directory moved into a denied path keeps a stale ALLOW (fail-open).
  struct inode* dir_inode = BPF_CORE_READ(dir_dentry, d_inode);
  if (dir_inode) {
    walk->entries[0].dev = BPF_CORE_READ(dir_inode, i_sb, s_dev);
    walk->entries[0].ino = BPF_CORE_READ(dir_inode, i_ino);
    walk->entries[0].subvol = bpfj_file_match_cached_subvol(dir_inode);
    // Like every entry the walk below builds: `walk` is a heap block, so the
    // padding starts as whatever the block last held, and the key is hashed
    // and compared as raw words.
    walk->entries[0]._pad = 0;
    walk->count = 1;
  }

  struct hlist_node* child_node = BPF_CORE_READ(dir_dentry, d_children.first);

  struct hlist_node* to_explore[BPFJ_FILE_MATCH_CACHED_MAX_CHILD_DENTRIES] = {
      0};
  u32 pos = 0;

  u32 j;
  bpf_for(j, 0, BPFJ_FILE_MATCH_CACHED_MAX_DIR_DESCENDANTS * 2) {
    if (!child_node) {
      if (pos == 0) {
        break;
      }

      child_node = to_explore[--pos];
      continue;
    }

    struct dentry* child = container_of(child_node, struct dentry, d_sib);
    struct inode* inode = BPF_CORE_READ(child, d_inode);

    child_node = BPF_CORE_READ(child, d_sib.next);

    if (inode) {
      unsigned int mode = BPF_CORE_READ(inode, i_mode);
      if ((mode & S_IFMT) == S_IFDIR) {
        if (pos >= BPFJ_FILE_MATCH_CACHED_MAX_CHILD_DENTRIES) {
          // Too many children, stop
          return -1;
        }

        to_explore[pos++] = child_node;
        child_node = BPF_CORE_READ(child, d_children.first);
      }

      u32 idx = walk->count;
      if (idx >= BPFJ_FILE_MATCH_CACHED_MAX_DIR_DESCENDANTS) {
        // Too many entries, stop
        return -1;
      }

      walk->entries[idx].dev = BPF_CORE_READ(inode, i_sb, s_dev);
      walk->entries[idx].ino = BPF_CORE_READ(inode, i_ino);
      walk->entries[idx].subvol = bpfj_file_match_cached_subvol(inode);
      walk->entries[idx]._pad = 0;
      walk->count = idx + 1;
    }
  }

  if (child_node == NULL && pos == 0) {
    return 0;
  }

  // Too many children, stop
  return -1;
}

static __noinline long bpfj_file_match_cached_invalidate_dir(
    struct bpfj_dyn_lru __arena* lru __arg_arena,
    struct dentry* dir_dentry) {
  BPFJ_HEAP_ALLOC_GUARD(struct bpfj_file_match_cached_dir_walk, walk);
  if (!walk) {
    __sync_fetch_and_add(&bpfj_file_match_cached_rename_counter, 1);
    return -ENOMEM;
  }

  long ret = bpfj_file_match_cached_collect_descendants(dir_dentry, walk);
  if (ret < 0) {
    __sync_fetch_and_add(&bpfj_file_match_cached_rename_counter, 1);
    return 0;
  }

  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_DIR_DESCENDANTS) {
    if (i >= walk->count) {
      break;
    }

    struct bpfj_file_match_cached_key __arena* key = &walk->entries[i];

    // Every descendant, not just the first: returning here left the rest of
    // the directory cached against a path that no longer exists. Erased rather
    // than wiped, for the reason in the caller.
    if (bpfj_dyn_lru_erase(lru, (u64 __arena*)key) < 0) {
      // The only failure is a contended lock, and a descendant left behind is
      // a stale cache entry. Fall back to the global counter, which retires
      // every entry at once -- the same escape hatch a directory too wide to
      // walk uses.
      __sync_fetch_and_add(&bpfj_file_match_cached_rename_counter, 1);
      return 0;
    }
  }

  return 0;
}

static long bpfj_file_match_cached_check_invalidate_cache_on_rename(
    struct bpfj_dyn_lru __arena* lru __arg_arena,
    struct dentry* dentry) {
  struct inode* inode = BPF_CORE_READ(dentry, d_inode);
  if (!inode) {
    return -EINVAL;
  }

  unsigned int mode = BPF_CORE_READ(inode, i_mode);
  if ((mode & S_IFMT) == S_IFDIR) {
    return bpfj_file_match_cached_invalidate_dir(lru, dentry);
  }

  BPFJ_HEAP_ALLOC_GUARD(struct bpfj_file_match_cached_key, key);
  if (!key) {
    return -ENOMEM;
  }

  key->dev = BPF_CORE_READ(inode, i_sb, s_dev);
  key->ino = BPF_CORE_READ(inode, i_ino);
  key->subvol = bpfj_file_match_cached_subvol(inode);
  key->_pad = 0;

  BPFJ_DBG_LOG(
      "file_match_cached: Renaming file, invalidating cache entry dev=0x%lu ino=%lu subvol=%lu",
      key->dev,
      key->ino,
      key->subvol);

  // Erased, not wiped: the entry is keyed on the file's identity, and a rename
  // does not change that, so leaving an emptied map behind would hold a slot
  // and a recency position for a path that has to be walked again anyway.
  if (bpfj_dyn_lru_erase(lru, (u64 __arena*)key) < 0) {
    // Same escape hatch as the directory walk, for the same reason: the only
    // failure is a contended map lock, an absent key erases successfully, and
    // the caller does nothing with the error. Left alone, a rename that lost
    // the lock keeps a stale ALLOW under an identity the rename does not
    // change.
    __sync_fetch_and_add(&bpfj_file_match_cached_rename_counter, 1);
  }
  return 0;
}

long file_match_cached_internal_loop(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    uintptr_t root) {
  uintptr_t curr = (uintptr_t)state->leaf;
  BPFJ_HEAP_ALLOC_GUARD(struct bpfj_file_match_name, name);

  struct bpfj_glob_run __arena* run = &state->glob_run;
  // Bound once: the compiled map and this match's variable bindings are the
  // same for every component. A NULL glob_map -- nothing compiled -- leaves the
  // run matching nothing, exactly as before.
  bpfj_glob_run_bind(run, matcher->glob_map, &state->bindings);
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_RECURSION) {
    // A self-parented dentry is a filesystem root, not a path component. A
    // namespace may have several whole-filesystem mounts stacked at `/`, so a
    // mount transition can yield another such dentry before reaching `root`.
    // Resolve through it without feeding an empty component to the matcher.
    struct dentry* curr_parent = BPF_CORE_READ((struct dentry*)curr, d_parent);
    if ((uintptr_t)curr_parent == curr) {
      uintptr_t out = 0;
      long ret = bpfj_file_match_cached_move_up(state, curr, root, &out);
      if (ret < 0) {
        return ret;
      }
      if (out == 0) {
        break;
      }
      curr = out;
      continue;
    }

    long ret = bpfj_file_match_cached_save_name(name, curr);
    if (ret < 0) {
      return ret;
    }

    // Propagated, not discarded. A component whose glob lookup failed
    // contributes no matches, and swallowing that here would let the walk carry
    // on and hand an under-populated match set to an allow/deny decision as if
    // it were a genuine set of misses.
    ret = bpfj_file_match_cached_nodes(run, matcher, state, name, ret);
    if (ret < 0) {
      return ret;
    }

    bpfj_file_match_cached_finalize_and_purge(state, curr);

    uintptr_t out = 0;
    ret = bpfj_file_match_cached_move_up(state, curr, root, &out);
    if (ret < 0) {
      return ret;
    }
    if (out == 0) {
      break;
    }

    curr = (uintptr_t)out;
  }

  return 0;
}

__noinline long file_match_cached(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    struct bpfj_mount_cache __arena* mount_cache __arg_arena) {
  // A negative dentry -- one with no inode yet, which is what the mknod-family
  // hooks are handed -- contributes ino 0 to the cache key, so every negative
  // dentry on a superblock would collide and alias to whichever path was
  // matched there first. Match it, but neither read nor write the cache.
  //
  // The dentry is read back out of the run state, where bind put it, and it is
  // landed in a local before BPF_CORE_READ touches it: that macro relocates
  // every step of the chain it is given, and the run state is ours, not the
  // kernel's, so there is no BTF for it to relocate against. Same two-step as
  // bpfj_file_match_cached_build_key.
  struct dentry* leaf = state->leaf;
  bool cacheable = bpfj_file_match_cached_caches(state) &&
      BPF_CORE_READ(leaf, d_inode) != NULL;

  if (cacheable) {
    long count = bpfj_file_match_cached_check_file_cache(state);
    if (count >= 0) {
      return count;
    }
  }

  const pid_t root_pid = 1;
  uintptr_t root = (uintptr_t)bpfj_file_match_cached_get_root(root_pid);
  if (!root) {
    return -ESRCH;
  }

  struct bpfj_file_match_cached_lock lock = {
      .rename_lock = bpfj_file_match_cached_rename_seqcount(),
      .mount_lock = bpfj_mount_seqcount(),
  };

  // One run state for the whole walk, not one per path component. The heap lock
  // is a trylock that never waits, so a per-component allocation turns heap
  // contention -- from the mount walk, the LRU, or userspace -- into a
  // component that matches nothing, which is indistinguishable downstream from
  // a component that genuinely matched nothing. Hoisted, there is one
  // contention window per walk and one place to report it.
  bool completed_cycle = false;
  bpf_repeat(BPFJ_FILE_MATCH_CACHED_MAX_RETRIES) {
    bpfj_file_match_cached_init(state);

    long mount_ret = bpfj_mount_load(
        mount_cache,
        root_pid,
        &state->mount_descriptor,
        &state->mount_snapshot);
    if (mount_ret == -EBUSY) {
      continue;
    }
    if (mount_ret < 0) {
      return mount_ret;
    }
    long ret = file_match_cached_internal_loop(matcher, state, root);
    if (ret == -EBUSY) {
      continue;
    }
    if (ret < 0) {
      return ret;
    }

    u32 rename_lock = bpfj_file_match_cached_rename_seqcount();
    u32 mount_lock = bpfj_mount_seqcount();
    if (lock.rename_lock == rename_lock && lock.mount_lock == mount_lock) {
      completed_cycle = true;
      break;
    }
    lock.rename_lock = rename_lock;
    lock.mount_lock = mount_lock;
  }

  if (!completed_cycle) {
    return -EBUSY;
  }

  if (cacheable) {
    bpfj_file_match_cached_save_file_cache(state);
  }

  if (bpfj_dbg_mode) {
    bpfj_file_match_cached_dbg_print(matcher, state);
  }

  return (long)bpfj_file_match_cached_count(state);
}

// The data entry for the path_id the iter at match_idx is sitting on.
//
// This used to be two functions and a string lookup: a global subprogram that
// probed a per-path str_map for the caller's role id, and an inline wrapper
// that staged the key onto the arena for it. Both are gone. A matcher covers
// one role, so its data is a flat array and the path_id is the index -- an
// index check and an add. That is also what let the 64-byte role staging
// buffer come off the run state, which every cache entry carries a copy of.
static __always_inline void* bpfj_file_match_cached_lookup(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    u32 match_idx) {
  const struct bpfj_file_matcher __arena* matcher = state->matcher;
  if (matcher == NULL) {
    return NULL;
  }

  void __arena* vec = matcher->data_vec;
  if (vec == NULL) {
    return NULL;
  }

  struct bpfj_file_match_cached_iter __arena* iter =
      bpfj_file_match_cached_iter_at(state, match_idx);
  if (iter == NULL) {
    return NULL;
  }

  s32 path_id = iter->node.path_id;
  u32 count = matcher->data_entry_count;
  u32 size = matcher->data_entry_size;
  if (path_id < 0 || (u32)path_id >= count || size == 0) {
    return NULL;
  }

  // Bounded against the data block, not against the arena.
  //
  // bpfj_heap_clamp_off masks to the arena size, which is the right bound for
  // an offset about to be added to the arena base -- which is what every other
  // use of it here is doing. This offset is added to `vec`, already an interior
  // pointer, so that mask would leave the result anywhere up to a whole arena
  // past the end of the block: it bounds the stride and nothing else.
  //
  // The block is count * size bytes, and both come back out of the arena, so
  // neither is known at verification time and the product is not to be trusted
  // either. Computed in 64 bits so it cannot wrap, and the entry has to fall
  // entirely inside it.
  u64 total = (u64)count * (u64)size;
  u64 off = (u64)(u32)path_id * (u64)size;
  if (total > BPFJ_HEAP_MAX_ARENA_SIZE || off + (u64)size > total) {
    return NULL;
  }
  return (void*)((char __arena*)vec + off);
}
