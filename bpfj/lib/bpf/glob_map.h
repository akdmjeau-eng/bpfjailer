// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/types_glob_map.h"
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/lib/bpf/vec.h"

// The glob map compiles all patterns into a single bit-parallel NFA whose state
// is partitioned into independent 64-bit words (see types_glob_map.h), advanced
// in one pass over the input.
//
// Variables (${NAME}) are fixed-width gadgets reserved inline in a pattern,
// with per-character transitions built each byte from the value bound at
// lookup. A thread that has consumed the whole value sits at the "post" bit
// (base + value length) and a per-gadget epsilon jump moves it to the fixed
// "exit" bit (base + MAX_VAR_LEN).
//
// The matcher is split into GLOBAL functions so the verifier checks each once.
// The compiled header and vector-backed run state live on the arena, keeping
// scratch proportional to the map rather than to its limits.

static __always_inline __u32
bpfj_glob_ptr_off(void __arena* base, __arena const void* ptr) {
  return (__u32)((unsigned long)ptr - (unsigned long)base);
}

static __always_inline u64 __arena* bpfj_glob_word_at(
    struct bpfj_vec __arena* vec,
    u32 index) {
  return bpfj_vec_at(vec, index);
}

static __always_inline struct bpfj_glob_gadget_run __arena* bpfj_glob_gadget_at(
    struct bpfj_glob_run __arena* run,
    u32 index) {
  return bpfj_vec_at(&run->gadgets, index);
}

static __always_inline bool bpfj_glob_state_has_accept(
    struct bpfj_glob_run __arena* run,
    u32 accept) {
  if (accept >= BPFJ_GLOB_MAP_MAX_ACCEPTS || accept >= run->map->num_accepts) {
    return false;
  }
  u32 word = run->map->accept_word[accept] & (BPFJ_GLOB_MAP_MAX_WORDS - 1);
  u32 bit = run->map->accept_bit[accept] & 63;
  u64 __arena* state = bpfj_glob_word_at(&run->state, word);
  return state != NULL && (((*state >> bit) & 1ULL) != 0);
}

// The binding for a gadget's key, or NULL if unbound. Key 0 is never assigned,
// so a zeroed slot cannot bind anything.
static __always_inline __arena const struct bpfj_glob_binding*
bpfj_glob_find_binding(
    const struct bpfj_glob_bindings __arena* bindings,
    __u32 key) {
  if (key == 0) {
    return NULL;
  }

  u32 count = bindings->count;
  for (u32 b = 0; b < BPFJ_GLOB_MAP_MAX_BINDINGS; ++b) {
    if (b >= count) {
      break;
    }
    if (bindings->b[b].key == key) {
      return &bindings->b[b];
    }
  }
  return NULL;
}

// Whether `map` has a gadget for `key`, for a converter holding more variables
// than fit in a bpfj_glob_bindings to bind only the ones the patterns use.
static __always_inline bool bpfj_glob_map_wants_key(
    const struct bpfj_glob_map __arena* map,
    __u32 key) {
  if (map == NULL || key == 0) {
    return false;
  }

  u32 num_vars = map->num_vars;
  bool found = false;
  u32 v = 0;
  bpf_for(v, 0, BPFJ_GLOB_MAP_MAX_BINDINGS) {
    if (v >= num_vars) {
      break;
    }
    if (map->var_keys[v] == key) {
      found = true;
      break;
    }
  }
  return found;
}

static __always_inline void bpfj_glob_poison_binding(
    __arena struct bpfj_glob_gadget_run* gadget) {
  gadget->len = BPFJ_GLOB_MAP_MAX_VAR_LEN + 1;
}

// GLOBAL function: resolve every gadget's binding once and copy its value into
// the gadget scratch. A sibling leaf of bpfj_glob_step/bpfj_glob_close, so the
// verifier charges max() not a sum.
__noinline int bpfj_glob_load_bindings(
    __arena struct bpfj_glob_run* run __arg_arena) {
  u32 num_gadgets = run->map->num_gadgets;

  long reserved = bpfj_vec_reserve(&run->gadgets, num_gadgets);
  if (reserved < 0) {
    return (int)reserved;
  }
  run->gadgets.size = num_gadgets;

  u32 g = 0;
  bpf_for(g, 0, BPFJ_GLOB_MAP_MAX_GADGETS) {
    if (g >= num_gadgets) {
      break;
    }
    struct bpfj_glob_gadget_run __arena* gadget = bpfj_glob_gadget_at(run, g);
    if (gadget == NULL) {
      return -ENOMEM;
    }
    u32 vlen = 0;
    __arena const struct bpfj_glob_binding* binding =
        bpfj_glob_find_binding(&run->bindings, run->map->gadget_key[g]);
    if (binding != NULL) {
      vlen = binding->len;
      if (vlen > BPFJ_GLOB_MAP_MAX_VAR_LEN) {
        bpfj_glob_poison_binding(gadget);
        continue;
      }
      // Not unrolled, so the copy spills no temporaries onto this frame.
#pragma clang loop unroll(disable)
      for (u32 k = 0; k < BPFJ_GLOB_MAP_MAX_VAR_LEN; ++k) {
        gadget->val[k] = k < vlen ? binding->val[k] : 0;
      }
    } else {
      bpfj_heap_zero_arena(gadget->val, BPFJ_GLOB_MAP_MAX_VAR_LEN);
    }
    gadget->len = vlen;
  }
  return 0;
}

// GLOBAL function: epsilon closure applied after every byte and once after
// init, moving each gadget's completed-value bit to its exit bit and then
// applying the '*' epsilon. Iterated to a fixpoint because the two epsilons
// feed each other and no single ordering closes both ("${VAR}*" needs the
// gadget edge first, "*${VAR}" the star edge); bits are only ever set, so
// re-running past the fixpoint is a no-op.
__noinline int bpfj_glob_close(__arena struct bpfj_glob_run* run __arg_arena) {
  u32 num_words = run->map->num_words;
  u32 num_gadgets = run->map->num_gadgets;

  u32 iter = 0;
  bpf_for(iter, 0, BPFJ_GLOB_MAP_CLOSE_ITERS) {
    // Variable tail epsilon: jump a thread sitting at base + value_len to the
    // gadget exit, in ascending base order so adjacent empty gadgets
    // ("${A}${B}") close within this one pass.
    u32 g = 0;
    bpf_for(g, 0, BPFJ_GLOB_MAP_MAX_GADGETS) {
      if (g >= num_gadgets) {
        break;
      }
      u32 word = run->map->gadget_word[g] & (BPFJ_GLOB_MAP_MAX_WORDS - 1);
      u32 base = run->map->gadget_base[g];
      struct bpfj_glob_gadget_run __arena* gadget = bpfj_glob_gadget_at(run, g);
      if (gadget == NULL) {
        return -ENOMEM;
      }
      u32 vlen = gadget->len;
      if (vlen > BPFJ_GLOB_MAP_MAX_VAR_LEN) {
        continue;
      }
      u32 post = (base + vlen) & 63;
      u32 exit = (base + BPFJ_GLOB_MAP_MAX_VAR_LEN) & 63;
      u64 __arena* state = bpfj_glob_word_at(&run->state, word);
      if (state == NULL) {
        return -ENOMEM;
      }
      if (((*state >> post) & 1ULL) != 0) {
        *state |= 1ULL << exit;
      }
    }

    // '*' epsilon: a star may also match the empty string and advance one bit.
    u32 w = 0;
    bpf_for(w, 0, BPFJ_GLOB_MAP_MAX_WORDS) {
      if (w >= num_words) {
        break;
      }
      u64 __arena* state = bpfj_glob_word_at(&run->state, w);
      if (state == NULL) {
        return -ENOMEM;
      }
      *state |= (*state & run->map->star_mask[w]) << 1;
    }
  }
  return 0;
}

// GLOBAL function: advance every word's sub-NFA by one input byte ch, then run
// the epsilon closure.
__noinline int bpfj_glob_step(
    __arena struct bpfj_glob_run* run __arg_arena,
    u8 ch) {
  u32 num_words = run->map->num_words;
  u32 num_gadgets = run->map->num_gadgets;
  __arena const u64* char_mask = run->map->char_mask;
  __arena const u64* star_mask = run->map->star_mask;

  // Per-word variable advance mask for this byte: gadget bit (base+k) is set
  // if value[k] == ch. In the run state, not on the stack, for the budget.
  u32 w = 0;
  bpf_for(w, 0, BPFJ_GLOB_MAP_MAX_WORDS) {
    if (w >= num_words) {
      break;
    }
    u64 __arena* advance = bpfj_glob_word_at(&run->var_advance, w);
    if (advance == NULL) {
      return -ENOMEM;
    }
    *advance = 0;
  }
  u32 g = 0;
  bpf_for(g, 0, BPFJ_GLOB_MAP_MAX_GADGETS) {
    if (g >= num_gadgets) {
      break;
    }
    u32 word = run->map->gadget_word[g] & (BPFJ_GLOB_MAP_MAX_WORDS - 1);
    u32 base = run->map->gadget_base[g];
    struct bpfj_glob_gadget_run __arena* gadget = bpfj_glob_gadget_at(run, g);
    u64 __arena* advance = bpfj_glob_word_at(&run->var_advance, word);
    if (gadget == NULL || advance == NULL) {
      return -ENOMEM;
    }
    u32 vlen = gadget->len;
    // Constant-bound and break-free so clang unrolls it rather than nesting a
    // loop the verifier would explore combinatorially.
    for (u32 k = 0; k < BPFJ_GLOB_MAP_MAX_VAR_LEN; ++k) {
      if (vlen <= BPFJ_GLOB_MAP_MAX_VAR_LEN && k < vlen &&
          (u8)gadget->val[k] == ch) {
        *advance |= 1ULL << ((base + k) & 63);
      }
    }
  }

  // Literal/'?'/variable tokens that match ch move one bit; '*' tokens consume
  // ch and stay.
  bpf_for(w, 0, BPFJ_GLOB_MAP_MAX_WORDS) {
    if (w >= num_words) {
      break;
    }
    u64 __arena* state = bpfj_glob_word_at(&run->state, w);
    u64 __arena* advance = bpfj_glob_word_at(&run->var_advance, w);
    if (state == NULL || advance == NULL) {
      return -ENOMEM;
    }
    u64 cur = *state;
    if (cur == 0) {
      continue;
    }
    u64 cm = char_mask[(u32)ch * num_words + w] | *advance;
    *state = ((cur & cm) << 1) | (cur & star_mask[w]);
  }

  // bpfj_glob_eval calls the closure separately, keeping the two siblings.
  return 0;
}

// GLOBAL function: initialize state and run the single pass over the input.
__noinline long bpfj_glob_eval_state(
    __arena struct bpfj_glob_run* run __arg_arena) {
  u32 num_words = run->map->num_words;

  // A separate frame, to stay within the bpf2bpf stack budget.
  long ret = bpfj_glob_load_bindings(run);
  if (ret < 0) {
    return ret;
  }

  ret = bpfj_vec_assign(&run->state, run->map->init_state, num_words);
  if (ret < 0) {
    return ret;
  }
  ret = bpfj_vec_reserve(&run->var_advance, num_words);
  if (ret < 0) {
    return ret;
  }
  run->var_advance.size = num_words;

  // For a pattern starting with an empty ${NAME} or a '*'.
  ret = bpfj_glob_close(run);
  if (ret < 0) {
    return ret;
  }

  u32 len = run->len;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_STR_LEN) {
    if (i >= len) {
      break;
    }
    ret = bpfj_glob_step(run, (u8)run->str[i]);
    if (ret < 0) {
      return ret;
    }
    ret = bpfj_glob_close(run);
    if (ret < 0) {
      return ret;
    }
  }

  return 0;
}

struct bpfj_glob_collect_ctx {
  struct bpfj_glob_run __arena* run;
};

// A callback gives result collection its own verifier stack rather than adding
// another bpf2bpf frame to file matching's already deep call chain.
static long bpfj_glob_collect_result(u32 j, void* data) {
  struct bpfj_glob_collect_ctx* ctx = data;
  struct bpfj_glob_run __arena* run = ctx->run;
  if (j >= run->map->num_accepts) {
    return 1;
  }
  if (!bpfj_glob_state_has_accept(run, j)) {
    return 0;
  }

  void __arena* buf = run->results.buf;
  if (buf == NULL) {
    run->collect_error = -ENOMEM;
    return 1;
  }
  u32 off = bpfj_heap_clamp_off(run->collect_count * sizeof(u64));
  u64 __arena* result = (u64 __arena*)((char __arena*)buf + off);
  *result = run->map->accept_val[j];
  ++run->collect_count;
  return 0;
}

// Evaluate the NFA and collect each matching pattern's value. This wrapper is
// inline so it does not add a frame to either of the two independent phases.
static __always_inline long bpfj_glob_eval(
    __arena struct bpfj_glob_run* run __arg_arena) {
  bpfj_vec_clear(&run->results);
  long ret = bpfj_vec_reserve(&run->results, run->map->num_accepts);
  if (ret < 0) {
    return ret;
  }
  ret = bpfj_glob_eval_state(run);
  if (ret < 0) {
    return ret;
  }
  run->collect_count = 0;
  run->collect_error = 0;
  struct bpfj_glob_collect_ctx ctx = {
      .run = run,
  };
  ret = bpf_loop(BPFJ_GLOB_MAP_MAX_ACCEPTS, bpfj_glob_collect_result, &ctx, 0);
  if (ret < 0) {
    return ret;
  }
  if (run->collect_error < 0) {
    return run->collect_error;
  }
  run->results.size = run->collect_count;
  return run->collect_count;
}

// Bind a run to the compiled header it will match against and copy in the
// caller's variable bindings, both fixed across lookups.
//
// map:      the arena-resident compiled header (see GlobMap.h); NULL matches
//           nothing.
// bindings: what each ${NAME} gadget resolves its key against; an unbound key
//           matches the empty string, and NULL means no bindings.
static __noinline void bpfj_glob_run_bind(
    struct bpfj_glob_run __arena* run,
    const struct bpfj_glob_map __arena* map,
    const struct bpfj_glob_bindings __arena* bindings) {
  run->map = map;
  run->str = NULL;
  run->len = 0;

  // Word-wise, not a struct assignment: clang lowers that to a memcpy whose
  // destination base folds back to the pre-addr_space_cast scalar. Only the
  // bindings in use, most lookups carrying a handful of the sixteen.
  _Static_assert(
      sizeof(struct bpfj_glob_binding) % 4 == 0 &&
          __builtin_offsetof(struct bpfj_glob_bindings, b) % 4 == 0,
      "bpfj_glob_bindings must be a whole number of u32s to copy word-wise");
  u32 count = 0;
  if (bindings != NULL) {
    count = bindings->count;
    if (count > BPFJ_GLOB_MAP_MAX_BINDINGS) {
      count = BPFJ_GLOB_MAP_MAX_BINDINGS;
    }

    u32 __arena* dst = (__arena u32*)run->bindings.b;
    const u32 __arena* src = (const u32 __arena*)bindings->b;
    u32 words = count * (sizeof(struct bpfj_glob_binding) / 4);
    u32 w = 0;
    bpf_for(w, 0, words) {
      // TODO eliminate copy
      dst[w] = src[w];
    }
  }
  run->bindings.count = count;
}

// Public entry point. References the arena search string for this evaluation;
// matching values remain in run->results until the next evaluation.
//
// run: bound by bpfj_glob_run_bind, and meant to be reused across lookups --
//      its vectors retain arena allocations, and the heap lock is a trylock,
//      so allocating one per lookup would let heap contention read as a miss.
// Returns the match count or a negative errno. A NULL run, or one bound to a
// NULL header, matches nothing rather than dereferencing arena offset 0, which
// reads the heap control struct rather than faulting.
static __always_inline long bpfj_glob_map_lookup(
    struct bpfj_glob_run __arena* run,
    const char __arena* str,
    u32 len) {
  if (run == NULL || run->map == NULL) {
    return 0;
  }

  if (len > BPFJ_GLOB_MAP_MAX_STR_LEN) {
    return -E2BIG;
  }
  if (str == NULL && len != 0) {
    return -EINVAL;
  }
  run->str = str;
  run->len = len;
  return bpfj_glob_eval(run);
}

static __always_inline u64 __arena* bpfj_glob_map_result_at(
    struct bpfj_glob_run __arena* run,
    u32 index) {
  return bpfj_vec_at(&run->results, index);
}

// Reserve run-owned input for a kernel-pointer caller to fill.
static __noinline char __arena* bpfj_glob_run_owned_input(
    struct bpfj_glob_run __arena* run,
    u32 len) {
  if (len > BPFJ_GLOB_MAP_MAX_STR_LEN ||
      bpfj_vec_reserve(&run->owned_str, len) < 0) {
    return NULL;
  }
  run->owned_str.size = len;
  run->str = run->owned_str.buf;
  run->len = len;
  return run->owned_str.buf;
}

static __noinline long
bpfj_glob_run_read_kernel(struct bpfj_glob_run __arena* run, u32 len, u64 src) {
  if (len > BPFJ_GLOB_MAP_MAX_STR_LEN) {
    return -E2BIG;
  }
  char __arena* input = bpfj_glob_run_owned_input(run, len);
  if (input == NULL && len != 0) {
    return -ENOMEM;
  }
  return len == 0 ? 0 : bpfj_heap_read_kernel(input, len, src);
}

// Match one caller-assigned value without materializing unrelated results.
// The caller has already copied the search string into run->str.
static __noinline long
bpfj_glob_map_contains(struct bpfj_glob_run __arena* run, u32 len, u64 wanted) {
  if (run == NULL || run->map == NULL) {
    return 0;
  }
  if (len > BPFJ_GLOB_MAP_MAX_STR_LEN) {
    return -E2BIG;
  }
  if (run->str == NULL && len != 0) {
    return -EINVAL;
  }

  run->len = len;
  long ret = bpfj_glob_eval_state(run);
  if (ret < 0) {
    return ret;
  }

  u32 accepts = run->map->num_accepts;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_ACCEPTS) {
    if (i >= accepts) {
      break;
    }
    if (bpfj_glob_state_has_accept(run, i) &&
        run->map->accept_val[i] == wanted) {
      return 1;
    }
  }
  return 0;
}

// Match only one contiguous range of compiled accepts without collecting or
// scanning matches belonging to other callers sharing the same NFA.
struct bpfj_glob_contains_range_ctx {
  struct bpfj_glob_run __arena* run;
  u32 first;
  u32 count;
  bool matched;
};

static long bpfj_glob_contains_range_result(u32 i, void* data) {
  struct bpfj_glob_contains_range_ctx* ctx = data;
  if (i >= ctx->count) {
    return 1;
  }
  if (bpfj_glob_state_has_accept(ctx->run, ctx->first + i)) {
    ctx->matched = true;
    return 1;
  }
  return 0;
}

static __noinline long bpfj_glob_map_contains_range(
    struct bpfj_glob_run __arena* run,
    u32 len,
    u32 first,
    u32 count) {
  if (run == NULL || run->map == NULL) {
    return 0;
  }
  if (len > BPFJ_GLOB_MAP_MAX_STR_LEN) {
    return -E2BIG;
  }
  if ((run->str == NULL && len != 0) || first > BPFJ_GLOB_MAP_MAX_ACCEPTS ||
      count > BPFJ_GLOB_MAP_MAX_ACCEPTS - first) {
    return 0;
  }
  u32 num_accepts = run->map->num_accepts;
  if (num_accepts > BPFJ_GLOB_MAP_MAX_ACCEPTS || first > num_accepts ||
      count > num_accepts - first) {
    return 0;
  }

  run->len = len;
  long ret = bpfj_glob_eval_state(run);
  if (ret < 0) {
    return ret;
  }

  struct bpfj_glob_contains_range_ctx ctx = {
      .run = run,
      .first = first,
      .count = count,
      .matched = false,
  };
  ret = bpf_loop(count, bpfj_glob_contains_range_result, &ctx, 0);
  if (ret < 0) {
    return ret;
  }
  return ctx.matched;
}

static __always_inline void bpfj_glob_run_destroy(
    struct bpfj_glob_run __arena* run) {
  bpfj_vec_destroy(&run->state);
  bpfj_vec_destroy(&run->var_advance);
  bpfj_vec_destroy(&run->gadgets);
  bpfj_vec_destroy(&run->results);
  bpfj_vec_destroy(&run->owned_str);
  run->map = NULL;
  run->str = NULL;
  run->len = 0;
  run->bindings.count = 0;
}

static __noinline void bpfj_glob_map_destroy(
    __arena struct bpfj_glob_map* map) {
  // Gated on rodata so the verifier prunes the arena code without it.
  if (!bpfj_heap_enabled) {
    return;
  }
  // NULL first: an arena NULL is offset 0, the heap control struct, so this
  // would otherwise free the allocator's own bookkeeping.
  if (map == NULL || map->num_words == 0) {
    return;
  }

  void __arena* base = (void __arena*)bpfj_heap_ctrl;

  bpfj_heap_free(bpfj_glob_ptr_off(base, map->char_mask));
  bpfj_heap_free(bpfj_glob_ptr_off(base, map->star_mask));
  bpfj_heap_free(bpfj_glob_ptr_off(base, map->init_state));
  if (map->num_accepts != 0) {
    bpfj_heap_free(bpfj_glob_ptr_off(base, map->accept_word));
    bpfj_heap_free(bpfj_glob_ptr_off(base, map->accept_bit));
    bpfj_heap_free(bpfj_glob_ptr_off(base, map->accept_val));
  }
  if (map->num_gadgets != 0) {
    bpfj_heap_free(bpfj_glob_ptr_off(base, map->gadget_word));
    bpfj_heap_free(bpfj_glob_ptr_off(base, map->gadget_base));
    bpfj_heap_free(bpfj_glob_ptr_off(base, map->gadget_key));
  }
  if (map->num_vars != 0) {
    bpfj_heap_free(bpfj_glob_ptr_off(base, map->var_keys));
  }

  map->char_mask = NULL;
  map->star_mask = NULL;
  map->init_state = NULL;
  map->accept_word = NULL;
  map->accept_bit = NULL;
  map->accept_val = NULL;
  map->gadget_word = NULL;
  map->gadget_base = NULL;
  map->gadget_key = NULL;
  map->var_keys = NULL;
  map->num_words = 0;
  map->num_accepts = 0;
  map->num_gadgets = 0;
  map->num_vars = 0;
}
