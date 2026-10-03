// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/types_glob_map.h"
#include "bpfj/lib/bpf/types_heap.h"

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
// The matcher is split into GLOBAL functions so the verifier checks each once,
// and both the compiled header (see GlobMap.h) and the per-run state live on
// the arena, keeping ~8 KiB off the 512-byte BPF stack.

static __always_inline __u32
bpfj_glob_ptr_off(void __arena* base, __arena const void* ptr) {
  return (__u32)((unsigned long)ptr - (unsigned long)base);
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
    __arena struct bpfj_glob_run* run,
    u32 g) {
  // Path components cannot contain NUL, so a full-width NUL string makes the
  // gadget impossible to satisfy and keeps malformed bindings fail closed.
  run->gadget_len[g] = BPFJ_GLOB_MAP_MAX_VAR_LEN;
  bpfj_heap_zero_arena(run->gadget_val[g], BPFJ_GLOB_MAP_MAX_VAR_LEN);
}

// GLOBAL function: resolve every gadget's binding once and copy its value into
// the gadget scratch. A sibling leaf of bpfj_glob_step/bpfj_glob_close, so the
// verifier charges max() not a sum.
__noinline int bpfj_glob_load_bindings(
    __arena struct bpfj_glob_run* run __arg_arena) {
  u32 num_gadgets = run->map->num_gadgets;

  u32 g = 0;
  bpf_for(g, 0, BPFJ_GLOB_MAP_MAX_GADGETS) {
    if (g >= num_gadgets) {
      break;
    }
    u32 vlen = 0;
    __arena const struct bpfj_glob_binding* binding =
        bpfj_glob_find_binding(&run->bindings, run->map->gadget_key[g]);
    if (binding != NULL) {
      vlen = binding->len;
      if (vlen > BPFJ_GLOB_MAP_MAX_VAR_LEN) {
        bpfj_glob_poison_binding(run, g);
        continue;
      }
      // Not unrolled, so the copy spills no temporaries onto this frame.
#pragma clang loop unroll(disable)
      for (u32 k = 0; k < BPFJ_GLOB_MAP_MAX_VAR_LEN; ++k) {
        run->gadget_val[g][k] = binding->val[k];
      }
    }
    run->gadget_len[g] = vlen;
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
      u32 vlen = run->gadget_len[g];
      u32 post = (base + vlen) & 63;
      u32 exit = (base + BPFJ_GLOB_MAP_MAX_VAR_LEN) & 63;
      if (((run->state[word] >> post) & 1ULL) != 0) {
        run->state[word] |= 1ULL << exit;
      }
    }

    // '*' epsilon: a star may also match the empty string and advance one bit.
    u32 w = 0;
    bpf_for(w, 0, BPFJ_GLOB_MAP_MAX_WORDS) {
      if (w >= num_words) {
        break;
      }
      run->state[w] |= (run->state[w] & run->map->star_mask[w]) << 1;
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
    run->var_advance[w] = 0;
  }
  u32 g = 0;
  bpf_for(g, 0, BPFJ_GLOB_MAP_MAX_GADGETS) {
    if (g >= num_gadgets) {
      break;
    }
    u32 word = run->map->gadget_word[g] & (BPFJ_GLOB_MAP_MAX_WORDS - 1);
    u32 base = run->map->gadget_base[g];
    u32 vlen = run->gadget_len[g];
    // Constant-bound and break-free so clang unrolls it rather than nesting a
    // loop the verifier would explore combinatorially.
    for (u32 k = 0; k < BPFJ_GLOB_MAP_MAX_VAR_LEN; ++k) {
      if (k < vlen && (u8)run->gadget_val[g][k] == ch) {
        run->var_advance[word] |= 1ULL << ((base + k) & 63);
      }
    }
  }

  // Literal/'?'/variable tokens that match ch move one bit; '*' tokens consume
  // ch and stay.
  bpf_for(w, 0, BPFJ_GLOB_MAP_MAX_WORDS) {
    if (w >= num_words) {
      break;
    }
    u64 cur = run->state[w];
    if (cur == 0) {
      continue;
    }
    u64 cm = char_mask[(u32)ch * num_words + w] | run->var_advance[w];
    run->state[w] = ((cur & cm) << 1) | (cur & star_mask[w]);
  }

  // bpfj_glob_eval calls the closure separately, keeping the two siblings.
  return 0;
}

// GLOBAL function: initialize state and run the single pass over the input.
__noinline long bpfj_glob_eval_state(
    __arena struct bpfj_glob_run* run __arg_arena) {
  u32 num_words = run->map->num_words;

  // A separate frame, to stay within the bpf2bpf stack budget.
  bpfj_glob_load_bindings(run);

  // Every slot, so later reads are definitely initialized for the verifier.
  u32 w = 0;
  bpf_for(w, 0, BPFJ_GLOB_MAP_MAX_WORDS) {
    u64 v = 0;
    if (w < num_words) {
      v = run->map->init_state[w];
    }
    run->state[w] = v;
  }

  // For a pattern starting with an empty ${NAME} or a '*'.
  bpfj_glob_close(run);

  u32 len = run->len;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_STR_LEN) {
    if (i >= len) {
      break;
    }
    bpfj_glob_step(run, (u8)run->str[i]);
    bpfj_glob_close(run);
  }

  return 0;
}

// GLOBAL function: evaluate the NFA and collect each matching pattern's value.
__noinline long bpfj_glob_eval(__arena struct bpfj_glob_run* run __arg_arena) {
  long ret = bpfj_glob_eval_state(run);
  if (ret < 0) {
    return ret;
  }

  // Stopping once the result buffer is full bounds `count` and lets the
  // verifier converge, so at most BPFJ_GLOB_MAP_MAX_RESULTS are reported.
  long count = 0;
  u32 j = 0;
  bpf_for(j, 0, BPFJ_GLOB_MAP_MAX_ACCEPTS) {
    if (j >= run->map->num_accepts || count >= BPFJ_GLOB_MAP_MAX_RESULTS) {
      break;
    }
    u32 aw = run->map->accept_word[j] & (BPFJ_GLOB_MAP_MAX_WORDS - 1);
    u32 bit = run->map->accept_bit[j] & 63;
    if (((run->state[aw] >> bit) & 1ULL) != 0) {
      run->results[count] = run->map->accept_val[j];
      ++count;
    }
  }

  run->num_matches = (u32)count;
  return count;
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

// Public entry point. Copies the search string into the run, runs the matcher,
// and copies matching values into
// out[0..min(matches, BPFJ_GLOB_MAP_MAX_RESULTS)).
//
// run: bound by bpfj_glob_run_bind, and meant to be reused across lookups --
//      it is several KiB of arena, and the heap lock is a trylock, so
//      allocating one per lookup would let heap contention read as a miss.
// out: must be at least BPFJ_GLOB_MAP_MAX_RESULTS wide.
//
// Returns the match count or a negative errno. A NULL run, or one bound to a
// NULL header, matches nothing rather than dereferencing arena offset 0, which
// reads the heap control struct rather than faulting.
static __noinline long bpfj_glob_map_lookup(
    struct bpfj_glob_run __arena* run,
    const char __arena* str,
    u32 len,
    u64 __arena* out) {
  if (run == NULL || run->map == NULL) {
    return 0;
  }

  if (len > BPFJ_GLOB_MAP_MAX_STR_LEN) {
    len = BPFJ_GLOB_MAP_MAX_STR_LEN;
  }
  run->len = len;

  u32 i = 0;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_STR_LEN) {
    if (i >= len) {
      break;
    }

    // TODO get rid of copy
    run->str[i] = str[i];
  }

  long count = bpfj_glob_eval(run);

  u32 n = count < 0 ? 0 : (u32)count;
  if (n > BPFJ_GLOB_MAP_MAX_RESULTS) {
    n = BPFJ_GLOB_MAP_MAX_RESULTS;
  }
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_RESULTS) {
    if (i >= n) {
      break;
    }

    // TODO: copy again
    out[i] = run->results[i];
  }

  return count;
}

// Match one caller-assigned value without truncating at the result-vector
// capacity, so several patterns carrying the same policy id remain exact.
// The caller has already copied the search string into run->str.
static __noinline long
bpfj_glob_map_contains(struct bpfj_glob_run __arena* run, u32 len, u64 wanted) {
  if (run == NULL || run->map == NULL || len > BPFJ_GLOB_MAP_MAX_STR_LEN) {
    return 0;
  }

  run->len = len;
  long ret = bpfj_glob_eval(run);
  if (ret < 0) {
    return ret;
  }

  u32 accepts = run->map->num_accepts;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_ACCEPTS) {
    if (i >= accepts) {
      break;
    }
    u32 word = run->map->accept_word[i] & (BPFJ_GLOB_MAP_MAX_WORDS - 1);
    u32 bit = run->map->accept_bit[i] & 63;
    if (((run->state[word] >> bit) & 1ULL) != 0 &&
        run->map->accept_val[i] == wanted) {
      return 1;
    }
  }
  return 0;
}

// Match only one contiguous range of compiled accepts without collecting or
// scanning matches belonging to other callers sharing the same NFA.
static __noinline long bpfj_glob_map_contains_range(
    struct bpfj_glob_run __arena* run,
    u32 len,
    u32 first,
    u32 count) {
  if (run == NULL || run->map == NULL || len > BPFJ_GLOB_MAP_MAX_STR_LEN ||
      first > run->map->num_accepts || count > run->map->num_accepts - first) {
    return 0;
  }

  run->len = len;
  long ret = bpfj_glob_eval_state(run);
  if (ret < 0) {
    return ret;
  }

  u32 i = 0;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_ACCEPTS) {
    if (i >= count) {
      break;
    }
    u32 accept = first + i;
    u32 word = run->map->accept_word[accept] & (BPFJ_GLOB_MAP_MAX_WORDS - 1);
    u32 bit = run->map->accept_bit[accept] & 63;
    if (((run->state[word] >> bit) & 1ULL) != 0) {
      return 1;
    }
  }
  return 0;
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
