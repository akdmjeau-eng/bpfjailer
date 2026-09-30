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

struct bpfj_glob_run {
  // A pointer, not a copy: it and every table it points at are arena-resident.
  __arena const struct bpfj_glob_map* map;
  __u32 len;
  __u32 num_matches;
  // By value, since a plain pointer stashed in arena run state decays to a
  // scalar across the global-function boundary.
  struct bpfj_var_array vars;
  __u64 state[BPFJ_GLOB_MAP_MAX_WORDS];
  __u64 var_advance[BPFJ_GLOB_MAP_MAX_WORDS]; // per-byte gadget advance scratch
  char str[BPFJ_GLOB_MAP_MAX_STR_LEN];
  __u64 results[BPFJ_GLOB_MAP_MAX_RESULTS];
  // Each gadget's resolved variable value, bulk-read once per lookup so the
  // per-byte matching reads a flat buffer.
  __u32 gadget_len[BPFJ_GLOB_MAP_MAX_GADGETS];
  char gadget_val[BPFJ_GLOB_MAP_MAX_GADGETS][BPFJ_GLOB_MAP_MAX_VAR_LEN];
};

static __always_inline __u32
bpfj_glob_ptr_off(void __arena* base, __arena const void* ptr) {
  return (__u32)((unsigned long)ptr - (unsigned long)base);
}

// The bound bpfj_var for a gadget's variable id, or NULL if unbound.
static __always_inline __arena const struct bpfj_var* bpfj_glob_find_var(
    const struct bpfj_var_array __arena* vars,
    __u32 id) {
  u32 count = vars->count;
  for (u32 v = 0; v < BPFJ_VAR_MAX; ++v) {
    if (v >= count) {
      break;
    }
    if (vars->vars[v].id == id) {
      return &vars->vars[v];
    }
  }
  return NULL;
}

// GLOBAL function: resolve every gadget's variable once and copy its string
// value into the gadget scratch. A sibling leaf of
// bpfj_glob_step/bpfj_glob_close, so the verifier charges max() not a sum.
__noinline int bpfj_glob_load_vars(
    __arena struct bpfj_glob_run* run __arg_arena) {
  u32 num_gadgets = run->map->num_gadgets;

  u32 g = 0;
  bpf_for(g, 0, BPFJ_GLOB_MAP_MAX_GADGETS) {
    if (g >= num_gadgets) {
      break;
    }
    u32 vlen = 0;
    __arena const struct bpfj_var* var =
        bpfj_glob_find_var(&run->vars, run->map->gadget_var[g]);
    if (var != NULL && var->type == BPFJ_VAR_TYPE_STR) {
      vlen = var->size;
      // A value longer than the gadget is truncated, and the gadget then
      // expects end-of-component, so bind long values with a trailing wildcard
      // ("$LONG*").
      if (vlen > BPFJ_GLOB_MAP_MAX_VAR_LEN) {
        vlen = BPFJ_GLOB_MAP_MAX_VAR_LEN;
      }
      // Not unrolled, so the copy spills no temporaries onto this frame.
#pragma clang loop unroll(disable)
      for (u32 k = 0; k < BPFJ_GLOB_MAP_MAX_VAR_LEN; ++k) {
        run->gadget_val[g][k] = var->val.str_val[k];
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

// GLOBAL function: initialize state, run the single pass over the input, and
// collect each matching pattern's value into the run state.
__noinline long bpfj_glob_eval(__arena struct bpfj_glob_run* run __arg_arena) {
  u32 num_words = run->map->num_words;

  // A separate frame, to stay within the bpf2bpf stack budget.
  bpfj_glob_load_vars(run);

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
// map:  the arena-resident compiled header (see GlobMap.h); NULL matches
//       nothing.
// vars: bindings each ${NAME} gadget resolves its variable id against; an
//       unbound id matches the empty string, and NULL means no bindings.
static __noinline void bpfj_glob_run_bind(
    struct bpfj_glob_run __arena* run,
    const struct bpfj_glob_map __arena* map,
    const struct bpfj_var_array __arena* vars) {
  run->map = map;

  // Word-wise, not a struct assignment: clang lowers that to a memcpy whose
  // destination base folds back to the pre-addr_space_cast scalar. u32 words
  // because bpfj_var is only 4-byte aligned.
  _Static_assert(
      (BPFJ_VAR_MAX * sizeof(struct bpfj_var)) % 4 == 0,
      "bpfj_var array must be a whole number of u32s to copy word-wise");
  if (vars != NULL) {
    u32 __arena* dst = (__arena u32*)run->vars.vars;
    const u32* src = (const u32*)vars->vars;
    for (u32 w = 0; w < (BPFJ_VAR_MAX * sizeof(struct bpfj_var)) / 4; ++w) {
      // TODO eliminate copy
      dst[w] = src[w];
    }
    run->vars.count = vars->count;
  } else {
    run->vars.count = 0;
  }
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
    bpfj_heap_free(bpfj_glob_ptr_off(base, map->gadget_var));
  }

  map->char_mask = NULL;
  map->star_mask = NULL;
  map->init_state = NULL;
  map->accept_word = NULL;
  map->accept_bit = NULL;
  map->accept_val = NULL;
  map->gadget_word = NULL;
  map->gadget_base = NULL;
  map->gadget_var = NULL;
  map->num_words = 0;
  map->num_accepts = 0;
  map->num_gadgets = 0;
  map->num_vars = 0;
}
