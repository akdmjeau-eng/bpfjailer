// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpfj/lib/bpf/types_heap.h"

// Glob matcher map. Userspace compiles all glob patterns into a SINGLE
// bit-parallel NFA, so a lookup evaluates every pattern in one pass over the
// input, writing each matching pattern's value into a caller-supplied vector.
//
// V1 supports four token kinds: a literal byte, '?' (any single byte), '*'
// (any sequence, including empty), and a variable reference ${NAME} matching
// the value bound to NAME at lookup. Consecutive '*' are collapsed at compile
// time, and a ${NAME} compiles to a fixed-width "gadget" of
// BPFJ_GLOB_MAP_MAX_VAR_LEN bit positions reserved inline in the pattern, so
// it is absent from the static char/star masks and filled on the fly.
//
// Each pattern compiles to m tokens in a contiguous bit range [base, base+m]
// within one 64-bit word, the last being the accept bit, which carries no
// token and so also guards against the NFA's left-shift leaking into the next
// pattern. A word's state is a u64 where bit p means "the input so far can
// leave us about to match the token at bit p". Two compiled tables drive the
// per-byte transition: char_mask[c * num_words + w] has bit p set when that
// token is '?' or the literal c, and star_mask[w] when it is '*';
// init_state[w] holds each pattern's base bit with the leading-'*' closure
// already applied.

#define BPFJ_GLOB_MAP_MAX_TOKENS \
  63 // per pattern; a pattern needs m+1 <= 64 bits
#define BPFJ_GLOB_MAP_MAX_STR_LEN 1024
// State words live in a per-run arena vec, so the limit bounds work rather
// than preallocated memory. Each word packs multiple patterns.
#define BPFJ_GLOB_MAP_MAX_WORDS 512
#define BPFJ_GLOB_MAP_MAX_ACCEPTS \
  4096 // total patterns (<= words * patterns/word)
// Gadget width in bits, and so the longest value a binding can match in full.
// It trades against gadgets per pattern -- two at this width need 78 bits, past
// the 63 BPFJ_GLOB_MAP_MAX_TOKENS allows -- and one is all FileMatchCached
// needs, compiling each path component into its own pattern. A var type whose
// values can be longer has to reject them before binding; malformed oversize
// bindings are treated as impossible matches rather than truncated prefixes.
#define BPFJ_GLOB_MAP_MAX_VAR_LEN 39
// Distinct ${NAME} keys one map may reference, and so the bindings a lookup
// carries.
#define BPFJ_GLOB_MAP_MAX_BINDINGS 16
#define BPFJ_GLOB_MAP_MAX_GADGETS 512
// Epsilon-closure passes needed to reach a fixpoint. Collapsing consecutive
// '*' and closing adjacent gadgets in one ascending sweep leaves only
// '*'<->gadget alternation, bounded by the gadgets that fit in one word + 1.
#define BPFJ_GLOB_MAP_CLOSE_ITERS \
  ((BPFJ_GLOB_MAP_MAX_TOKENS / BPFJ_GLOB_MAP_MAX_VAR_LEN) + 1)

struct bpfj_glob_map {
  __arena __u64* char_mask; // [256 * num_words]
  __arena __u64* star_mask; // [num_words]
  __arena __u64* init_state; // [num_words]
  __arena __u32* accept_word; // [num_accepts], the state word of each pattern
  __arena __u32* accept_bit; // [num_accepts], the accept bit within that word
  __arena __u64* accept_val; // [num_accepts], the pattern's value
  __arena __u32* gadget_word; // [num_gadgets], the state word of each gadget
  __arena __u32* gadget_base; // [num_gadgets], the gadget's first (state-0) bit
  __arena __u32* gadget_key; // [num_gadgets], the binding key matched there
  __arena __u32* var_keys; // [num_vars], each distinct key, ascending
  __u32 num_words;
  __u32 num_accepts; // one per pattern
  __u32 num_gadgets; // one per ${NAME} occurrence
  __u32 num_vars; // distinct binding keys referenced
};

// What the matcher knows of variables: a key the compiler assigned to ${NAME},
// never 0, and the bytes that name stands for in this lookup. The key is
// whatever the caller's var type identifies a variable by, and a converter
// from that type fills these in, so nothing here depends on how vars are
// stored. A key with no binding matches the empty string.
struct bpfj_glob_binding {
  __u32 key;
  __u32 len;
  char val[BPFJ_GLOB_MAP_MAX_VAR_LEN];
};

struct bpfj_glob_bindings {
  __u32 count;
  __u32 _pad;
  struct bpfj_glob_binding b[BPFJ_GLOB_MAP_MAX_BINDINGS];
};

struct bpfj_glob_gadget_run {
  __u32 len;
  char val[BPFJ_GLOB_MAP_MAX_VAR_LEN];
};

struct bpfj_glob_run {
  __arena const struct bpfj_glob_map* map;
  __arena const char* str;
  __u32 len;
  __u32 _pad;
  struct bpfj_glob_bindings bindings;
  struct bpfj_vec state;
  struct bpfj_vec var_advance;
  struct bpfj_vec gadgets;
  struct bpfj_vec results;
  struct bpfj_vec owned_str;
  __u32 collect_count;
  int collect_error;
};

// Initialize only the vec headers; their buffers grow on the first lookup.
static inline void bpfj_glob_run_init(struct bpfj_glob_run __arena* run) {
  run->map = NULL;
  run->str = NULL;
  run->len = 0;
  run->_pad = 0;
  run->bindings.count = 0;
  run->bindings._pad = 0;

  run->state.buf = NULL;
  run->state.elem_size = sizeof(__u64);
  run->state.size = 0;
  run->state.capacity = 0;
  run->state._pad = 0;

  run->var_advance.buf = NULL;
  run->var_advance.elem_size = sizeof(__u64);
  run->var_advance.size = 0;
  run->var_advance.capacity = 0;
  run->var_advance._pad = 0;

  run->gadgets.buf = NULL;
  run->gadgets.elem_size = sizeof(struct bpfj_glob_gadget_run);
  run->gadgets.size = 0;
  run->gadgets.capacity = 0;
  run->gadgets._pad = 0;

  run->results.buf = NULL;
  run->results.elem_size = sizeof(__u64);
  run->results.size = 0;
  run->results.capacity = 0;
  run->results._pad = 0;

  run->owned_str.buf = NULL;
  run->owned_str.elem_size = sizeof(char);
  run->owned_str.size = 0;
  run->owned_str.capacity = 0;
  run->owned_str._pad = 0;
  run->collect_count = 0;
  run->collect_error = 0;
}
