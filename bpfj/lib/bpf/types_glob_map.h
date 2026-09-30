// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/var/bpf/types_var.h"

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
#define BPFJ_GLOB_MAP_MAX_STR_LEN 256
// State words, bounded by the 512-byte BPF stack the state lives on during a
// lookup; each word packs multiple patterns, so this holds hundreds of globs.
#define BPFJ_GLOB_MAP_MAX_WORDS 32
#define BPFJ_GLOB_MAP_MAX_RESULTS \
  64 // output vector capacity the matcher bounds
#define BPFJ_GLOB_MAP_MAX_ACCEPTS \
  1024 // total patterns (<= words * patterns/word)
// Gadget width in bits, equal to the max bpfj_var string value length so any
// bound value fits. It trades against gadgets per pattern -- two at this width
// need 78 bits, past the 63 BPFJ_GLOB_MAP_MAX_TOKENS allows -- and one is all
// FileMatchCached needs, compiling each path component into its own pattern.
#define BPFJ_GLOB_MAP_MAX_VAR_LEN (BPFJ_VAR_VAL_LEN - 1)
#define BPFJ_GLOB_MAP_MAX_VARS 64
#define BPFJ_GLOB_MAP_MAX_GADGETS 256
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
  __arena __u32* gadget_var; // [num_gadgets], the variable id matched there
  __u32 num_words;
  __u32 num_accepts; // one per pattern
  __u32 num_gadgets; // one per ${NAME} occurrence
  __u32 num_vars; // distinct variable ids referenced
};
