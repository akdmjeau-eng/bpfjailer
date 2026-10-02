// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// For the errnos the checks below fail with, since
// bpfjailer/enforce/bpf/key_enforce.bpf.c pulls this header in without one.
#include <errno.h>

#include "bpfj/fsverity/bpf/types_fsverity.h"
#include "bpfj/lib/bpf/kfuncs.h"
#include "bpfj/lib/bpf/scratch.h"
#include "bpfj/lib/bpf/types_role.h"

// Included by both trees, which is why it includes neither tree's types.h and
// why bpfj_check_fsverity_pkcs7 takes a role id as bytes: the two spell the
// wrapping struct differently (bpfj_role_id here, role_id internally).

#define BPFJ_SIG_BUF_SIZE 4096 * 4

#define BPFJ_FSVERITY_SHA256_ALG 1
#define BPFJ_FSVERITY_SHA256_DIGEST_SIZE 32
#define BPFJ_FSVERITY_SHA512_ALG 2
#define BPFJ_FSVERITY_SHA512_DIGEST_SIZE 64

// A struct fsverity_digest and its digest bytes, with BPFJ_SEQ_BYTES spare on
// the end for the sequence number a `min-seq` role signs alongside it.
#define BPFJ_FSVERITY_STRUCT_SIZE 80

struct bpfj_sig_buf {
  char buf[BPFJ_SIG_BUF_SIZE];
};

struct bpfj_fsverity_buf {
  char buf[BPFJ_FSVERITY_STRUCT_SIZE];
};

// The key bpfj_key_map is declared with, laid out the same as a pod's role_id
// member in either tree.
struct bpfj_verity_key {
  char id[ROLE_ID_LEN];
};

#ifndef BPFJ_FSVERITY_POLICY_ARENA
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_verity_key);
  __type(value, __u32);
} bpfj_key_map SEC(".maps");

// The lowest sequence number a binary claiming this role may carry, from
// `min-seq` in policy; a role absent from here is not sequence-checked, so
// presence is the opt-in. Nothing in BPF raises it, which makes retiring a
// version a policy change rather than a side effect of a newer binary running.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_verity_key);
  __type(value, __u64);
} bpfj_verity_seq_map SEC(".maps");
#endif

// Both buffers a check needs, in one slot, since they are held over the same
// span and claiming them together removes a failure path.
struct bpfj_fsverity_scratch {
  struct bpfj_fsverity_buf digest;
  struct bpfj_sig_buf sig;
};

extern int bpf_get_fsverity_digest(
    struct file* file,
    const struct bpf_dynptr* digest_p) __ksym;

extern int bpf_verify_pkcs7_signature(
    const struct bpf_dynptr* data_p,
    const struct bpf_dynptr* sig_p,
    struct bpf_key* trusted_keyring) __ksym;

// Signed, as key_serial_t is: a negative serial is how the special keyrings
// are named, KEY_SPEC_SESSION_KEYRING among them.
extern struct bpf_key* bpf_lookup_user_key(s32 serial, u64 flags) __ksym;

extern void bpf_key_put(struct bpf_key* bkey) __ksym;

// Read back the big-endian sequence number at `src`, a byte at a time because
// the source is a char array at an offset the verifier tracks byte-wise.
static __u64 bpfj_get_seq_be(const __u8* src) {
  __u64 seq = 0;
  for (int i = 0; i < BPFJ_SEQ_BYTES; i++) {
    seq = (seq << 8) | src[i];
  }

  return seq;
}

// Split out so the scratch guard has a scope of its own that no early return
// jumps over, and so the claim happens after the caller's two early exits
// rather than on every exec of an unsigned role.
//
// `is_exec` governs whether a sequence number is demanded, not whether one is
// read: a file is checked by both bprm_check and the mmap of its own text
// against the one signature it carries, and demanding one of every executable
// mapping would demand one of every shared object too.
static int bpfj_verify_fsverity_pkcs7(
    struct file* file,
    struct bpf_key* key,
    struct bpfj_fsverity_scratch* scratch,
    bool has_floor,
    __u64 floor,
    bool is_exec,
    enum bpfj_fsverity_reason* reason) {
  struct fsverity_digest* digest = (struct fsverity_digest*)&scratch->digest;
  __builtin_memset(digest, 0, BPFJ_FSVERITY_STRUCT_SIZE);

  struct bpf_dynptr digest_ptr;
  bpf_dynptr_from_mem(digest, BPFJ_FSVERITY_STRUCT_SIZE, 0, &digest_ptr);
  int ret = bpf_get_fsverity_digest(file, &digest_ptr);
  if (ret < 0) {
    // No digest
    *reason = BPFJ_FSVERITY_REASON_NO_DIGEST;
    return ret;
  }

  if (digest->digest_algorithm == BPFJ_FSVERITY_SHA256_ALG &&
      digest->digest_size != BPFJ_FSVERITY_SHA256_DIGEST_SIZE) {
    *reason = BPFJ_FSVERITY_REASON_DIGEST_INVALID;
    return -EBADMSG;
  } else if (
      digest->digest_algorithm == BPFJ_FSVERITY_SHA512_ALG &&
      digest->digest_size != BPFJ_FSVERITY_SHA512_DIGEST_SIZE) {
    *reason = BPFJ_FSVERITY_REASON_DIGEST_INVALID;
    return -EBADMSG;
  }

  const __u32 digest_size = digest->digest_algorithm == BPFJ_FSVERITY_SHA256_ALG
      ? BPFJ_FSVERITY_SHA256_DIGEST_SIZE
      : BPFJ_FSVERITY_SHA512_DIGEST_SIZE;

  __u32 payload_size = digest_size;
  __u64 seq = 0;
  bool have_seq = false;
  if (has_floor) {
    // Straight into the digest's own buffer, just past the digest, so the
    // pair the signature covers is assembled without a copy. Two constant
    // offsets rather than one variable one, bpf_dynptr_from_mem needing a
    // bounded map value.
    struct bpf_dynptr seq_ptr;
    if (digest_size == BPFJ_FSVERITY_SHA256_DIGEST_SIZE) {
      bpf_dynptr_from_mem(
          &digest->digest[BPFJ_FSVERITY_SHA256_DIGEST_SIZE],
          BPFJ_SEQ_BYTES,
          0,
          &seq_ptr);
    } else {
      bpf_dynptr_from_mem(
          &digest->digest[BPFJ_FSVERITY_SHA512_DIGEST_SIZE],
          BPFJ_SEQ_BYTES,
          0,
          &seq_ptr);
    }

    have_seq = bpf_get_file_xattr(file, BPFJ_EXEC_SEQ_XATTR, &seq_ptr) ==
        BPFJ_SEQ_BYTES;

    // Absent is only an answer for a mapping; on exec, falling back to the
    // bare digest would make stripping the xattr a way out of the check.
    if (!have_seq && is_exec) {
      *reason = BPFJ_FSVERITY_REASON_NO_SEQ;
      return -EPERM;
    }

    if (have_seq) {
      seq = digest_size == BPFJ_FSVERITY_SHA256_DIGEST_SIZE
          ? bpfj_get_seq_be(&digest->digest[BPFJ_FSVERITY_SHA256_DIGEST_SIZE])
          : bpfj_get_seq_be(&digest->digest[BPFJ_FSVERITY_SHA512_DIGEST_SIZE]);

      payload_size = digest_size + BPFJ_SEQ_BYTES;
    }
  }

  // Clamped for the verifier, which wants an upper bound on a variable length
  // into a map value.
  if (payload_size > BPFJ_FSVERITY_SHA512_DIGEST_SIZE + BPFJ_SEQ_BYTES) {
    payload_size = BPFJ_FSVERITY_SHA512_DIGEST_SIZE + BPFJ_SEQ_BYTES;
  }

  bpf_dynptr_from_mem(digest->digest, payload_size, 0, &digest_ptr);

  struct bpfj_sig_buf* sig = &scratch->sig;
  struct bpf_dynptr sig_ptr;
  bpf_dynptr_from_mem(sig, sizeof(*sig), 0, &sig_ptr);
  ret = bpf_get_file_xattr(file, BPFJ_EXEC_SIG_XATTR, &sig_ptr);
  if (ret < 0 || ret >= sizeof(*sig) - 1) {
    // no sig xattr
    *reason = BPFJ_FSVERITY_REASON_NO_SIG;
    return ret < 0 ? ret : -EMSGSIZE;
  }

  // Check the signature
  ret = bpf_verify_pkcs7_signature(&digest_ptr, &sig_ptr, key);
  if (ret < 0) {
    *reason = BPFJ_FSVERITY_REASON_SIG_INVALID;
    return ret;
  }

  // Past the signature, where `seq` is known to be the signer's rather than
  // whatever the caller wrote in the xattr. Equal is allowed, the floor being
  // the oldest version a role still accepts, and exec only, since a floor is
  // per role and a role's libraries are signed on their own schedule.
  // `floor` is redundant beside `have_seq`, but the verifier tracks the null
  // check rather than the implication.
  if (has_floor && have_seq && is_exec && seq < floor) {
    *reason = BPFJ_FSVERITY_REASON_SEQ_ROLLBACK;
    return -EPERM;
  }

  return 0;
}

#ifndef BPFJ_FSVERITY_POLICY_ARENA
static int bpfj_check_fsverity_pkcs7(
    struct file* file,
    const char role_id[ROLE_ID_LEN],
    bool is_exec,
    enum bpfj_fsverity_reason* reason) {
  // Check keys
  __u32* key_serial = bpf_map_lookup_elem(&bpfj_key_map, role_id);
  if (!key_serial) {
    // No key for this role
    return 0;
  }

  // We need a key
  struct bpf_key* key = bpf_lookup_user_key(*key_serial, 0);
  if (!key) {
    // The serial no longer resolves, which is the check being unavailable
    // rather than passing; returning 0 would silently disarm the role.
    *reason = BPFJ_FSVERITY_REASON_NO_KEY;
    return -ENOKEY;
  }

  BPFJ_SCRATCH_GUARD(struct bpfj_fsverity_scratch, scratch);
  if (!scratch) {
    // The pool is finite, and the alternative to denying is running a binary
    // whose signature was never looked at.
    *reason = BPFJ_FSVERITY_REASON_NONE_NOMEM;
    bpf_key_put(key);
    return -ENOMEM;
  }

  __u64* floor = bpf_map_lookup_elem(&bpfj_verity_seq_map, role_id);
  const int ret = bpfj_verify_fsverity_pkcs7(
      file, key, scratch, floor != NULL, floor ? *floor : 0, is_exec, reason);
  bpf_key_put(key);
  return ret;
}
#endif

static int bpfj_check_fsverity_pkcs7_policy(
    struct file* file,
    __u32 key_serial,
    bool has_floor,
    __u64 floor,
    bool is_exec,
    enum bpfj_fsverity_reason* reason) {
  if (!key_serial) {
    return 0;
  }

  struct bpf_key* key = bpf_lookup_user_key(key_serial, 0);
  if (!key) {
    *reason = BPFJ_FSVERITY_REASON_NO_KEY;
    return -ENOKEY;
  }

  BPFJ_SCRATCH_GUARD(struct bpfj_fsverity_scratch, scratch);
  if (!scratch) {
    *reason = BPFJ_FSVERITY_REASON_NONE_NOMEM;
    bpf_key_put(key);
    return -ENOMEM;
  }

  const int ret = bpfj_verify_fsverity_pkcs7(
      file, key, scratch, has_floor, floor, is_exec, reason);
  bpf_key_put(key);
  return ret;
}
