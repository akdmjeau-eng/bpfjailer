// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// The shape of the scratch pool, split from scratch.h because that file
// declares BPF maps and cannot be included from userspace.
//
// Two size classes, because the two callers are nothing alike: the pod
// assembled on exec is 512 bytes and every exec on the host claims one, while
// the fs-verity digest and signature pair is 16456 bytes and is only claimed
// for a role that names a certificate. With one class, a loop of 130
// verifications against a busy host intermittently emptied the pool and
// denied a binary that verifies.

//
// How many of each, and why these are not small numbers.
//
// A slot is held for the span of one hook call, so the count has to cover the
// calls that can be in flight at once. That is not the CPU count: these hooks
// are sleepable, and a task parked in bpf_get_file_xattr holds its slot while
// another runs on the same CPU, so in-flight calls can exceed cores by the
// depth of whatever is blocking. A host with hundreds of cores forking hard
// is the case to size for, and 40 large slots was not it.
//
// Sizing matters more than it used to: running out now denies rather than
// degrading. bpfj_jailer_exec refuses an exec it cannot enroll, because
// letting it through would run the binary without the role its xattr names,
// and bpfj_check_fsverity_pkcs7 refuses a signature it cannot check. Both are
// the right answer to a failed claim and both are outages if the pool is
// routinely empty, so the pool is sized to make that the rare case.
//
// What used to cap these was not memory but the verifier. The counts are the
// bound on the scan in bpfj_scratch_claim(), and a plain loop is walked
// iteration by iteration, so 2048 small slots took bpfj_jailer_exec over the
// instruction budget: "BPF program is too large. Processed 1000001 insn".
// That scan is a bpf_for now, walked once whatever the bound, so memory is
// the only thing these trade against again.
//

// 512 for the pod, with room for the next small thing that needs one. Claimed
// by every exec on the host, so this is the one that has to be deep.
#define BPFJ_SCRATCH_SMALL_SIZE 1024
#define BPFJ_SCRATCH_SMALL_SLOTS 2048

// 16456 for the fs-verity pair, rounded up for legibility. Only claimed for a
// role that names a certificate, so shallower than the small class and still
// six times what it was.
#define BPFJ_SCRATCH_LARGE_SIZE 16640
#define BPFJ_SCRATCH_LARGE_SLOTS 256

// 2048 * 1024 + 256 * 16640 = 6356992, about 6MB against the 1MB this was --
// the price of denying on exhaustion, which needs a pool a busy host does not
// reach the end of.
#define BPFJ_SCRATCH_BYTES                              \
  (BPFJ_SCRATCH_SMALL_SIZE * BPFJ_SCRATCH_SMALL_SLOTS + \
   BPFJ_SCRATCH_LARGE_SIZE * BPFJ_SCRATCH_LARGE_SLOTS)

#define BPFJ_SCRATCH_SMALL_WORDS ((BPFJ_SCRATCH_SMALL_SLOTS + 63) / 64)
#define BPFJ_SCRATCH_LARGE_WORDS ((BPFJ_SCRATCH_LARGE_SLOTS + 63) / 64)

// Set in a slot handle to say which class it came from, so free knows which
// bitmap to clear without the caller having to remember.
#define BPFJ_SCRATCH_LARGE_TAG 0x80000000U

// No slot. What the guard holds when the pool had nothing left, and what
// bpfj_scratch_free ignores.
#define BPFJ_SCRATCH_NONE 0xffffffffU
