// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// The fs-verity definitions both trees share. fsverity.h is included by
// either tree, so it can include neither tree's types.h nor lean on the
// including file to have done so, clang-format sorting bpfj/fsverity/bpf/
// ahead of bpfjailer/.

#define BPFJ_EXEC_SIG_XATTR "user.bpfj.sig"

// The binary's sequence number, 8 bytes big-endian, for a role carrying
// `min-seq`. Safe in an xattr fs-verity does not cover only because it is
// signed over; see bpfj_check_fsverity_pkcs7.
#define BPFJ_EXEC_SEQ_XATTR "user.bpfj.seq"
#define BPFJ_SEQ_BYTES 8

// Why a signature check did not pass, carried out of
// bpfj_check_fsverity_pkcs7 alongside its pass/fail return value.
enum bpfj_fsverity_reason {
  BPFJ_FSVERITY_REASON_NONE = 0,
  BPFJ_FSVERITY_REASON_NONE_NOMEM = 1,
  BPFJ_FSVERITY_REASON_NO_KEY = 2,
  BPFJ_FSVERITY_REASON_NO_DIGEST = 3,
  BPFJ_FSVERITY_REASON_NO_SIG = 4,
  BPFJ_FSVERITY_REASON_SIG_INVALID = 5,
  BPFJ_FSVERITY_REASON_DIGEST_INVALID = 6,
  BPFJ_FSVERITY_REASON_NO_SEQ = 7,
  BPFJ_FSVERITY_REASON_SEQ_ROLLBACK = 8,
};
