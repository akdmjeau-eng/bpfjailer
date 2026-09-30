// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// Shared by both trees because both build a pod on it, and because
// bpfj/fsverity/bpf/fsverity.h keys bpfj_key_map on it and cannot reach
// either tree's types.h. The struct wrapping the id is not shared: this tree
// spells it bpfj_role_id, the internal one role_id.
#define ROLE_ID_LEN 16
