// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/var/bpf/types_var.h"

static inline const char __arena* bpfj_var_get_name(
    const struct bpfj_var* var) {
  return bpfj_var_name_ptr(var);
}
