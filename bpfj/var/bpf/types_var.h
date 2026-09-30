// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#include <cstddef>
#include <cstdio>
#endif

#include <errno.h>

#define BPFJ_VAR_NAME_LEN 16
// Sized for a canonical 36-character UUID plus the NUL. Widening it grows
// bpfj_pod and so bpfj_pod_array, which MetArmor embeds by value and shares by
// fd, so deploy bpfjailerd and MetArmor together. The glob NFA gadget width
// (BPFJ_GLOB_MAP_MAX_VAR_LEN) deliberately does not track this, a 39-wide
// gadget having pushed fs2_enforce over the 6.13 verifier limit.
#define BPFJ_VAR_VAL_LEN 40
#define BPFJ_VAR_MAX 4
#define BPFJ_VAR_MAP_SIZE 16

struct vsock_address {
  __u32 cid;
  __u32 port;
};

// Name of the variable
struct bpfj_var_name {
  char name[BPFJ_VAR_NAME_LEN];
};

// Type of the variable
enum bpfj_var_type {
  BPFJ_VAR_TYPE_UNKNOWN = 0,
  BPFJ_VAR_TYPE_STR = 1,
  BPFJ_VAR_TYPE_VSOCK_ADDR = 2,
};

// A variable set to a value
struct bpfj_var {
  // Identifies the variable more cheaply than a string name would.
  __u32 id;
  // Type of the variable
  __u8 type;
  // Size of the value
  __u8 size;

  __u16 reserved;

  // Union to provide type-safe access to different value types
  union {
    char str_val[BPFJ_VAR_VAL_LEN - 1]; // String values (reserve 1 byte for
                                        // null terminator)
    struct vsock_address vsock_val; // vsock address values
    unsigned char bin_val[BPFJ_VAR_VAL_LEN]; // Binary/raw data values
  } val;
};

struct bpfj_var_array {
  struct bpfj_var vars[BPFJ_VAR_MAX];
  __u8 count;
};

// Set a variable value
inline int bpfj_var_set(
    struct bpfj_var* out,
    __u32 id,
    __u8 type,
    const void* val,
    __u8 size) {
  // str
  if (type == BPFJ_VAR_TYPE_STR && size > BPFJ_VAR_VAL_LEN - 1) {
    return -ERANGE;
  }
  // vsock addr
  if (type == BPFJ_VAR_TYPE_VSOCK_ADDR &&
      size != sizeof(struct vsock_address)) {
    return -EINVAL;
  }
  // bin
  if (size > BPFJ_VAR_VAL_LEN) {
    return -ERANGE;
  }

  out->id = id;
  out->type = type;
  out->size = size;

  switch (type) {
    case BPFJ_VAR_TYPE_STR:
      __builtin_memcpy(out->val.str_val, val, size);
      out->val.str_val[size] = '\0';
      break;
    case BPFJ_VAR_TYPE_VSOCK_ADDR:
      __builtin_memcpy(&out->val.vsock_val, val, size);
      break;
    default:
      __builtin_memcpy(out->val.bin_val, val, size);
      break;
  }

  return 0;
}

// Get a variable value as a string
inline int
bpfj_var_get_str(const struct bpfj_var* var, char* dest, __u8* size) {
  if (var->type != BPFJ_VAR_TYPE_STR) {
    return -EINVAL;
  }

  __builtin_memset(dest, 0, BPFJ_VAR_VAL_LEN);
  __builtin_memcpy(
      dest, var->val.str_val, var->size + 1); // Include null terminator

  if (size) {
    *size = var->size;
  }

  return 0;
}

// Get a variable value as a vsock address
inline int bpfj_var_get_vsock_addr(
    const struct bpfj_var* var,
    struct vsock_address* dest) {
  if (var->type != BPFJ_VAR_TYPE_VSOCK_ADDR) {
    return -EINVAL;
  }

  __builtin_memset(dest, 0, sizeof(struct vsock_address));
  __builtin_memcpy(dest, &var->val.vsock_val, sizeof(struct vsock_address));

  return 0;
}

// Get a variable value as binary data
inline int
bpfj_var_get_bin(const struct bpfj_var* var, unsigned char* dest, __u8* size) {
  __builtin_memset(dest, 0, BPFJ_VAR_VAL_LEN);
  __builtin_memcpy(dest, var->val.bin_val, var->size);

  if (size) {
    *size = var->size;
  }

  return 0;
}

// Serialize a variable to a string
static inline int
bpfj_var_serialize(const struct bpfj_var* var, char* dest, size_t dest_size) {
  switch (var->type) {
    case BPFJ_VAR_TYPE_STR:
      __builtin_memcpy(dest, var->val.str_val, var->size + 1);
      return 0;
    case BPFJ_VAR_TYPE_VSOCK_ADDR:
#ifdef __cplusplus
      snprintf(
          dest,
          dest_size,
          "%u:%u",
          var->val.vsock_val.cid,
          var->val.vsock_val.port);
#else
      BPF_SNPRINTF(
          dest,
          dest_size,
          "%u:%u",
          var->val.vsock_val.cid,
          var->val.vsock_val.port);
#endif
      return 0;
    default:
      return -EINVAL;
  }

  return 0;
}

// Deserialize a variable from a string. Can't be called from bpf
#ifdef __cplusplus
static inline int
bpfj_var_deserialize(const char* src, size_t src_size, struct bpfj_var* var) {
  switch (var->type) {
    case BPFJ_VAR_TYPE_STR:
      if (src_size > BPFJ_VAR_VAL_LEN - 1) {
        return -ERANGE;
      }

      __builtin_memcpy(var->val.str_val, src, src_size);
      var->val.str_val[src_size] = '\0';
      var->size = src_size;

      return 0;
    case BPFJ_VAR_TYPE_VSOCK_ADDR:
      if (sscanf(
              src,
              "%u:%u",
              &var->val.vsock_val.cid,
              &var->val.vsock_val.port) != 2) {
        return -EINVAL;
      }

      var->size = sizeof(struct vsock_address);

      return 0;
    default:
      return -EINVAL;
  }

  return 0;
}
#endif
