// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/heap.h"

static __always_inline void bpfj_mutation_append(
    __u8 domain,
    __u8 operation,
    __u64 key0,
    __u64 key1,
    const struct bpfj_role_id* role,
    const struct bpfj_uuid* pod,
    __u32 object_id,
    __u8 owned) {
  if (!bpfj_heap_enabled) {
    return;
  }

  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  struct bpfj_mutation_journal __arena* journal = ctrl->mutation_journal;
  if (!journal) {
    return;
  }

  __attribute__((cleanup(
      bpfj_lock_guard_cleanup))) struct bpfj_lock_guard journal_lock = {};
#pragma clang loop unroll(disable)
  for (int attempt = 0; attempt < 1024; ++attempt) {
    if (bpfj_lock_trylock(&journal->lock)) {
      journal_lock.lock = &journal->lock;
      break;
    }
  }
  if (!BPFJ_LOCK_IS_ACQUIRED(journal_lock)) {
    journal->failure = BPFJ_MUTATION_JOURNAL_CONTENDED;
    return;
  }
  if (journal->state != BPFJ_MUTATION_JOURNAL_RECORDING) {
    return;
  }

  __u32 index = journal->next;
  if (index >= journal->entries.capacity) {
    journal->failure = BPFJ_MUTATION_JOURNAL_FULL;
    return;
  }
  journal->next = index + 1;
  journal->entries.size = index + 1;
  barrier_var(index);

  struct bpfj_mutation_record __arena* records = journal->entries.buf;
  struct bpfj_mutation_record __arena* record = records + index;
  record->domain = domain;
  record->operation = operation;
  record->owned = owned;
  record->reserved = 0;
  record->key[0] = key0;
  record->key[1] = key1;
  record->object_id = object_id;
  if (role) {
    __builtin_memcpy(&record->role, role, sizeof(*role));
  }
  if (pod) {
    __builtin_memcpy(&record->pod, pod, sizeof(*pod));
  }
  record->committed = 1;
}

static __always_inline void bpfj_mutation_bpf_owner(
    __u8 domain,
    __u8 operation,
    __u64 key,
    const struct bpfj_bpf_owner* owner) {
  bpfj_mutation_append(
      domain,
      operation,
      key,
      0,
      owner ? &owner->role : NULL,
      owner ? &owner->pod : NULL,
      owner ? owner->id : 0,
      owner != NULL);
}

static __always_inline void bpfj_mutation_mq_owner(
    __u8 domain,
    __u8 operation,
    __u64 key0,
    __u64 key1,
    const struct bpfj_mq_owner* owner,
    __u8 owned) {
  bpfj_mutation_append(
      domain,
      operation,
      key0,
      key1,
      owner ? &owner->role : NULL,
      owner ? &owner->pod : NULL,
      0,
      owned);
}

static __always_inline void bpfj_mutation_shm_owner(
    __u8 domain,
    __u8 operation,
    __u64 key0,
    __u64 key1,
    const struct bpfj_shm_owner* owner,
    __u8 owned) {
  bpfj_mutation_append(
      domain,
      operation,
      key0,
      key1,
      owner ? &owner->role : NULL,
      owner ? &owner->pod : NULL,
      0,
      owned);
}
