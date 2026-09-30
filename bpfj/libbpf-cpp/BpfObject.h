// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/libbpf.h>

#include <optional>
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/libbpf-cpp/BpfProgram.h"

namespace bpfj::libbpf {

class BpfObject {
 public:
  template <typename T, typename Ctype, typename F>
  class ObjectRange;

  template <typename T, typename CType, typename F>
  class ObjectIterator {
   public:
    bool operator==(const ObjectIterator& other) const noexcept {
      return obj_ == other.obj_ && curr_ == other.curr_;
    }

    ObjectIterator& operator++() noexcept {
      curr_ = next_(obj_, curr_);
      return *this;
    }

    T operator*() noexcept {
      return T(curr_);
    }

   private:
    ObjectIterator(struct bpf_object* obj, CType* curr, F next) noexcept
        : obj_(obj), curr_(curr), next_(next) {}

    struct bpf_object* obj_;
    CType* curr_;
    F next_;

    friend class ObjectRange<T, CType, F>;
  };

  template <typename T, typename Ctype, typename F>
  class ObjectRange {
   public:
    using Iterator = ObjectIterator<T, Ctype, F>;

    Iterator begin() const noexcept {
      return Iterator(obj_, next_(obj_, nullptr), next_);
    }

    Iterator end() const noexcept {
      return Iterator(obj_, nullptr, next_);
    }

   private:
    explicit ObjectRange(struct bpf_object* obj, F next) noexcept
        : obj_(obj), next_(std::forward<F>(next)) {}

    struct bpf_object* obj_;
    F next_;

    friend class BpfObject;
  };

  explicit BpfObject(struct bpf_object* obj) : obj_(obj) {}
  ~BpfObject() = default;

  struct bpf_object* get() {
    return obj_;
  }

  BpfMap findMapByName(const char* name) const noexcept {
    return BpfMap(::bpf_object__find_map_by_name(obj_, name));
  }

  auto forEachMap() noexcept {
    auto next = &::bpf_object__next_map;
    return ObjectRange<BpfMap, struct bpf_map, decltype(next)>(obj_, next);
  }

  BpfProgram findProgramByName(const char* name) const noexcept {
    return BpfProgram(::bpf_object__find_program_by_name(obj_, name));
  }

  auto forEachProgram() noexcept {
    auto next = &::bpf_object__next_program;
    return ObjectRange<BpfProgram, struct bpf_program, decltype(next)>(
        obj_, next);
  }

 private:
  struct bpf_object* obj_;
};

} // namespace bpfj::libbpf
