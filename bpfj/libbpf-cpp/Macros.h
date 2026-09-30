// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <memory>
#include <type_traits>
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfMap.h"

namespace bpfj::libbpf::detail {

template <typename T>
concept IsSmartPointer = requires(T t) {
  typename T::element_type;
  *t;
};

template <IsSmartPointer T>
typename T::element_type& getRef(T& ptr) {
  return *ptr;
}

template <typename T, typename... Args>
T& getRef(T& ref, Args&&... /*unused*/) {
  static_assert(
      sizeof...(Args) == 0,
      "Args... only exists to lower the priority of this function");
  return ref;
}

} // namespace bpfj::libbpf::detail

// Extract a BpfMap from a skeleton object's maps struct, taking either
// BpfSkel<T>& or shared_ptr<BpfSkel<T>>.
//
// Rooted at `::libbpf`, because this expands wherever the caller writes it and
// the closed source tree has a `bpfjailer::libbpf` an unrooted expansion inside
// `namespace bpfjailer` would bind to.
#define BPFJ_GET_MAP(obj, MAP_NAME)                    \
  ({                                                   \
    auto& ref__ = ::bpfj::libbpf::detail::getRef(obj); \
    ::bpfj::libbpf::BpfMap(ref__.maps().MAP_NAME);     \
  })

// Get the address of a link pointer from a skeleton object's links struct.
// Returns bpf_link** which survives skeleton reattach.
#define BPFJ_GET_LINK(obj, LINK_NAME)                  \
  ({                                                   \
    auto& ref__ = ::bpfj::libbpf::detail::getRef(obj); \
    ::bpfj::libbpf::BpfLink(ref__.links().LINK_NAME);  \
  })
