// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/libbpf.h>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "bpfj/err/StdExpected.h"
#include "bpfj/libbpf-cpp/BpfMap.h"
#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

// Singleton for managing bpfj variables. All variables must be set before init
// is called, only because bpfjailer config and programs are generally immutable
// once loaded -- nothing stops dynamic add/remove.
class VarManager {
 public:
  VarManager() = default;

  // Add or get a variable, returning its id or an error if the name is too
  // long.
  [[nodiscard]] err::Expected<std::uint32_t> id(std::string_view name);

  void setMaps(struct bpf_map* varMap) {
    namesMap_.emplace(varMap);
  }

  err::Expected<> resize();

  err::Expected<> update();

  std::uint32_t getVariableCount() const {
    std::shared_lock lock{varsMutex_};
    return static_cast<std::uint32_t>(vars_.size());
  }

  err::Expected<std::string> name(std::uint32_t id);

 private:
  // A shared_mutex beside the map rather than around it: the tree carries no
  // Synchronized, and the locking is three call sites deep.
  mutable std::shared_mutex varsMutex_;
  std::unordered_map<std::string, std::uint32_t> vars_;
  std::optional<bpfj::libbpf::BpfMap> namesMap_;
  std::uint32_t nextId_ = 1;
};

} // namespace bpfjailer
