// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/var/VarManager.h"

#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "bpfj/libbpf-cpp/Conv.h"
#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

err::Expected<std::uint32_t> VarManager::id(std::string_view name) {
  if (name.size() >= BPFJ_VAR_NAME_LEN) {
    return err::Error(
        std::errc::invalid_argument,
        "Name " + std::string(name) + " of len " + std::to_string(name.size()) +
            " is too long to be a bpfj variable name");
  }

  std::unique_lock lock{varsMutex_};
  auto pair = vars_.emplace(name, nextId_);
  if (pair.second) {
    // Insertion happened, increment nextId
    ++nextId_;
  }

  return pair.first->second;
}

err::Expected<> VarManager::resize() {
  if (!namesMap_) {
    return err::Error(
        std::errc::invalid_argument, "Resize before the var map was set");
  }

  if (auto res = namesMap_->setMaxEntries(nextId_); !res) {
    return err::Error(res.error().code(), "Failed to resize var map");
  }

  return err::unit;
}

err::Expected<> VarManager::update() {
  if (!namesMap_) {
    return err::Error(
        std::errc::invalid_argument, "Update before the var map was set");
  }

  std::unique_lock lock{varsMutex_};
  std::unordered_map<std::uint32_t, std::string> rev;
  for (auto& [name, id] : vars_) {
    rev.emplace(id, name);
  }
  auto updateRes = namesMap_->updateBatch(
      std::move(rev),
      bpfj::libbpf::conv::ToSame<std::uint32_t>(),
      bpfj::libbpf::conv::
          ToString<struct bpfj_var_name, sizeof(bpfj_var_name::name)>());
  if (!updateRes) {
    return err::Error(updateRes.error().code(), "Failed to update var map");
  }

  return err::unit;
}

err::Expected<std::string> VarManager::name(std::uint32_t id) {
  // The published BPF names map is authoritative where it exists, so a stale
  // in-memory table cannot shadow it; the fallback is for pod-log
  // write/replay/restore and unit tests, which resolve names pre-load. Either
  // way an id with no published name is an error rather than an empty
  // string.
  if (namesMap_) {
    auto name = namesMap_->lookupElem<struct bpfj_var_name>(id);
    if (!name) {
      return err::Error(
          name.error().code(),
          "Failed to lookup var name for id " + std::to_string(id));
    }
    return std::string(name->name, ::strnlen(name->name, BPFJ_VAR_NAME_LEN));
  }

  std::shared_lock lock{varsMutex_};
  for (const auto& [name, varId] : vars_) {
    if (varId == id) {
      return name;
    }
  }
  return err::Error(
      std::errc::invalid_argument,
      "No published name for var id " + std::to_string(id) +
          ": register it before logging");
}

} // namespace bpfjailer
