// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/libbpf.h>
#include <optional>
#include "bpfj/libbpf-cpp/BpfObject.h"
#include "bpfj/libbpf-cpp/Err.h"

namespace bpfj::libbpf {

class BpfSkelBase {
 public:
  struct OpenOpts {
    OpenOpts() noexcept : opts_{} {
      opts_.sz = sizeof(opts_);
    }

    // TODO wrap the rest of the options
    struct bpf_object_open_opts opts_;
  };

  BpfSkelBase() noexcept = default;
  virtual ~BpfSkelBase() noexcept = default;

  BpfSkelBase(const BpfSkelBase&) = delete;
  BpfSkelBase& operator=(const BpfSkelBase&) = delete;
  BpfSkelBase(BpfSkelBase&&) noexcept = default;
  BpfSkelBase& operator=(BpfSkelBase&&) noexcept = default;

  [[nodiscard]] virtual Expected<> open(
      const std::optional<OpenOpts>& opts = {}) noexcept = 0;

  [[nodiscard]] virtual Expected<> load() noexcept = 0;

  [[nodiscard]] virtual Expected<> openAndLoad() noexcept = 0;

  [[nodiscard]] virtual Expected<> attach() noexcept = 0;

  virtual void detach() noexcept = 0;

  virtual void destroy() noexcept = 0;

  virtual BpfObject obj() noexcept = 0;

  const char* name() noexcept {
    return ::bpf_object__name(obj().get());
  }

  std::optional<BpfMap> getMap(const char* name) noexcept {
    auto map = obj().findMapByName(name);
    if (!map.get()) {
      return std::nullopt;
    }
    return map;
  }

  std::optional<BpfProgram> getProg(const char* name) noexcept {
    auto prog = obj().findProgramByName(name);
    if (!prog.get()) {
      return std::nullopt;
    }
    return prog;
  }

  template <typename MapType>
  Expected<> tryReuseMapFd(const MapType& map) noexcept {
    auto found = obj().findMapByName(map.name());
    if (!found.get()) {
      return unit;
    }
    return found.reuseFd(map.fd());
  }
};

} // namespace bpfj::libbpf
