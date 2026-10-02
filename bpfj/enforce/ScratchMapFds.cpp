// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/ScratchMapFds.h"

#include <fcntl.h>

#include <array>

#include "bpfj/libbpf-cpp/BpfSkelBase.h"

namespace bpfjailer {

Expected<ScratchMapFds> ScratchMapFds::duplicateFrom(
    bpfj::libbpf::BpfSkelBase& skel) noexcept {
  std::array<Fd, kMapNames.size()> fds;
  for (std::size_t i = 0; i < kMapNames.size(); ++i) {
    const char* const name = kMapNames[i];
    auto map = skel.getMap(name);
    if (!map) {
      return makeUnexpected(makeError(
          std::errc::no_such_file_or_directory, "no map named ", name));
    }

    const int fd = ::fcntl(map->fd(), F_DUPFD_CLOEXEC, 0);
    if (fd < 0) {
      return makeUnexpected(
          makeErrnoError("failed to duplicate BPF map ", name));
    }
    fds[i] = Fd(fd);
  }

  return ScratchMapFds(std::move(fds));
}

Expected<> ScratchMapFds::reuseIn(
    bpfj::libbpf::BpfSkelBase& skel) const noexcept {
  for (std::size_t i = 0; i < kMapNames.size(); ++i) {
    const char* const name = kMapNames[i];
    auto map = skel.getMap(name);
    if (!map) {
      return makeUnexpected(makeError(
          std::errc::no_such_file_or_directory, "no map named ", name));
    }

    if (auto res = map->reuseFd(fds_[i].get()); !res) {
      return res;
    }
  }

  return unit;
}

} // namespace bpfjailer
