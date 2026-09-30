// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <fcntl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <compare>
#include "bpfj/err/Error.h"

namespace bpfjailer {

class Fd {
 protected:
 public:
  explicit Fd(int fd) noexcept : fd_(fd) {}
  Fd() noexcept = default;

  virtual ~Fd() noexcept {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }

  static Expected<Fd> fromFd(int fd) {
    return Fd(fd);
  }

  static Expected<std::array<Fd, 2>> pipe(int flags = 0);

  static Expected<Fd> open(const char* pathname, int flags, mode_t mode = 0666);

  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;

  void swap(Fd& other) noexcept {
    std::swap(fd_, other.fd_);
    std::swap(isStored_, other.isStored_);
  }

  Fd(Fd&& other) noexcept {
    swap(other);
  }

  Fd& operator=(Fd&& other) noexcept {
    swap(other);
    return *this;
  }

  Expected<Fd> dup() const;

  int get() const {
    return fd_;
  }

  int& getRef() {
    return fd_;
  }

  const int& getRef() const {
    return fd_;
  }

  bool hasFd() const {
    return fd_ >= 0;
  }

  auto operator<=>(const Fd& other) const = default;

  virtual const std::string& name() const {
    static const std::string empty;
    return empty;
  }

  virtual Expected<> rename(const std::string& /* name */) {
    return makeUnexpected(Error::fromErrno("Rename not supported"));
  }

  Expected<int> poll(
      std::chrono::milliseconds timeout,
      short events = POLLIN,
      short revents = 0) const;

  Expected<off_t> lseek(off_t offset, int whence = SEEK_SET) const;

  Expected<struct stat> fstat() const;

  // virtual so tests can inject ENOSPC on the log write path (LogFile pwrites
  // its entries/metadata rather than storing through the mmap).
  virtual Expected<> ftruncate(off_t length) const;

  Expected<std::size_t> read(void* buf, std::size_t count) const;

  Expected<std::size_t> pread(void* buf, std::size_t count, off_t offset) const;

  Expected<std::size_t> write(const void* buf, std::size_t count) const;

  virtual Expected<std::size_t>
  pwrite(const void* buf, std::size_t count, off_t offset) const;

  Expected<> fcntl(int cmd, int arg) const;

 protected:
  int fd_ = -1;

  // Whether or not this fd is shared with systemd in the fdstore
  bool isStored_ = false;
};

} // namespace bpfjailer

namespace std {
inline void swap(bpfjailer::Fd& lhs, bpfjailer::Fd& rhs) noexcept {
  lhs.swap(rhs);
}

} // namespace std
