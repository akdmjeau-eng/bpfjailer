// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/lib/Fd.h"

namespace bpfjailer {

Expected<Fd> Fd::dup() const {
  auto fd = ::dup(fd_);
  if (fd < 0) {
    return makeUnexpected(Error::fromErrno("dup failed"));
  }
  return Fd(fd);
}

Expected<std::array<Fd, 2>> Fd::pipe(int flags) {
  int fds[2];
  if (::pipe2(fds, flags) < 0) {
    return makeUnexpected(Error::fromErrno("pipe error"));
  }

  return std::array<Fd, 2>{Fd(fds[0]), Fd(fds[1])};
}

Expected<Fd> Fd::open(const char* pathname, int flags, mode_t mode) {
  auto fd = ::open(pathname, flags, mode);
  if (fd < 0) {
    return makeUnexpected(Error::fromErrno("open error"));
  }

  return Fd(fd);
}

Expected<int>
Fd::poll(std::chrono::milliseconds timeout, short events, short revents) const {
  struct pollfd pfd{};
  pfd.fd = fd_;
  pfd.events = events;
  pfd.revents = revents;
  auto ret = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("poll error"));
  }

  return ret;
}

Expected<off_t> Fd::lseek(off_t offset, int whence) const {
  auto ret = ::lseek(fd_, offset, whence);
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("lseek error"));
  }

  return ret;
}

Expected<struct stat> Fd::fstat() const {
  struct stat st{};
  auto ret = ::fstat(fd_, &st);
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("fstat error"));
  }

  return st;
}

Expected<> Fd::ftruncate(off_t length) const {
  auto ret = ::ftruncate(fd_, length);
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("ftruncate error"));
  }

  return unit;
}

Expected<std::size_t> Fd::read(void* buf, std::size_t count) const {
  auto ret = ::read(fd_, buf, count);
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("read error"));
  }

  return ret;
}

Expected<std::size_t> Fd::write(const void* buf, std::size_t count) const {
  auto ret = ::write(fd_, buf, count);
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("write error"));
  }

  return ret;
}

Expected<std::size_t> Fd::pread(void* buf, std::size_t count, off_t offset)
    const {
  auto ret = ::pread(fd_, buf, count, offset);
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("pread error"));
  }

  return ret;
}

Expected<std::size_t>
Fd::pwrite(const void* buf, std::size_t count, off_t offset) const {
  auto ret = ::pwrite(fd_, buf, count, offset);
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("pwrite error"));
  }

  return ret;
}

Expected<> Fd::fcntl(int cmd, int arg) const {
  auto ret = ::fcntl(fd_, cmd, arg);
  if (ret < 0) {
    return makeUnexpected(Error::fromErrno("fcntl error"));
  }

  return unit;
}

} // namespace bpfjailer
