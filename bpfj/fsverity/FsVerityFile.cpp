// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/fsverity/FsVerityFile.h"

#include <fcntl.h>
#include <linux/fsverity.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <string>

#include "bpfj/lib/Base64.h"
#include "bpfj/lib/ScopeGuard.h"

#define BPFJ_FS_VERITY_MAX_DIGEST_SIZE 64

#define BPFJ_FS_VERITY_SHA256_DIGEST_SIZE (std::uint16_t)32
#define BPFJ_FS_VERITY_SHA512_DIGEST_SIZE (std::uint16_t)64

namespace bpfjailer {

namespace {

// We redefine this because of the cursed VLA in the kernel header.
struct digest {
  __u16 digest_algorithm;
  __u16 digest_size; // input/output
  unsigned char digest[BPFJ_FS_VERITY_MAX_DIGEST_SIZE];
};

// folly::writeFull: a write() can come up short or be interrupted, either of
// which silently truncates the file unless the caller goes round again.
ssize_t writeFull(int fd, const char* buf, std::size_t count) {
  std::size_t written = 0;
  while (written < count) {
    ssize_t n = ::write(fd, buf + written, count - written);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    written += static_cast<std::size_t>(n);
  }
  return static_cast<ssize_t>(written);
}

} // namespace

FsVerityFile::FsVerityFile(std::string_view path, Sha256 /* tag */)
    : path_(path), algorithm_(FS_VERITY_HASH_ALG_SHA256) {}
FsVerityFile::FsVerityFile(std::string_view path, Sha512 /* tag */)
    : path_(path), algorithm_(FS_VERITY_HASH_ALG_SHA512) {}

err::Expected<> FsVerityFile::enable() {
  int fd = ::open(path_.c_str(), O_RDONLY);
  if (fd < 0) {
    return err::Error::fromErrno("Could not open path " + path_);
  }

  auto closeGuard = makeGuard([fd] { ::close(fd); });

  fsverity_enable_arg arg = {
      .version = 1,
      .hash_algorithm = algorithm_,
      .block_size = 4096,
      .salt_size = 0,
      .salt_ptr = 0,
      .sig_size = 0,
      .__reserved1 = 0,
      .sig_ptr = 0,
      .__reserved2 = {},
  };
  if (::ioctl(fd, FS_IOC_ENABLE_VERITY, &arg) < 0) {
    return err::Error::fromErrno("Could not enable fs-verity on " + path_);
  }

  return err::unit;
}

err::Expected<std::vector<unsigned char>> FsVerityFile::measure() {
  int fd = ::open(path_.c_str(), O_RDONLY); // We don't store the fd because it
                                            // changes when we enable fs-verity
  if (fd < 0) {
    return err::Error::fromErrno("Could not open path " + path_);
  }

  auto closeGuard = makeGuard([fd] { ::close(fd); });

  digest digest = {
      .digest_algorithm = algorithm_,
      .digest_size =
          (algorithm_ == FS_VERITY_HASH_ALG_SHA256
               ? BPFJ_FS_VERITY_SHA256_DIGEST_SIZE
               : BPFJ_FS_VERITY_SHA512_DIGEST_SIZE),
      .digest = {},
  };

  if (::ioctl(fd, FS_IOC_MEASURE_VERITY, &digest) < 0) {
    return err::Error::fromErrno("Could not measure fs-verity on " + path_);
  }

  if (digest.digest_size !=
      (algorithm_ == FS_VERITY_HASH_ALG_SHA256
           ? BPFJ_FS_VERITY_SHA256_DIGEST_SIZE
           : BPFJ_FS_VERITY_SHA512_DIGEST_SIZE)) {
    return err::Error(
        std::errc::io_error,
        "Unexpected digest size " + std::to_string(digest.digest_size) +
            " for path " + path_ + " algo " + std::to_string(algorithm_));
  }

  std::vector<unsigned char> out(digest.digest_size);
  std::copy(digest.digest, digest.digest + digest.digest_size, out.begin());
  return out;
}

err::Expected<std::string> FsVerityFile::measureBase64() {
  auto digest = measure();
  if (!digest) {
    return digest.error();
  }
  return base64::encode(digest->data(), digest->size());
}

err::Expected<> FsVerityFile::create(std::string_view contents) {
  int fd = ::creat(path_.c_str(), 0644);
  if (fd < 0) {
    return err::Error::fromErrno("Could not open path " + path_);
  }

  if (writeFull(fd, contents.data(), contents.size()) < 0) {
    auto error = err::Error::fromErrno("Could not write contents to " + path_);
    ::close(fd);
    return error;
  }
  ::close(fd);

  auto res = enable();
  if (!res) {
    return res.error();
  }

  return err::unit;
}

void FsVerityFile::unlink() {
  ::unlink(path_.c_str());
}

err::Expected<> FsVerityFile::setxattr(
    const std::string& key,
    std::string_view value) {
  if (::setxattr(path_.c_str(), key.c_str(), value.data(), value.size(), 0) <
      0) {
    return err::Error::fromErrno(
        "Could not setxattr " + key + " on path " + path_);
  }

  return err::unit;
}

} // namespace bpfjailer
