// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/err/StdExpected.h"

namespace bpfjailer {

class FsVerityFile {
 public:
  struct Sha256 {};
  struct Sha512 {};

  FsVerityFile(std::string_view path, Sha256 /* tag */);
  FsVerityFile(std::string_view path, Sha512 /* tag */);

  static err::Expected<FsVerityFile>
  create(std::string_view path, std::string_view contents, Sha256 /* tag */) {
    return FsVerityFile::create<Sha256>(path, contents);
  }

  static err::Expected<FsVerityFile>
  create(std::string_view path, std::string_view contents, Sha512 /* tag */) {
    return FsVerityFile::create<Sha512>(path, contents);
  }

  err::Expected<> enable();

  err::Expected<std::vector<unsigned char>> measure();

  err::Expected<std::string> measureBase64();

  void unlink();

  err::Expected<> setxattr(const std::string& key, std::string_view value);

 private:
  err::Expected<> create(std::string_view contents);

  template <typename T>
  static err::Expected<FsVerityFile> create(
      std::string_view path,
      std::string_view contents) {
    auto fs = FsVerityFile(path, T{});
    auto res = fs.create(contents);
    if (!res) {
      return res.error();
    }
    return fs;
  }

  const std::string path_;
  std::uint16_t algorithm_;
};

} // namespace bpfjailer
