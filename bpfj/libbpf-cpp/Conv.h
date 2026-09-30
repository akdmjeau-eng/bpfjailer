// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include "bpfj/libbpf-cpp/Err.h"

namespace bpfj::libbpf::conv {

namespace detail {

/// @brief Bounds-checked memcpy, standing in for secure_lib's checked_memcpy.
/// Every caller rejects oversized input first, so this is a backstop: it zeroes
/// the destination rather than overrunning it.
inline void checkedMemcpy(
    void* dest,
    std::size_t destSize,
    const void* src,
    std::size_t srcSize) noexcept {
  if (srcSize > destSize) {
    std::memset(dest, 0, destSize);
    return;
  }
  std::memcpy(dest, src, srcSize);
}

template <typename T>
concept IsInt = std::is_integral_v<T>;

template <typename T>
concept IsString = requires(T t) {
  t.c_str();
  t.size();
};

// Update an inner map from packed key/value buffers via bpf_map_update_batch,
// falling back to per-entry inserts with transient-errno backoff-retry.
// Defined in Conv.cpp; the injectable, testable core is in ConvInternal.h.
[[nodiscard]] Expected<> batchUpdateInnerMap(
    int fd,
    const char* mapPrefix,
    bpf_map_type type,
    unsigned char* keys,
    std::size_t keySize,
    unsigned char* vals,
    std::size_t valSize,
    std::uint32_t total) noexcept;

} // namespace detail

template <typename T>
struct ToSame {
  Expected<T> operator()(const T& t) const noexcept {
    return t;
  }
};

template <typename T>
struct ToConstant {
  explicit ToConstant(const T& val) : val_(val) {}

  Expected<T> operator()(auto&& /* ignored */) const noexcept {
    return val_;
  }

  T val_;
};

template <detail::IsInt T>
struct ToCounter {
  ToCounter(T begin = 0) : begin_(begin), val_(begin) {}

  Expected<T> operator()(auto&& /* ignored */) {
    return val_++;
  }

  void reset() noexcept {
    val_ = begin_;
  }

  T begin_;
  T val_;
};

template <detail::IsInt T>
struct ToInt {
  template <detail::IsInt I>
  Expected<T> operator()(I i) const noexcept {
    if constexpr (!std::is_signed_v<T>) {
      if (i < 0) {
        return makeUnexpected(Error(
            std::errc::invalid_argument, "negative value for unsigned type"));
      }
    }

    if (i < std::numeric_limits<T>::min()) {
      return makeUnexpected(
          Error(std::errc::value_too_large, "value below minimum"));
    } else if (i > std::numeric_limits<T>::max()) {
      return makeUnexpected(
          Error(std::errc::value_too_large, "value above maximum"));
    }

    return static_cast<T>(i);
  }
};

template <typename T, std::size_t N = sizeof(T)>
struct ToString {
  template <detail::IsString S>
  Expected<T> operator()(S&& s) const noexcept {
    T ret;
    if (N <= s.size()) {
      return makeUnexpected(
          Error(std::errc::value_too_large, "string too long"));
    }

    detail::checkedMemcpy(&ret, N, s.c_str(), s.size() + 1);

    return ret;
  }

  // Special case for string literals
  template <std::size_t N2>
  Expected<T> operator()(const char (&s)[N2]) const noexcept {
    T ret;
    if (N < N2) {
      return makeUnexpected(
          Error(std::errc::value_too_large, "string literal too long"));
    }

    detail::checkedMemcpy(&ret, N, s, N2);

    return ret;
  }
};

template <typename T>
struct ToConstSizeStr {
  explicit ToConstSizeStr(const char* /* logStr */ = nullptr) {}

  template <detail::IsString S>
  Expected<T> operator()(S&& s) const noexcept {
    T strct{};
    if (sizeof(strct) <= s.size()) {
      return makeUnexpected(Error(
          std::errc::invalid_argument,
          "string too long for fixed-size struct"));
    }
    detail::checkedMemcpy(&strct, sizeof(strct), s.c_str(), s.size() + 1);
    return strct;
  }
};

template <detail::IsInt T>
using ToNumeric = ToInt<T>;

namespace tomap_detail {

template <typename T>
concept IsMap = requires(T t) {
  t.begin()->first;
  t.begin()->second;
  t.size();
};

template <typename F, typename Arg>
using ConvertedType =
    std::decay_t<decltype(std::declval<std::decay_t<F>>()(
                              std::declval<std::decay_t<Arg>>())
                              .value())>;

template <typename T>
concept IsResetable = requires(T t) { t.reset(); };

} // namespace tomap_detail

template <typename MakeKey, typename MakeVal>
struct ToMap {
  using is_to_map = std::true_type;

  ToMap(
      const char* mapPrefix,
      MakeKey&& makeKey,
      MakeVal&& makeVal,
      enum bpf_map_type type = BPF_MAP_TYPE_HASH,
      std::uint32_t flags = 0,
      std::uint32_t minMaxEntries = 0)
      : mapPrefix_(mapPrefix),
        makeKey_(std::forward<MakeKey>(makeKey)),
        makeVal_(std::forward<MakeVal>(makeVal)),
        type_(type),
        flags_(flags),
        minMaxEntries_(minMaxEntries) {}

  template <typename U>
  Expected<int> operator()(U&& container) {
    std::uint32_t maxEntries = std::max(
        static_cast<std::uint32_t>(container.size()),
        minMaxEntries_ > 0 ? minMaxEntries_ : std::uint32_t(1));

    if constexpr (tomap_detail::IsResetable<std::decay_t<MakeKey>>) {
      makeKey_.reset();
    }
    if constexpr (tomap_detail::IsResetable<std::decay_t<MakeVal>>) {
      makeVal_.reset();
    }

    std::uint32_t keySize = 0;
    std::uint32_t valSize = 0;

    if constexpr (tomap_detail::IsMap<std::decay_t<U>>) {
      keySize = sizeof(
          tomap_detail::
              ConvertedType<MakeKey, decltype(container.begin()->first)>);
      valSize = sizeof(
          tomap_detail::
              ConvertedType<MakeVal, decltype(container.begin()->second)>);
    } else {
      keySize = sizeof(
          tomap_detail::ConvertedType<MakeKey, decltype(*container.begin())>);
      valSize = sizeof(
          tomap_detail::ConvertedType<MakeVal, decltype(*container.begin())>);
    }

    if (container.empty()) {
      return createEmptyMap<U>(keySize, valSize, maxEntries);
    }

    keyBuf_.clear();
    valBuf_.clear();
    int fd = -1;

    for (auto& entry : container) {
      auto res = [&]() -> Expected<> {
        if constexpr (tomap_detail::IsMap<std::decay_t<U>>) {
          return appendEntry(fd, maxEntries, entry.first, entry.second);
        } else {
          return appendEntry(fd, maxEntries, entry, entry);
        }
      }();
      if (!res) {
        if (fd >= 0) {
          ::close(fd);
        }
        return makeUnexpected(res.error());
      }
    }

    if (auto res = detail::batchUpdateInnerMap(
            fd,
            mapPrefix_,
            type_,
            keyBuf_.data(),
            keySize,
            valBuf_.data(),
            valSize,
            static_cast<std::uint32_t>(container.size()));
        !res) {
      ::close(fd);
      return makeUnexpected(res.error());
    }

    return fd;
  }

  MakeKey& makeKey() {
    return makeKey_;
  }
  MakeVal& makeVal() {
    return makeVal_;
  }
  enum bpf_map_type type() {
    return type_;
  }
  const char* mapPrefix() {
    return mapPrefix_;
  }

 private:
  template <typename K, typename V>
  Expected<> appendEntry(int& fd, std::uint32_t maxEntries, K&& key, V&& val) {
    auto k = makeKey_(key);
    if (!k) {
      return makeUnexpected(k.error());
    }
    auto v = makeVal_(val);
    if (!v) {
      return makeUnexpected(v.error());
    }

    if (fd == -1) {
      if (type_ == BPF_MAP_TYPE_LPM_TRIE) {
        // LPM trie needs a spare entry (see kernel code)
        ++maxEntries;
      }

      LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = flags_);
      fd = ::bpf_map_create(
          type_, mapPrefix_, sizeof(*k), sizeof(*v), maxEntries, &opts);
      if (fd < 0) {
        return makeUnexpected(Error::fromErrno("failed to create inner map"));
      }
    }

    auto* kptr = reinterpret_cast<const unsigned char*>(&*k);
    keyBuf_.insert(keyBuf_.end(), kptr, kptr + sizeof(*k));
    auto* vptr = reinterpret_cast<const unsigned char*>(&*v);
    valBuf_.insert(valBuf_.end(), vptr, vptr + sizeof(*v));

    return unit;
  }

  template <typename U>
  Expected<int> createEmptyMap(
      std::uint32_t keySize,
      std::uint32_t valSize,
      std::uint32_t maxEntries) {
    LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = flags_);
    int fd = ::bpf_map_create(
        type_, mapPrefix_, keySize, valSize, maxEntries, &opts);
    if (fd < 0) {
      return makeUnexpected(
          Error::fromErrno("failed to create empty inner map"));
    }
    return fd;
  }

  const char* mapPrefix_;
  MakeKey makeKey_;
  MakeVal makeVal_;
  std::vector<unsigned char> keyBuf_;
  std::vector<unsigned char> valBuf_;
  enum bpf_map_type type_;
  std::uint32_t flags_;
  std::uint32_t minMaxEntries_;
};

} // namespace bpfj::libbpf::conv
