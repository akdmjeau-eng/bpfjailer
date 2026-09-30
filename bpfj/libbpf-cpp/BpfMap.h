// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>
#include "bpfj/libbpf-cpp/Err.h"
#include "bpfj/libbpf-cpp/Util.h"

namespace bpfj::libbpf {

namespace detail {

template <typename T>
concept IsTrivallyCopyable = std::is_trivially_copyable_v<std::decay_t<T>>;

template <typename T>
concept IsIterable = requires(T t) {
  t.begin();
  t.end();
};

template <typename T>
concept IsList = IsIterable<T> && requires(T t) { t.size(); };

template <typename T>
concept IsSet =
    IsList<T> && requires(T t) { typename std::decay_t<T>::key_type; };

template <typename T>
concept IsMap = IsSet<T> && requires(T t) {
  t.begin()->first;
  t.begin()->second;
};

template <typename T>
concept IsToMap = requires { typename std::decay_t<T>::is_to_map; };

template <typename T, typename... Args>
concept IsFunctor = std::is_invocable_v<std::decay_t<T>, Args&&...>;

template <IsTrivallyCopyable T>
void append(std::vector<unsigned char>& buf, T&& toAppend) {
  const auto* ptr = reinterpret_cast<const unsigned char*>(&toAppend);
  buf.insert(buf.end(), ptr, ptr + sizeof(std::decay_t<T>));
}

template <IsIterable T>
void append(std::vector<unsigned char>& buf, T&& toAppend) {
  buf.insert(buf.end(), toAppend.begin(), toAppend.end());
}

template <typename K, typename V, typename ToKey, typename ToVal>
[[nodiscard]] Expected<> append(
    std::vector<unsigned char>& keys,
    std::vector<unsigned char>& vals,
    K&& k,
    V&& v,
    ToKey&& toKey,
    ToVal&& toVal) {
  auto key = toKey(std::forward<K>(k));
  if (!key) {
    return makeUnexpected(key.error());
  }

  auto val = toVal(std::forward<V>(v));
  if (!val) {
    return makeUnexpected(val.error());
  }

  append(keys, *key);
  append(vals, *val);

  return unit;
}

} // namespace detail

class BpfMap {
 public:
  template <typename K>
  struct Iterator {
   public:
    Iterator(
        const BpfMap& map,
        Expected<>& err,
        bool returnEnd = false) noexcept
        : map_(map), err_(err), isEnd_(returnEnd) {
      if (!isEnd_) {
        // Advance to the first element
        err_ = advance();
      }
    }

    bool operator==(const Iterator& other) const noexcept {
      if (isEnd_ == other.isEnd_) {
        return true;
      }

      return memcmp(&next_, &other.next_, sizeof(next_)) == 0;
    }

    Iterator& operator++() noexcept {
      err_ = advance(&next_);

      return *this;
    }

    K& operator*() noexcept {
      return next_;
    }

    K* operator->() noexcept {
      return &next_;
    }

   private:
    Expected<> advance(K* curr = nullptr) noexcept {
      auto res = map_.getNextKey(curr, &next_, sizeof(next_));
      if (!res) {
        if (res.error().code() != std::errc::no_such_file_or_directory) {
          return makeUnexpected(res.error());
        }

        isEnd_ = true;
      }

      return unit;
    }

    const BpfMap& map_;
    Expected<>& err_;
    K next_{};
    bool isEnd_{false};
  };

  template <typename K>
  class Range {
   public:
    // Borrow an external err the caller wants to inspect after iterating.
    Range(const BpfMap& map, Expected<>& err) noexcept
        : map_(map), err_(&err) {}
    // Own the err when the caller does not care, stored inline so the
    // iterators reference storage that outlives a stack temporary.
    explicit Range(const BpfMap& map) noexcept : map_(map), err_(&ownedErr_) {}

    // Non-movable: err_ may point at ownedErr_, and range-for constructs the
    // Range in place under guaranteed copy elision.
    Range(const Range&) = delete;
    Range& operator=(const Range&) = delete;
    Range(Range&&) = delete;
    Range& operator=(Range&&) = delete;
    ~Range() = default;

    Iterator<K> begin() const noexcept {
      return Iterator<K>(map_, *err_);
    }

    Iterator<K> end() const noexcept {
      return Iterator<K>(map_, *err_, true);
    }

   private:
    const BpfMap& map_;
    Expected<> ownedErr_{unit};
    Expected<>* err_;
  };

  template <typename K>
  Range<K> forEach(Expected<>& err) const noexcept {
    return Range<K>(*this, err);
  }

  template <typename K>
  Range<K> forEach() const noexcept {
    return Range<K>(*this);
  }

  explicit BpfMap(struct bpf_map* map) noexcept : map_(map) {}

  ~BpfMap() noexcept = default;

  BpfMap(const BpfMap& other) noexcept {
    map_ = other.map_;
  }

  BpfMap& operator=(const BpfMap& other) noexcept = default;

  void swap(BpfMap& other) noexcept {
    std::swap(map_, other.map_);
  }

  BpfMap(BpfMap&& other) noexcept {
    swap(other);
  }

  BpfMap& operator=(BpfMap&& other) noexcept {
    swap(other);
    return *this;
  }

  struct bpf_map* get() const noexcept {
    return map_;
  }

  [[nodiscard]] Expected<> setAutocreate(bool autocreate) noexcept {
    return detail::call(
        "failed to set autocreate on BPF map",
        ::bpf_map__set_autocreate,
        map_,
        autocreate);
  }

  bool autocreate() const noexcept {
    return ::bpf_map__autocreate(map_);
  }

  [[nodiscard]] Expected<> setAutoattach(bool autoattach) noexcept {
    return detail::call(
        "failed to set autoattach on BPF map",
        ::bpf_map__set_autoattach,
        map_,
        autoattach);
  }

  int fd() const noexcept {
    return ::bpf_map__fd(map_);
  }

  [[nodiscard]] Expected<> reuseFd(int fd) noexcept {
    return detail::call(
        "failed to reuse fd for BPF map", ::bpf_map__reuse_fd, map_, fd);
  }

  const char* name() const noexcept {
    return ::bpf_map__name(map_);
  }

  bpf_map_type type() const noexcept {
    return ::bpf_map__type(map_);
  }

  [[nodiscard]] Expected<> setType(bpf_map_type type) noexcept {
    return detail::call(
        "failed to set type on BPF map", ::bpf_map__set_type, map_, type);
  }

  std::uint32_t maxEntries() const noexcept {
    return ::bpf_map__max_entries(map_);
  }

  [[nodiscard]] Expected<> setMaxEntries(std::uint32_t maxEntries) noexcept {
    if (maxEntries == 0) {
      maxEntries = 1;
    }

    return detail::call(
        "failed to set max entries on BPF map",
        ::bpf_map__set_max_entries,
        map_,
        maxEntries);
  }

  std::uint32_t mapFlags() const noexcept {
    return ::bpf_map__map_flags(map_);
  }

  [[nodiscard]] Expected<> setMapFlags(std::uint32_t mapFlags) noexcept {
    return detail::call(
        "failed to set map flags on BPF map",
        ::bpf_map__set_map_flags,
        map_,
        mapFlags);
  }

  std::uint32_t numaNode() const noexcept {
    return ::bpf_map__numa_node(map_);
  }

  [[nodiscard]] Expected<> setNumaNode(std::uint32_t numaNode) noexcept {
    return detail::call(
        "failed to set numa node on BPF map",
        ::bpf_map__set_numa_node,
        map_,
        numaNode);
  }

  std::uint32_t keySize() const noexcept {
    return ::bpf_map__key_size(map_);
  }

  [[nodiscard]] Expected<> setKeySize(std::uint32_t keySize) noexcept {
    return detail::call(
        "failed to set key size on BPF map",
        ::bpf_map__set_key_size,
        map_,
        keySize);
  }

  std::uint32_t valueSize() const noexcept {
    return ::bpf_map__value_size(map_);
  }

  [[nodiscard]] Expected<> setValueSize(std::uint32_t valueSize) noexcept {
    return detail::call(
        "failed to set value size on BPF map",
        ::bpf_map__set_value_size,
        map_,
        valueSize);
  }

  std::uint32_t btfKeyTypeId() const noexcept {
    return ::bpf_map__btf_key_type_id(map_);
  }

  std::uint32_t btfValueTypeId() const noexcept {
    return ::bpf_map__btf_value_type_id(map_);
  }

  std::uint32_t ifIndex() const noexcept {
    return ::bpf_map__ifindex(map_);
  }

  [[nodiscard]] Expected<> setIfIndex(std::uint32_t ifIndex) noexcept {
    return detail::call(
        "failed to set ifindex on BPF map",
        ::bpf_map__set_ifindex,
        map_,
        ifIndex);
  }

  std::uint64_t mapExtra() const noexcept {
    return ::bpf_map__map_extra(map_);
  }

  [[nodiscard]] Expected<> setMapExtra(std::uint64_t extra) noexcept {
    return detail::call(
        "failed to set map extra on BPF map",
        ::bpf_map__set_map_extra,
        map_,
        extra);
  }

  [[nodiscard]] Expected<> setInitialValue(
      const void* value,
      std::size_t size) noexcept {
    return detail::call(
        "failed to set initial value on BPF map",
        ::bpf_map__set_initial_value,
        map_,
        value,
        size);
  }

  void* initialValue(std::size_t* pSize) const noexcept {
    return ::bpf_map__initial_value(map_, pSize);
  }

  bool isInternal() const noexcept {
    return ::bpf_map__is_internal(map_);
  }

  [[nodiscard]] Expected<> setPinPath(const char* path) noexcept {
    return detail::call(
        "failed to set pin path on BPF map",
        ::bpf_map__set_pin_path,
        map_,
        path);
  }

  const char* pinPath() const noexcept {
    return ::bpf_map__pin_path(map_);
  }

  bool isPinned() const noexcept {
    return ::bpf_map__is_pinned(map_);
  }

  [[nodiscard]] Expected<> pin(const char* path) noexcept {
    return detail::call("failed to pin BPF map", ::bpf_map__pin, map_, path);
  }

  [[nodiscard]] Expected<> unpin(const char* path) noexcept {
    return detail::call(
        "failed to unpin BPF map", ::bpf_map__unpin, map_, path);
  }

  [[nodiscard]] Expected<> setInnerMapFd(int fd) noexcept {
    return detail::call(
        "failed to set inner map fd", ::bpf_map__set_inner_map_fd, map_, fd);
  }

  BpfMap innerMap() const noexcept {
    return BpfMap(::bpf_map__inner_map(map_));
  }

  [[nodiscard]] Expected<> lookupElem(
      const void* key,
      std::size_t keySz,
      void* value,
      std::size_t valueSz,
      std::uint64_t flags = 0) const noexcept {
    return detail::call(
        "failed to lookup element in BPF map",
        ::bpf_map__lookup_elem,
        map_,
        key,
        keySz,
        value,
        valueSz,
        flags);
  }

  template <detail::IsTrivallyCopyable V, detail::IsTrivallyCopyable K>
  [[nodiscard]] Expected<V> lookupElem(const K& key, std::uint64_t flags = 0)
      const noexcept {
    V value;
    if (auto error =
            lookupElem(&key, sizeof(key), &value, sizeof(value), flags);
        !error) {
      return makeUnexpected(error.error());
    }

    return value;
  }

  template <
      detail::IsTrivallyCopyable V,
      typename K,
      detail::IsFunctor<K> MakeKey>
  [[nodiscard]] Expected<V> lookupElem(
      K&& key,
      MakeKey&& makeKey,
      std::uint64_t flags = 0) const noexcept {
    auto k = makeKey(std::forward<K>(key));
    if (!k) {
      return makeUnexpected(k.error());
    }
    return lookupElem<V>(*k, flags);
  }

  [[nodiscard]] Expected<> updateElem(
      const void* key,
      std::size_t keySz,
      const void* value,
      std::size_t valueSz,
      std::uint64_t flags = 0) noexcept {
    return detail::call(
        "failed to update element in BPF map",
        ::bpf_map__update_elem,
        map_,
        key,
        keySz,
        value,
        valueSz,
        flags);
  }

  template <detail::IsTrivallyCopyable V, detail::IsTrivallyCopyable K>
  [[nodiscard]] Expected<>
  updateElem(const K& key, const V& value, std::uint64_t flags = 0) noexcept {
    return updateElem(&key, sizeof(key), &value, sizeof(value), flags);
  }

  [[nodiscard]] Expected<>
  deleteElem(const void* key, std::size_t keySz, std::uint64_t flags) noexcept {
    return detail::call(
        "failed to delete element from BPF map",
        ::bpf_map__delete_elem,
        map_,
        key,
        keySz,
        flags);
  }

  template <detail::IsTrivallyCopyable K>
  [[nodiscard]] Expected<> deleteElem(const K& key, std::uint64_t flags = 0) {
    return deleteElem(&key, sizeof(key), flags);
  }

  [[nodiscard]] Expected<> lookupAndDeleteElem(
      const void* key,
      std::size_t keySz,
      void* value,
      std::size_t valueSz,
      std::uint64_t flags) noexcept {
    return detail::call(
        "failed to lookup and delete element in BPF map",
        ::bpf_map__lookup_and_delete_elem,
        map_,
        key,
        keySz,
        value,
        valueSz,
        flags);
  }

  template <detail::IsTrivallyCopyable V, detail::IsTrivallyCopyable K>
  [[nodiscard]] Expected<V> lookupAndDeleteElem(
      const K& key,
      std::uint64_t flags = 0) noexcept {
    V value;
    if (auto error = lookupAndDeleteElem(
            &key, sizeof(key), &value, sizeof(value), flags);
        !error) {
      return makeUnexpected(error.error());
    }

    return value;
  }

  [[nodiscard]] Expected<> getNextKey(
      const void* currKey,
      void* nextKey,
      std::size_t keySz) const noexcept {
    return detail::call(
        "failed to get next key in BPF map",
        ::bpf_map__get_next_key,
        map_,
        currKey,
        nextKey,
        keySz);
  }

  [[nodiscard]]
  Expected<> updateBatch(
      const void* keys,
      const void* vals,
      std::uint32_t* count,
      const struct bpf_map_batch_opts* opts = nullptr) const {
    return detail::call(
        (std::string("failed to batch update BPF map ") + name()).c_str(),
        ::bpf_map_update_batch,
        fd(),
        keys,
        vals,
        count,
        opts);
  }

  template <typename T, typename ToKey, typename ToVal>
  [[nodiscard]] Expected<> updateBatch(T&& data, ToKey&& toKey, ToVal&& toVal) {
    if constexpr (detail::IsToMap<std::decay_t<ToVal>>) {
      // A single BPF_MAP_UPDATE_ELEM on a map-of-maps costs one
      // synchronize_rcu() grace period *per element* (~16ms on 6.16), while
      // BPF_MAP_UPDATE_BATCH inserts the whole set under one. Every inner fd
      // is closed on exit, the kernel holding its own reference once an entry
      // is inserted. (Mirrors metarmor BpfMap::updateFromMap.)
      std::vector<unsigned char> keyBytes;
      std::vector<std::uint32_t> innerFds;
      std::size_t keySz = 0;
      // The kernel keeps its own reference for entries that landed.
      struct FdCloser {
        std::vector<std::uint32_t>& fds;
        explicit FdCloser(std::vector<std::uint32_t>& f) : fds(f) {}
        FdCloser(const FdCloser&) = delete;
        FdCloser& operator=(const FdCloser&) = delete;
        FdCloser(FdCloser&&) = delete;
        FdCloser& operator=(FdCloser&&) = delete;
        ~FdCloser() {
          for (std::uint32_t fd : fds) {
            ::close(static_cast<int>(fd));
          }
        }
      } fdCloser{innerFds};

      // Both map and list inputs expose size(), so reserve once for the
      // large-policy fast path this batch exists for.
      const std::size_t n = data.size();
      innerFds.reserve(n);

      auto collect = [&](auto&& keyExp, auto&& valExp) -> Expected<> {
        if (!valExp) {
          return makeUnexpected(valExp.error());
        }
        // First, so FdCloser closes it even if the key or a later entry
        // fails.
        innerFds.push_back(static_cast<std::uint32_t>(*valExp));
        if (!keyExp) {
          return makeUnexpected(keyExp.error());
        }
        const auto& key = *keyExp;
        static_assert(
            std::is_trivially_copyable_v<std::decay_t<decltype(key)>>,
            "batch key must be trivially copyable to byte-copy into keyBytes");
        keySz = sizeof(key);
        if (keyBytes.empty()) {
          keyBytes.reserve(n * keySz);
        }
        const auto* keyPtr = reinterpret_cast<const unsigned char*>(&key);
        keyBytes.insert(keyBytes.end(), keyPtr, keyPtr + sizeof(key));
        return unit;
      };

      if constexpr (detail::IsMap<typename std::decay_t<T>>) {
        for (auto&& [k, v] : data) {
          if (auto res = collect(toKey(k), toVal(v)); !res) {
            return makeUnexpected(res.error());
          }
        }
      } else {
        for (auto&& v : data) {
          if (auto res = collect(toKey(v), toVal(v)); !res) {
            return makeUnexpected(res.error());
          }
        }
      }

      if (innerFds.empty()) {
        return unit;
      }

      std::uint32_t count = static_cast<std::uint32_t>(innerFds.size());
      DECLARE_LIBBPF_OPTS(
          bpf_map_batch_opts, batchOpts, .elem_flags = 0, .flags = 0);
      if (auto res =
              updateBatch(keyBytes.data(), innerFds.data(), &count, &batchOpts);
          res && count == innerFds.size()) {
        return unit;
      }
      // Batch failed or reported a partial count, so fall back to
      // per-element updates, from 0 rather than the kernel's `count`:
      // re-applying an inserted fd is idempotent, and not every failure path
      // sets `count` to the applied prefix.
      for (std::size_t i = 0; i < innerFds.size(); ++i) {
        if (auto res = updateElem(
                keyBytes.data() + (i * keySz),
                keySz,
                &innerFds[i],
                sizeof(innerFds[i]));
            !res) {
          return makeUnexpected(res.error());
        }
      }
      return unit;
    } else if constexpr (detail::IsMap<typename std::decay_t<T>>) {
      return updateBatch(
          [&](auto& keys, auto& vals) -> Expected<std::uint32_t> {
            std::uint32_t count = 0;
            for (auto&& [k, v] : data) {
              if (auto res = detail::append(
                      keys,
                      vals,
                      k,
                      v,
                      std::forward<ToKey>(toKey),
                      std::forward<ToVal>(toVal));
                  !res) {
                return makeUnexpected(res.error());
              }
              ++count;
            }

            return count;
          });
    } else if constexpr (detail::IsList<typename std::decay_t<T>>) {
      return updateBatch(
          [&](auto& keys, auto& vals) -> Expected<std::uint32_t> {
            std::uint32_t count = 0;
            for (auto&& k : data) {
              if (auto res = detail::append(
                      keys,
                      vals,
                      k,
                      k,
                      std::forward<ToKey>(toKey),
                      std::forward<ToVal>(toVal));
                  !res) {
                return makeUnexpected(res.error());
              }
              ++count;
            }

            return count;
          });
    } else {
      static_assert(!std::is_same<T, T>::value);
    }
  }

 private:
  template <typename F>
  [[nodiscard]] Expected<> updateBatch(F&& append) {
    std::vector<unsigned char> keys;
    std::vector<unsigned char> vals;

    auto count = append(keys, vals);
    if (!count) {
      return makeUnexpected(count.error());
    }

    std::uint32_t c = *count;
    DECLARE_LIBBPF_OPTS(
        bpf_map_batch_opts, batchOpts, .elem_flags = 0, .flags = 0);
    if (auto res = updateBatch(keys.data(), vals.data(), &c, &batchOpts);
        !res) {
      return res;
    }
    if (c != *count) {
      return makeUnexpected(
          Error(std::errc::value_too_large, "batch update count mismatch"));
    }

    return unit;
  }

  struct bpf_map* map_ = nullptr;
};

} // namespace bpfj::libbpf

namespace std {
inline void swap(
    bpfj::libbpf::BpfMap& lhs,
    bpfj::libbpf::BpfMap& rhs) noexcept {
  lhs.swap(rhs);
}

} // namespace std
