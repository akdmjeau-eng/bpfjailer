// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/err/StdExpected.h"

namespace bpfjailer {

/**
 * @brief Where Keyring::persist() links, for a caller that loads in-process.
 *
 * The user keyring by default, and that is not only about lifetime. bpfjctl
 * exits as soon as load() returns, so a session keyring would go with it and
 * leave the serial in bpfj_key_map naming nothing -- but the deciding reason
 * is possession. The keyring search during signature verification is
 * permission checked against the keyrings the *verified* process possesses,
 * and in production that can be any process on the host. Only the uid's
 * keyring is possessed by all of them.
 *
 * A caller that outlives its own load and only ever verifies binaries inside
 * its own process tree -- the test harness -- can point this at a session
 * keyring instead, which its children inherit across fork and exec and which
 * the kernel reaps when the last of them exits. Nothing then accumulates in a
 * keyring shared by the whole uid.
 */
void setKeyringPersistTarget(std::int32_t ring);

/// @brief Where persist() links, for a caller that has to undo it.
[[nodiscard]] std::int32_t keyringPersistTarget();

class Keyring {
 public:
  class Key {
   public:
    err::Expected<std::vector<char>> read() const;

    std::int32_t key() const {
      return key_;
    }

   private:
    explicit Key(std::int32_t key) : key_(key) {}

    std::int32_t key_;

    friend class Keyring;
  };

  Keyring(std::string_view prefix, std::string_view name);
  ~Keyring();

  err::Expected<> init();

  /// @brief Link the keyring into the user keyring so it outlives this
  /// process, for a caller writing its serial into a BPF map, where a reaped
  /// keyring would leave the serial naming nothing. Unlike linkToUser() this
  /// leaves the permissions alone, since the kernel searches a trusted keyring
  /// with possession asserted and narrowing the mode would take away the
  /// `search` verification depends on. Linking converges on repeat.
  err::Expected<> persist() const;

  void unlink() const;

  void unlinkUser() const;

  err::Expected<Key> addKey(std::string_view key, std::string_view value);

  err::Expected<Key> addPKey(std::string_view key, std::string_view value);

  void removeKey(const Key& key) const;

  err::Expected<std::vector<Key>> listKeys() const;

  // Makes things immutable
  err::Expected<> linkToUser();

  std::int32_t keyring() const {
    return keyring_;
  }

  std::string_view name() const {
    return name_;
  }

 private:
  std::string prefix_;
  std::string name_;
  std::int32_t keyring_ = -1;
};

} // namespace bpfjailer
