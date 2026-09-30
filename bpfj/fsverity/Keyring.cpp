// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/fsverity/Keyring.h"

#include <string>

#include "bpfj/fsverity/Keyctl.h"

namespace bpfjailer {

Keyring::Keyring(std::string_view prefix, std::string_view name)
    : prefix_(prefix), name_(std::string(prefix) + ":" + std::string(name)) {}

Keyring::~Keyring() = default;

err::Expected<std::vector<char>> Keyring::Key::read() const {
  auto size = keyctl::read(key_, nullptr, 0);
  if (size <= 0) {
    return err::Error::fromErrno(
        "Failed to read key " + std::to_string(key_) + " from keyring");
  }

  std::vector<char> buf(static_cast<std::size_t>(size));
  if (keyctl::read(key_, buf.data(), buf.size()) != size) {
    return err::Error::fromErrno(
        "Failed to read key " + std::to_string(key_) + " from keyring");
  }

  return buf;
}

err::Expected<> Keyring::init() {
  auto kr = keyctl::addKey(
      "keyring", name_.c_str(), nullptr, 0, keyctl::kSessionKeyring);
  if (kr < 0) {
    return err::Error::fromErrno("Failed to create keyring " + name_);
  }

  keyring_ = kr;

  return err::unit;
}

namespace {

std::int32_t& persistTarget() {
  static std::int32_t ring = keyctl::kUserKeyring;
  return ring;
}

} // namespace

void setKeyringPersistTarget(std::int32_t ring) {
  persistTarget() = ring;
}

std::int32_t keyringPersistTarget() {
  return persistTarget();
}

err::Expected<> Keyring::persist() const {
  if (keyctl::link(keyring_, persistTarget()) < 0) {
    return err::Error::fromErrno(
        "Failed to link keyring " + name_ + "-" + std::to_string(keyring_) +
        " to the persist keyring");
  }

  return err::unit;
}

err::Expected<Keyring::Key> Keyring::addKey(
    std::string_view key,
    std::string_view value) {
  auto str = prefix_ + ":" + std::string(key);
  auto k =
      keyctl::addKey("user", str.c_str(), value.data(), value.size(), keyring_);
  if (k < 0) {
    return err::Error::fromErrno(
        "Failed to add key " + std::string(key) + " to keyring " + name_ + "-" +
        std::to_string(keyring_));
  }

  return Key(k);
}

err::Expected<Keyring::Key> Keyring::addPKey(
    std::string_view key,
    std::string_view value) {
  auto str = prefix_ + ":" + std::string(key);
  auto k = keyctl::addKey(
      "asymmetric", str.c_str(), value.data(), value.size(), keyring_);
  if (k < 0) {
    return err::Error::fromErrno(
        "Failed to add key " + std::string(key) + " to keyring " + name_ + "-" +
        std::to_string(keyring_));
  }

  return Key(k);
}

void Keyring::removeKey(const Keyring::Key& key) const {
  keyctl::unlink(key.key_, keyring_);
}

void Keyring::unlink() const {
  keyctl::unlink(keyring_, keyctl::kSessionKeyring);
}

void Keyring::unlinkUser() const {
  keyctl::unlink(keyring_, persistTarget());
}

err::Expected<std::vector<Keyring::Key>> Keyring::listKeys() const {
  std::vector<Keyring::Key> keys;
  auto size = keyctl::read(keyring_, nullptr, 0);
  if (size <= 0) {
    return err::Error::fromErrno("Failed to read keyring");
  }

  std::vector<char> buf(static_cast<std::size_t>(size));
  if (keyctl::read(keyring_, buf.data(), buf.size()) != size) {
    return err::Error::fromErrno("Failed to read keyring");
  }

  // A keyring's payload is the array of serials of the keys linked into it.
  auto* ptr = reinterpret_cast<keyctl::Serial*>(buf.data());
  for (std::size_t i = 0; i < buf.size() / sizeof(keyctl::Serial); ++i) {
    keys.emplace_back(Key(ptr[i]));
  }

  return keys;
}

err::Expected<> Keyring::linkToUser() {
  // Give permission to link to the user keyring
  if (keyctl::setperm(keyring_, keyctl::kUserAll) < 0) {
    return err::Error::fromErrno("Failed to set permissions on keyring");
  }

  if (keyctl::link(keyring_, keyctl::kUserKeyring) < 0) {
    return err::Error::fromErrno(
        "Failed to link keyring " + name_ + "-" + std::to_string(keyring_) +
        " to user keyring");
  }

  return err::unit;
}

} // namespace bpfjailer
