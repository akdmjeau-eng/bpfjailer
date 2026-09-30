// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <string>

#include "bpfj/fsverity/Keyctl.h"
#include "bpfj/fsverity/Keyring.h"
#include "bpfj/lib/ScopeGuard.h"

using bpfjailer::Keyring;
using bpfjailer::makeGuard;
namespace keyctl = bpfjailer::keyctl;

namespace {

constexpr char kPrefix[] = "bpfj-keyring-test";

/// @brief The serial of the keyring named `name` under `ring`, or negative.
[[nodiscard]] keyctl::Serial find(
    keyctl::Serial ring,
    const std::string& name) {
  return keyctl::search(ring, "keyring", (kPrefix + (":" + name)).c_str(), 0);
}

} // namespace

TEST(Keyring, AddsReadsAndListsAKey) {
  Keyring kr(kPrefix, "add-read");
  ASSERT_OK(kr.init());
  const auto cleanup = makeGuard([&] { kr.unlink(); });

  const std::string value = "testvalue";
  auto key = kr.addKey("testkey", value);
  ASSERT_OK(key);

  auto payload = key->read();
  ASSERT_OK(payload);
  ASSERT_EQ(std::string(payload->data(), payload->size()), value);

  auto keys = kr.listKeys();
  ASSERT_OK(keys);
  ASSERT_EQ(keys->size(), 1U);
  ASSERT_EQ(keys->at(0).key(), key->key());
}

TEST(Keyring, RemoveKeyTakesOnlyTheKeyNamed) {
  Keyring kr(kPrefix, "remove");
  ASSERT_OK(kr.init());
  const auto cleanup = makeGuard([&] { kr.unlink(); });

  auto doomed = kr.addKey("doomed", "value");
  ASSERT_OK(doomed);
  auto kept = kr.addKey("kept", "value");
  ASSERT_OK(kept);

  kr.removeKey(*doomed);

  auto keys = kr.listKeys();
  ASSERT_OK(keys);
  ASSERT_EQ(keys->size(), 1U);
  ASSERT_EQ(keys->at(0).key(), kept->key());
}

TEST(Keyring, AddPKeyRejectsAPayloadThatIsNotACertificate) {
  Keyring kr(kPrefix, "pkey");
  ASSERT_OK(kr.init());
  const auto cleanup = makeGuard([&] { kr.unlink(); });

  // The kernel parses an asymmetric key's payload as DER, so a refusal here
  // is addPKey's own error path and not a contrived one.
  ASSERT(!kr.addPKey("notacert", "plainly not DER"));
}

TEST(Keyring, InitLinksIntoTheSessionKeyringAndUnlinkTakesItBack) {
  Keyring kr(kPrefix, "session");
  ASSERT_OK(kr.init());

  ASSERT_EQ(find(keyctl::kSessionKeyring, "session"), kr.keyring());

  kr.unlink();

  ASSERT(find(keyctl::kSessionKeyring, "session") < 0);
}

TEST(Keyring, PersistLinksIntoTheUserKeyring) {
  // The harness points every test's persist target at its own session
  // keyring, so the shipped default has to be asked for by name here. This
  // is the contract bpfjctl depends on: the loader exits, and the keyring
  // has to still be there for the serial in bpfj_key_map to resolve.
  bpfjailer::setKeyringPersistTarget(keyctl::kUserKeyring);
  const auto restore = makeGuard(
      [] { bpfjailer::setKeyringPersistTarget(keyctl::kSessionKeyring); });

  Keyring kr(kPrefix, "persist");
  ASSERT_OK(kr.init());
  const auto cleanup = makeGuard([&] {
    kr.unlinkUser();
    kr.unlink();
  });

  ASSERT_OK(kr.persist());

  // Matched against this keyring's own serial rather than merely found: a
  // leftover of the same name from an earlier run would answer the search
  // with a different one.
  ASSERT_EQ(find(keyctl::kUserKeyring, "persist"), kr.keyring());
}

TEST(Keyring, LinkToUserLinksIntoTheUserKeyring) {
  Keyring kr(kPrefix, "link-to-user");
  ASSERT_OK(kr.init());
  const auto cleanup = makeGuard([&] {
    kr.unlinkUser();
    kr.unlink();
  });

  ASSERT_OK(kr.linkToUser());

  ASSERT_EQ(find(keyctl::kUserKeyring, "link-to-user"), kr.keyring());
}
