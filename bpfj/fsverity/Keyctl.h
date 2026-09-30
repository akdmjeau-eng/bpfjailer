// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/syscall.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

// add_key(2) and keyctl(2), as thin inline wrappers. glibc wraps neither, and
// libkeyutils is not packaged as a static archive on every distribution this
// tree is built on, which `make signed`'s STATIC=1 cannot route around. The
// closed source tree still uses libkeyutils, at bpfjailer/fsverity.

namespace bpfjailer::keyctl {

using Serial = std::int32_t; // key_serial_t

// The special keyring ids and command numbers from <linux/keyctl.h>, restated
// so this header stands alone, and as constants rather than macros so a
// translation unit that does include that header still compiles.
inline constexpr Serial kSessionKeyring = -3;
inline constexpr Serial kUserKeyring = -4;

// The mask granting the owner every permission, which is not in the uapi
// header at all -- the bits live in the kernel's internal key.h.
inline constexpr std::uint32_t kUserAll = 0x003f0000;

// The same for the possessor, which a keyring gets by default. Restated here
// only so a caller widening the owner's half does not drop it.
inline constexpr std::uint32_t kPossessorAll = 0x3f000000;

namespace detail {

enum Command : int {
  kJoinSessionKeyring = 1,
  kSetperm = 5,
  kLink = 8,
  kUnlink = 9,
  kSearch = 10,
  kRead = 11,
};

inline long call(
    Command cmd,
    unsigned long arg2,
    unsigned long arg3 = 0,
    unsigned long arg4 = 0,
    unsigned long arg5 = 0) {
  return ::syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
}

} // namespace detail

/// @brief Create a key of `type` and link it into `ring`. @return its serial.
[[nodiscard]] inline Serial addKey(
    const char* type,
    const char* description,
    const void* payload,
    std::size_t plen,
    Serial ring) {
  return static_cast<Serial>(
      ::syscall(__NR_add_key, type, description, payload, plen, ring));
}

/// @brief Read a key's payload, or a keyring's serials, into `buffer`.
/// @return the size of the whole payload, which can exceed `buflen` -- that is
/// how a null buffer asks for the size to allocate.
[[nodiscard]] inline long read(Serial id, char* buffer, std::size_t buflen) {
  return detail::call(
      detail::kRead,
      static_cast<unsigned long>(id),
      reinterpret_cast<unsigned long>(buffer),
      buflen);
}

/// @brief Replace the caller's session keyring with a new anonymous one,
/// inherited across fork and exec and destroyed once the last process holding
/// it exits, which is what scopes the keyrings a caller creates to its own
/// process tree rather than the uid's keyring.
/// @return the new session keyring's serial.
[[nodiscard]] inline Serial joinSessionKeyring() {
  return static_cast<Serial>(detail::call(detail::kJoinSessionKeyring, 0));
}

inline long link(Serial id, Serial ring) {
  return detail::call(
      detail::kLink,
      static_cast<unsigned long>(id),
      static_cast<unsigned long>(ring));
}

inline long unlink(Serial id, Serial ring) {
  return detail::call(
      detail::kUnlink,
      static_cast<unsigned long>(id),
      static_cast<unsigned long>(ring));
}

inline long setperm(Serial id, std::uint32_t perm) {
  return detail::call(detail::kSetperm, static_cast<unsigned long>(id), perm);
}

/// @brief Find a key by type and description, searching `ring` recursively.
[[nodiscard]] inline Serial
search(Serial ring, const char* type, const char* description, Serial dest) {
  return static_cast<Serial>(detail::call(
      detail::kSearch,
      static_cast<unsigned long>(ring),
      reinterpret_cast<unsigned long>(type),
      reinterpret_cast<unsigned long>(description),
      static_cast<unsigned long>(dest)));
}

} // namespace bpfjailer::keyctl
