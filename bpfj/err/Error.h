// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "bpfj/err/StdExpected.h"

// The open source Error/Expected: the standard library and nothing else. The
// closed source tree's own, at bpfjailer/err/Error.h, is backed by metarmor
// and folly::Expected and presents the same surface, so a file moving between
// the trees does not change shape:
//
//   - Error, Expected<T>, Unit, unit
//   - makeUnexpected(), so no call site names the underlying library
//   - makeError() / makeErrnoError(), which join the message from pieces
//     rather than formatting, so non-strings need an explicit std::to_string.

namespace bpfjailer {

namespace detail {

template <typename E>
concept IsErrorCode = requires(E e) {
  { std::make_error_code(e) } -> std::same_as<std::error_code>;
};

template <typename S>
concept IsStringLike = std::convertible_to<S, std::string_view>;

template <IsStringLike... Parts>
std::string concatenate(Parts&&... parts) noexcept {
  std::string message;
  message.reserve((std::string_view(parts).size() + ...));
  (message.append(std::string_view(parts)), ...);
  return message;
}

} // namespace detail

using Error = err::Error;

template <typename T = err::Unit>
using Expected = err::Expected<T>;

using Unit = err::Unit;
inline constexpr Unit unit = err::unit;

// Expected converts from Error implicitly, so this just returns the error
// unchanged; it exists so call sites read the same in both trees.
inline Error makeUnexpected(Error error) noexcept {
  return error;
}

template <detail::IsErrorCode E, detail::IsStringLike... Parts>
Error makeError(E errc, Parts&&... parts) noexcept {
  return Error(errc, detail::concatenate(std::forward<Parts>(parts)...));
}

template <detail::IsStringLike... Parts>
Error makeError(std::error_code code, Parts&&... parts) noexcept {
  return Error(code, detail::concatenate(std::forward<Parts>(parts)...));
}

template <detail::IsStringLike... Parts>
Error makeErrnoError(Parts&&... parts) noexcept {
  return Error::fromErrno(detail::concatenate(std::forward<Parts>(parts)...));
}

} // namespace bpfjailer
