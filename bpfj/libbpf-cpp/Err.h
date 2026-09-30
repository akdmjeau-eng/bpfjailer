// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "bpfj/err/StdExpected.h"

// The error vocabulary, in `libbpf`: the same names the rest of the tree
// spells over the same types, but naming `bpfjailer::err::*` directly rather
// than reaching `bpfj/err/Error.h`, whose aliases the closed source tree
// points at metarmor's types instead. Declaring them once here also keeps the
// ~250 unqualified uses across the component spelled as they were.
namespace bpfj::libbpf {

using Error = bpfjailer::err::Error;
using Unit = bpfjailer::err::Unit;

template <typename T = Unit>
using Expected = bpfjailer::err::Expected<T>;

inline constexpr Unit unit = bpfjailer::err::unit;

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

// Expected converts from Error implicitly, so this just hands the error back;
// it exists so call sites read the same as the rest of the tree's.
inline Error makeUnexpected(Error error) noexcept {
  return error;
}

// The message comes in pieces and is joined rather than formatted, nothing
// here being allowed a formatting library; non-strings need std::to_string.
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

} // namespace bpfj::libbpf
