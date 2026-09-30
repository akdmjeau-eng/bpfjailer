// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cerrno>
#include <concepts>
#include <ostream>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

namespace bpfjailer::err {

namespace detail {

// Anything make_error_code() accepts -- std::errc, std::io_errc and, where
// <future> is in scope, std::future_errc -- as a requirement rather than a
// list, so this header need not include <future>. std::error_code is not
// itself convertible, so the enum overloads never compete with its own.
template <typename E>
concept IsErrorCode = requires(E e) {
  { std::make_error_code(e) } -> std::same_as<std::error_code>;
};

} // namespace detail

/// @brief An std::error_code paired with a message, interchangeable with
/// metarmor's Error at every call site here but built on nothing but the
/// standard library, which is what lets the open source build drop folly, fmt
/// and metarmor. The code is kept apart from the message and joined only when
/// streamed, so `os << error` reads the same in both builds.
class Error {
 public:
  explicit Error(std::error_code code) noexcept
      : code_(code), message_(code.message()) {}

  template <detail::IsErrorCode E>
  explicit Error(E errc) noexcept {
    using std::make_error_code;
    code_ = make_error_code(errc);
    message_ = code_.message();
  }

  Error(std::error_code code, std::string message) noexcept
      : code_(code), message_(std::move(message)) {}

  template <detail::IsErrorCode E>
  Error(E errc, std::string message) noexcept : message_(std::move(message)) {
    using std::make_error_code;
    code_ = make_error_code(errc);
  }

  /// @brief Build an Error from the current errno.
  static Error fromErrno(std::string message) noexcept {
    return Error(std::errc(errno), std::move(message));
  }

  const std::error_code& code() const noexcept {
    return code_;
  }

  const char* what() const noexcept {
    return message_.c_str();
  }

  const std::string& message() const noexcept {
    return message_;
  }

  std::string str() const noexcept {
    return message_;
  }

 private:
  std::error_code code_;
  std::string message_;
};

inline std::ostream& operator<<(std::ostream& os, const Error& error) {
  return os << error.code().message() << ": " << error.message();
}

} // namespace bpfjailer::err
