// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <concepts>
#include <type_traits>
#include <utility>
#include <variant>

#include "bpfj/err/StdError.h"
#include "bpfj/err/Unit.h"

namespace bpfjailer::err {

template <typename T>
concept NotError = !std::same_as<std::remove_cvref_t<T>, Error>;

/// @brief Minimal Expected<T>: either a T or an Error, standing in for
/// folly::Expected<T, Error>. Construction from an Error is implicit, so
/// `return makeUnexpected(err);` reads the same against either.
template <NotError T = Unit>
class Expected {
 public:
  using value_type = T;
  using error_type = Error;

  Expected() : data_(std::in_place_index<0>) {}

  /* implicit */ Expected(const T& v) : data_(std::in_place_index<0>, v) {}
  /* implicit */ Expected(T&& v)
      : data_(std::in_place_index<0>, std::move(v)) {}

  /* implicit */ Expected(const Error& e) : data_(std::in_place_index<1>, e) {}
  /* implicit */ Expected(Error&& e)
      : data_(std::in_place_index<1>, std::move(e)) {}

  bool hasValue() const noexcept {
    return data_.index() == 0;
  }

  bool hasError() const noexcept {
    return data_.index() == 1;
  }

  explicit operator bool() const noexcept {
    return hasValue();
  }

  // Preconditions: hasValue() for the value accessors, hasError() for
  // error(). Noexcept and unchecked, so violating either dereferences a
  // nullptr where folly::Expected would throw BadExpectedAccess.
  T& operator*() & noexcept {
    return *std::get_if<0>(&data_);
  }
  const T& operator*() const& noexcept {
    return *std::get_if<0>(&data_);
  }
  T&& operator*() && noexcept {
    return std::move(*std::get_if<0>(&data_));
  }

  T* operator->() noexcept {
    return std::get_if<0>(&data_);
  }
  const T* operator->() const noexcept {
    return std::get_if<0>(&data_);
  }

  T& value() & noexcept {
    return *std::get_if<0>(&data_);
  }
  const T& value() const& noexcept {
    return *std::get_if<0>(&data_);
  }
  T&& value() && noexcept {
    return std::move(*std::get_if<0>(&data_));
  }

  Error& error() & noexcept {
    return *std::get_if<1>(&data_);
  }
  const Error& error() const& noexcept {
    return *std::get_if<1>(&data_);
  }
  Error&& error() && noexcept {
    return std::move(*std::get_if<1>(&data_));
  }

 private:
  std::variant<T, Error> data_;
};

} // namespace bpfjailer::err
