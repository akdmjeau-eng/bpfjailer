// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include "bpfj/err/StdExpected.h"

namespace bpfjailer::base64 {

/// @brief Standard alphabet, padded, as folly::base64Encode produces, which
/// is what tooling reading fs-verity digests back expects.
std::string encode(const unsigned char* data, std::size_t len);

/// @brief Decode standard-alphabet base64, skipping whitespace so a PEM body
/// can be handed over with its line breaks intact. A stray character, bad
/// padding or a truncated group is an error, since dropping those silently
/// would turn a mistyped certificate into one the kernel rejects with nothing
/// to point at.
err::Expected<std::string> decode(std::string_view text);

} // namespace bpfjailer::base64
