// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/lib/Base64.h"

#include <array>
#include <cctype>
#include <cstdint>

namespace bpfjailer::base64 {

namespace {

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 0-63 for an alphabet character, -1 otherwise. Built once at load rather than
// by scanning kAlphabet per character.
constexpr std::array<signed char, 256> kReverse = [] {
  std::array<signed char, 256> table{};
  for (auto& slot : table) {
    slot = -1;
  }
  for (signed char i = 0; i < 64; ++i) {
    table[static_cast<unsigned char>(kAlphabet[i])] = i;
  }
  return table;
}();

bool isSpace(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
      c == '\v';
}

} // namespace

std::string encode(const unsigned char* data, std::size_t len) {
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  std::size_t i = 0;
  for (; i + 2 < len; i += 3) {
    std::uint32_t triple = (static_cast<std::uint32_t>(data[i]) << 16) |
        (static_cast<std::uint32_t>(data[i + 1]) << 8) | data[i + 2];
    out.push_back(kAlphabet[(triple >> 18) & 0x3F]);
    out.push_back(kAlphabet[(triple >> 12) & 0x3F]);
    out.push_back(kAlphabet[(triple >> 6) & 0x3F]);
    out.push_back(kAlphabet[triple & 0x3F]);
  }
  if (i < len) {
    std::uint32_t triple = static_cast<std::uint32_t>(data[i]) << 16;
    bool two = (i + 1 < len);
    if (two) {
      triple |= static_cast<std::uint32_t>(data[i + 1]) << 8;
    }
    out.push_back(kAlphabet[(triple >> 18) & 0x3F]);
    out.push_back(kAlphabet[(triple >> 12) & 0x3F]);
    out.push_back(two ? kAlphabet[(triple >> 6) & 0x3F] : '=');
    out.push_back('=');
  }
  return out;
}

err::Expected<std::string> decode(std::string_view text) {
  std::string out;
  out.reserve((text.size() / 4) * 3);

  // The current group, packed six bits at a time. `have` counts only data
  // characters: padding contributes no bits, so folding '=' in would shift the
  // group as though it did.
  std::uint32_t group = 0;
  int have = 0;
  int padding = 0;

  for (const char c : text) {
    if (isSpace(c)) {
      continue;
    }

    if (c == '=') {
      if (++padding > 2) {
        return err::Error(
            std::errc::invalid_argument,
            "too much '=' padding in base64 input");
      }
      continue;
    }

    if (padding > 0) {
      return err::Error(
          std::errc::invalid_argument, "base64 data after padding");
    }

    const signed char value = kReverse[static_cast<unsigned char>(c)];
    if (value < 0) {
      return err::Error(
          std::errc::invalid_argument,
          "invalid base64 character '" + std::string(1, c) + "'");
    }

    group = (group << 6) | static_cast<std::uint32_t>(value);
    if (++have == 4) {
      out.push_back(static_cast<char>((group >> 16) & 0xFF));
      out.push_back(static_cast<char>((group >> 8) & 0xFF));
      out.push_back(static_cast<char>(group & 0xFF));
      group = 0;
      have = 0;
    }
  }

  // One trailing character is not a group: six bits cannot have come from a
  // whole byte.
  if (have == 1) {
    return err::Error(std::errc::invalid_argument, "truncated base64 input");
  }

  // Padding is optional, but must complete the group it closes: "QQ="
  // describes a group of three, which is not a thing.
  if (padding > 0 && have + padding != 4) {
    return err::Error(
        std::errc::invalid_argument, "misplaced '=' in base64 input");
  }

  // Two characters carry twelve bits and so one byte, three carry eighteen and
  // so two; the group's low bits are the encoder's zero fill.
  if (have == 2) {
    out.push_back(static_cast<char>((group >> 4) & 0xFF));
  } else if (have == 3) {
    out.push_back(static_cast<char>((group >> 10) & 0xFF));
    out.push_back(static_cast<char>((group >> 2) & 0xFF));
  }

  return out;
}

} // namespace bpfjailer::base64
