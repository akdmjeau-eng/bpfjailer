// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/err/Error.h"

// The bpfjsrv wire format, shared by Client.h and the server. A request is one
// YAML document and a reply is one more, each in its own SOCK_SEQPACKET
// datagram, so neither side has to frame or to read to EOF.
//
//   role: worker
//   user-id: alice
//   vars:
//     - vm_uuid: 550e8400-e29b-41d4-a716-446655440000
//
//   ok: true
//   uuid: 0f9d4c22-6a1e-4f0b-9c3a-1b2c3d4e5f60
//
//   ok: false
//   error: no variable named tenant is published in this jail
//
// No pid appears anywhere: the server takes it from the connection's
// SO_PEERCRED, so a client can only ever enroll itself. Header-only and free
// of any dependency a consumer would have to link, so a service can include
// Client.h and nothing else.

namespace bpfjailer::srv {

/// @brief The address bpfjsrv.socket binds, and the client's default. The
/// leading `@` is the abstract namespace, as systemd's Listen*= spells it, so
/// there is no file to create or clean up and no mode to keep anyone out:
/// every process in the network namespace can connect, and SO_PEERCRED plus
/// the role's `unpriv-enroll` policy decide what it may ask for.
inline constexpr std::string_view kDefaultSocketPath = "@bpfj";

// A request is a role, a user id and at most sixteen short variables, so
// anything approaching this is not a request this protocol can express.
inline constexpr std::size_t kMaxMessageBytes = 4096;

// Mirrors BPFJ_OSS_VAR_MAX, restated so Client.h does not drag in the BPF
// headers; Server.cpp static_asserts that the two still agree.
inline constexpr std::size_t kMaxVars = 16;

inline constexpr std::string_view kRoleField = "role";
inline constexpr std::string_view kUserIdField = "user-id";
inline constexpr std::string_view kVarsField = "vars";
inline constexpr std::string_view kOkField = "ok";
inline constexpr std::string_view kUuidField = "uuid";
inline constexpr std::string_view kErrorField = "error";

struct EnrollRequest {
  std::string role;
  std::string userId;
  std::vector<std::pair<std::string, std::string>> vars;
};

struct EnrollResponse {
  bool ok = false;
  std::string uuid;
  std::string error;
};

/// @brief Whether `value` can travel as a bare YAML scalar. The protocol
/// carries identifiers rather than free text, so it restricts every field to a
/// charset with no YAML metacharacter instead of quoting and escaping.
[[nodiscard]] inline bool isBareScalar(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }

  for (const char c : value) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
        c == '@' || c == '/' || c == '+' || c == '=';
    if (!ok) {
      return false;
    }
  }

  return true;
}

/// @brief Reject a request the wire format cannot carry.
[[nodiscard]] inline Expected<> validateRequest(
    const EnrollRequest& req) noexcept {
  if (!isBareScalar(req.role)) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "role must be a non-empty bare scalar, got '",
        req.role,
        "'"));
  }

  if (!isBareScalar(req.userId)) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "user-id must be a non-empty bare scalar, got '",
        req.userId,
        "'"));
  }

  if (req.vars.size() > kMaxVars) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "at most ",
        std::to_string(kMaxVars),
        " variables, got ",
        std::to_string(req.vars.size())));
  }

  for (std::size_t i = 0; i < req.vars.size(); ++i) {
    const auto& [name, value] = req.vars[i];
    if (!isBareScalar(name)) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "variable name must be a non-empty bare scalar, got '",
          name,
          "'"));
    }

    if (!isBareScalar(value)) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "value of variable ",
          name,
          " must be a non-empty bare scalar, got '",
          value,
          "'"));
    }

    for (std::size_t j = 0; j < i; ++j) {
      if (req.vars[j].first == name) {
        return makeUnexpected(makeError(
            std::errc::invalid_argument, "variable ", name, " is set twice"));
      }
    }
  }

  return unit;
}

/// @brief Render `req` as the request document.
[[nodiscard]] inline Expected<std::string> encodeRequest(
    const EnrollRequest& req) noexcept {
  if (auto res = validateRequest(req); !res) {
    return makeUnexpected(res.error());
  }

  std::string out;
  out.append(kRoleField).append(": ").append(req.role).append("\n");
  out.append(kUserIdField).append(": ").append(req.userId).append("\n");
  if (!req.vars.empty()) {
    out.append(kVarsField).append(":\n");
    for (const auto& [name, value] : req.vars) {
      out.append("  - ").append(name).append(": ").append(value).append("\n");
    }
  }

  if (out.size() > kMaxMessageBytes) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "request is ",
        std::to_string(out.size()),
        " bytes, over the ",
        std::to_string(kMaxMessageBytes),
        " this protocol carries"));
  }

  return out;
}

/// @brief Flatten `message` to one line of printable ASCII, the one field
/// neither side controls the shape of, so the reply stays a bare scalar.
[[nodiscard]] inline std::string sanitizeMessage(
    std::string_view message) noexcept {
  // Long enough for the errors this tree composes, short enough that a reply
  // cannot push a datagram over kMaxMessageBytes.
  constexpr std::size_t kMaxErrorBytes = 512;

  std::string out;
  out.reserve(std::min(message.size(), kMaxErrorBytes));
  for (const char c : message.substr(0, kMaxErrorBytes)) {
    out.push_back(c >= 0x20 && c <= 0x7e ? c : ' ');
  }

  return out.empty() ? std::string("unspecified failure") : out;
}

/// @brief Render the reply for a pod that was created.
[[nodiscard]] inline std::string encodeOk(std::string_view uuid) noexcept {
  std::string out;
  out.append(kOkField).append(": true\n");
  out.append(kUuidField).append(": ").append(uuid).append("\n");
  return out;
}

/// @brief Render the reply for a request that was refused.
[[nodiscard]] inline std::string encodeError(
    std::string_view message) noexcept {
  std::string out;
  out.append(kOkField).append(": false\n");
  out.append(kErrorField).append(": ").append(sanitizeMessage(message));
  out.append("\n");
  return out;
}

/// @brief Read a reply document, hand-parsed rather than handed to the YAML
/// parser so a consumer of Client.h needs nothing but the header.
[[nodiscard]] inline Expected<EnrollResponse> decodeResponse(
    std::string_view text) noexcept {
  EnrollResponse out;
  bool sawOk = false;

  while (!text.empty()) {
    const auto eol = text.find('\n');
    const std::string_view line = text.substr(0, eol);
    text = eol == std::string_view::npos ? std::string_view{}
                                         : text.substr(eol + 1);

    const auto sep = line.find(": ");
    if (sep == std::string_view::npos) {
      continue;
    }

    const std::string_view key = line.substr(0, sep);
    const std::string_view value = line.substr(sep + 2);
    if (key == kOkField) {
      out.ok = value == "true";
      sawOk = true;
    } else if (key == kUuidField) {
      out.uuid = std::string(value);
    } else if (key == kErrorField) {
      out.error = std::string(value);
    }
  }

  if (!sawOk) {
    return makeUnexpected(makeError(
        std::errc::protocol_error, "reply carried no '", kOkField, "' field"));
  }

  if (out.ok && out.uuid.empty()) {
    return makeUnexpected(makeError(
        std::errc::protocol_error, "reply reported success with no uuid"));
  }

  return out;
}

} // namespace bpfjailer::srv
