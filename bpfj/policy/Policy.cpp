// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/policy/Policy.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <exception>
#include <set>
#include <string_view>
#include <utility>

#include "bpfj/lib/Base64.h"
#include "yaml/Yaml.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kBaseRole = "base-role";
constexpr std::string_view kCerts = "certs";
constexpr std::string_view kRoles = "roles";
constexpr std::string_view kVars = "vars";
constexpr std::string_view kEnforceBinaryCerts = "enforce-binary-certs";
constexpr std::string_view kAny = "any";
constexpr std::string_view kFsAny = "fs-any";
constexpr std::string_view kVerityAny = "verity-any";
constexpr std::string_view kBpfPod = "bpf-pod";
constexpr std::string_view kBpfRoles = "bpf-roles";
constexpr std::string_view kBpfAny = "bpf-any";
constexpr std::string_view kLkmAny = "lkm-any";
constexpr std::string_view kMqSysvPod = "mq-sysv-pod";
constexpr std::string_view kMqSysvRoles = "mq-sysv-roles";
constexpr std::string_view kMqSysvAny = "mq-sysv-any";
constexpr std::string_view kMqPosixPod = "mq-posix-pod";
constexpr std::string_view kMqPosixRoles = "mq-posix-roles";
constexpr std::string_view kMqPosixAny = "mq-posix-any";
constexpr std::string_view kMqPosixPattern = "mq-posix-pattern";
constexpr std::string_view kShmSysvPod = "shm-sysv-pod";
constexpr std::string_view kShmSysvRoles = "shm-sysv-roles";
constexpr std::string_view kShmSysvAny = "shm-sysv-any";
constexpr std::string_view kShmPosixPod = "shm-posix-pod";
constexpr std::string_view kShmPosixRoles = "shm-posix-roles";
constexpr std::string_view kShmPosixAny = "shm-posix-any";
constexpr std::string_view kShmPosixPattern = "shm-posix-pattern";
constexpr std::string_view kKillPod = "kill-pod";
constexpr std::string_view kKillRoles = "kill-roles";
constexpr std::string_view kKillAny = "kill-any";
constexpr std::string_view kPtracePod = "ptrace-pod";
constexpr std::string_view kPtraceRoles = "ptrace-roles";
constexpr std::string_view kPtraceAny = "ptrace-any";
constexpr std::string_view kKeyringOwn = "keyring-own";
constexpr std::string_view kKeyringRoles = "keyring-roles";
constexpr std::string_view kKeyringAny = "keyring-any";
constexpr std::string_view kUnprivEnroll = "unpriv-enroll";
constexpr std::string_view kEnrollRoles = "enroll-roles";
constexpr std::string_view kEnrollAny = "enroll-any";
constexpr std::string_view kOverrideStacked = "override-stacked";
constexpr std::string_view kUntrackedBpf = "untracked-bpf";
constexpr std::string_view kMinSeq = "min-seq";
constexpr std::string_view kPaths = "paths";
constexpr std::string_view kUnixBind = "unix-bind";
constexpr std::string_view kUnixConnect = "unix-connect";
constexpr std::string_view kUnixDgram = "unix-dgram";
constexpr std::string_view kMount = "mount";
constexpr std::string_view kUmount = "umount";

constexpr std::string_view kPemBegin = "-----BEGIN CERTIFICATE-----";
constexpr std::string_view kPemEnd = "-----END CERTIFICATE-----";

/// @brief Whether a node carries nothing a reader would call content, which
/// has to be read off the scalar's contents because a key written with no
/// value parses as a scalar holding the line break rather than None.
[[nodiscard]] bool isBlank(const Yaml::Node& node) noexcept {
  if (node.IsNone()) {
    return true;
  }

  if (!node.IsScalar()) {
    return false;
  }

  const auto value = node.As<std::string>();
  return value.find_first_not_of(" \t\n\r\f\v") == std::string::npos;
}

/// @brief Report a collection written in flow syntax, which the vendored
/// parser does not support: "[a, b]" arrives as a scalar, and every downstream
/// check then reports something misleading.
[[nodiscard]] err::Expected<err::Unit> checkNotFlow(
    const Yaml::Node& node,
    const std::string& what) noexcept {
  if (!node.IsScalar()) {
    return err::unit;
  }

  const auto value = node.As<std::string>();
  const auto first = value.find_first_not_of(" \t\n\r\f\v");
  if (first == std::string::npos ||
      (value[first] != '[' && value[first] != '{')) {
    return err::unit;
  }

  return err::Error(
      std::errc::invalid_argument,
      what + ": flow syntax is not supported, write it as an indented block");
}

/// @brief The child of `node` under `key`, or null when it was not written.
/// Yaml::Node::operator[] inserts a blank child instead, which would make
/// "left out" and "written empty" indistinguishable.
[[nodiscard]] Yaml::Node* findChild(
    Yaml::Node& node,
    std::string_view key) noexcept {
  if (!node.IsMap()) {
    return nullptr;
  }

  for (auto it = node.Begin(); it != node.End(); it++) {
    if ((*it).first == key) {
      return &(*it).second;
    }
  }

  return nullptr;
}

[[nodiscard]] err::Expected<std::map<std::string, std::string>> parseCerts(
    Yaml::Node& node) noexcept {
  std::map<std::string, std::string> certs;
  if (isBlank(node)) {
    return certs;
  }

  if (auto res = checkNotFlow(node, "'certs'"); res.hasError()) {
    return res.error();
  }

  if (!node.IsMap()) {
    return err::Error(
        std::errc::invalid_argument, "'certs' must be a map of id to X.509");
  }

  for (auto it = node.Begin(); it != node.End(); it++) {
    const auto& [id, value] = *it;
    if (!value.IsScalar()) {
      return err::Error(
          std::errc::invalid_argument, "cert '" + id + "' is not a string");
    }

    auto der = decodeCertificate(value.As<std::string>());
    if (der.hasError()) {
      return err::Error(
          der.error().code(), "cert '" + id + "': " + der.error().message());
    }

    if (der->empty()) {
      return err::Error(
          std::errc::invalid_argument, "cert '" + id + "' is empty");
    }

    certs.emplace(id, std::move(*der));
  }

  return certs;
}

/// @brief Read a block list of ids, or a bare scalar as a list of one.
[[nodiscard]] err::Expected<std::vector<std::string>> parseIdList(
    const std::string& what,
    Yaml::Node& node) noexcept {
  std::vector<std::string> ids;
  if (isBlank(node)) {
    return ids;
  }

  if (auto res = checkNotFlow(node, what); res.hasError()) {
    return res.error();
  }

  if (node.IsScalar()) {
    // A bare id, for the common single-entry case.
    ids.push_back(node.As<std::string>());
    return ids;
  }

  if (!node.IsSequence()) {
    return err::Error(
        std::errc::invalid_argument, what + " must be an id or a list of ids");
  }

  for (auto it = node.Begin(); it != node.End(); it++) {
    auto& entry = (*it).second;
    if (!entry.IsScalar()) {
      return err::Error(
          std::errc::invalid_argument, what + " entries must be ids");
    }
    ids.push_back(entry.As<std::string>());
  }

  return ids;
}

/// @brief Read the variable allowlist: names made of letters, digits and '_',
/// each written once.
[[nodiscard]] err::Expected<std::vector<std::string>> parseVars(
    Yaml::Node& node) noexcept {
  auto names = parseIdList("'vars'", node);
  if (names.hasError()) {
    return names.error();
  }

  std::set<std::string_view> seen;
  for (const auto& name : *names) {
    const bool wellFormed = !name.empty() &&
        std::all_of(name.begin(), name.end(), [](unsigned char c) {
          return std::isalnum(c) != 0 || c == '_';
        });
    if (!wellFormed) {
      return err::Error(
          std::errc::invalid_argument,
          "var '" + name + "' must be letters, digits and '_'");
    }

    if (!seen.insert(name).second) {
      return err::Error(
          std::errc::invalid_argument, "var '" + name + "' is listed twice");
    }
  }

  return names;
}

[[nodiscard]] err::Expected<std::vector<std::string>> parseCertRefs(
    const std::string& role,
    Yaml::Node& node,
    const std::map<std::string, std::string>& certs) noexcept {
  std::vector<std::string> refs;
  if (isBlank(node)) {
    return refs;
  }

  if (auto res =
          checkNotFlow(node, "role '" + role + "': enforce-binary-certs");
      res.hasError()) {
    return res.error();
  }

  if (node.IsScalar()) {
    // A bare id, for the common single-certificate case.
    refs.push_back(node.As<std::string>());
  } else if (node.IsSequence()) {
    for (auto it = node.Begin(); it != node.End(); it++) {
      auto& entry = (*it).second;
      if (!entry.IsScalar()) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + role +
                "': enforce-binary-certs entries must be cert ids");
      }
      refs.push_back(entry.As<std::string>());
    }
  } else {
    return err::Error(
        std::errc::invalid_argument,
        "role '" + role +
            "': enforce-binary-certs must be a cert id or a list");
  }

  // A typo would otherwise build a keyring short a certificate, and the role
  // would deny binaries that policy says are signed.
  for (const auto& ref : refs) {
    if (certs.find(ref) == certs.end()) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + role + "' names cert '" + ref +
              "', which is not in certs");
    }
  }

  return refs;
}

/// @brief Read a boolean flag from a role's body, spelled out rather than
/// taken through Node::As<bool>(), which answers false for anything it does
/// not recognise -- so a misspelled value would silently enforce the opposite
/// of what the policy reads as.
[[nodiscard]] err::Expected<bool> parseRoleFlag(
    const std::string& role,
    std::string_view key,
    Yaml::Node& node) noexcept {
  if (isBlank(node)) {
    return false;
  }

  if (!node.IsScalar()) {
    return err::Error(
        std::errc::invalid_argument,
        "role '" + role + "': " + std::string(key) + " must be true or false");
  }

  auto value = node.As<std::string>();

  // Neither find can return npos: isBlank() above ran the same search, so
  // what is left holds at least one other character. Worth stating because
  // substr(npos, ...) throws and this function is noexcept.
  const auto first = value.find_first_not_of(" \t\n\r\f\v");
  const auto last = value.find_last_not_of(" \t\n\r\f\v");
  value = value.substr(first, last - first + 1);
  std::transform(
      value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });

  if (value == "true" || value == "yes" || value == "1") {
    return true;
  }

  if (value == "false" || value == "no" || value == "0") {
    return false;
  }

  return err::Error(
      std::errc::invalid_argument,
      "role '" + role + "': " + std::string(key) + " is '" + value +
          "', which is neither true nor false");
}

/// @brief Read a role's `min-seq` value, rejecting anything that is not a
/// plain non-negative integer rather than letting strtoull's leniency arm the
/// check at a floor the author did not write.
[[nodiscard]] err::Expected<std::uint64_t> parseMinSeq(
    const std::string& role,
    Yaml::Node& node) noexcept {
  const std::string what = "role '" + role + "': " + std::string(kMinSeq);
  if (isBlank(node) || !node.IsScalar()) {
    return err::Error(
        std::errc::invalid_argument, what + " must be a non-negative integer");
  }

  auto text = node.As<std::string>();
  const auto first = text.find_first_not_of(" \t\n\r\f\v");
  const auto last = text.find_last_not_of(" \t\n\r\f\v");
  if (first == std::string::npos) {
    return err::Error(
        std::errc::invalid_argument, what + " must be a non-negative integer");
  }
  text = text.substr(first, last - first + 1);

  if (text.find_first_not_of("0123456789") != std::string::npos) {
    return err::Error(
        std::errc::invalid_argument,
        what + " is '" + text + "', which is not a non-negative integer");
  }

  errno = 0;
  char* end = nullptr;
  const unsigned long long value = std::strtoull(text.c_str(), &end, 10);
  if (errno != 0 || end == text.c_str() || *end != '\0') {
    return err::Error(
        std::errc::value_too_large,
        what + " is '" + text + "', which does not fit");
  }

  return static_cast<std::uint64_t>(value);
}

[[nodiscard]] err::Expected<std::map<std::string, FileMode>> parsePaths(
    const std::string& role,
    Yaml::Node& node) noexcept {
  const std::string what = "role '" + role + "': paths";
  if (isBlank(node)) {
    return std::map<std::string, FileMode>{};
  }
  if (auto res = checkNotFlow(node, what); res.hasError()) {
    return res.error();
  }
  if (!node.IsMap()) {
    return err::Error(
        std::errc::invalid_argument,
        what + " must be a map of path pattern to mode");
  }

  std::map<std::string, FileMode> paths;
  for (auto it = node.Begin(); it != node.End(); it++) {
    const auto& [path, value] = *it;
    if (path.empty()) {
      return err::Error(
          std::errc::invalid_argument, what + " contains an empty path");
    }
    if (!value.IsScalar()) {
      return err::Error(
          std::errc::invalid_argument,
          what + " mode for '" + path + "' must be a string");
    }

    const std::string mode = value.As<std::string>();
    FileMode parsedMode;
    if (mode == "NONE") {
      parsedMode = FileMode::None;
    } else if (mode == "RDONLY") {
      parsedMode = FileMode::ReadOnly;
    } else if (mode == "RDWR") {
      parsedMode = FileMode::ReadWrite;
    } else if (mode == "RDEXEC") {
      parsedMode = FileMode::ReadExec;
    } else {
      return err::Error(
          std::errc::invalid_argument,
          what + " mode for '" + path + "' is '" + mode +
              "'; expected NONE, RDONLY, RDWR or RDEXEC");
    }
    if (!paths.emplace(path, parsedMode).second) {
      return err::Error(
          std::errc::invalid_argument,
          what + " contains duplicate path '" + path + "'");
    }
  }
  return paths;
}

[[nodiscard]] err::Expected<std::map<std::string, bool>> parseUnixRules(
    const std::string& role,
    std::string_view key,
    Yaml::Node& node) noexcept {
  const std::string what = "role '" + role + "': " + std::string(key);
  if (isBlank(node)) {
    return std::map<std::string, bool>{};
  }
  if (auto res = checkNotFlow(node, what); res.hasError()) {
    return res.error();
  }
  if (!node.IsMap()) {
    return err::Error(
        std::errc::invalid_argument,
        what + " must be a map of socket name to true or false");
  }

  std::map<std::string, bool> rules;
  bool hasRoot = false;
  bool hasRootGlob = false;
  for (auto it = node.Begin(); it != node.End(); it++) {
    const auto& [writtenName, value] = *it;
    std::string name = writtenName;
    if (name.size() >= 2 &&
        ((name.front() == '\'' && name.back() == '\'') ||
         (name.front() == '"' && name.back() == '"'))) {
      name = name.substr(1, name.size() - 2);
    }
    if (name.empty() || (name.front() != '/' && name.front() != '@')) {
      return err::Error(
          std::errc::invalid_argument,
          what + " key '" + name + "' must start with '/' or '@'");
    }
    if (name == "/") {
      hasRoot = true;
    } else if (name == "/*") {
      hasRootGlob = true;
    }
    if (hasRoot && hasRootGlob) {
      return err::Error(
          std::errc::invalid_argument,
          what + " cannot contain both '/' and '/*'");
    }
    if (isBlank(value)) {
      return err::Error(
          std::errc::invalid_argument,
          what + " value for '" + name + "' must be true or false");
    }
    auto allowed = parseRoleFlag(role, key, value);
    if (allowed.hasError()) {
      return allowed.error();
    }
    if (!rules.emplace(name, *allowed).second) {
      return err::Error(
          std::errc::invalid_argument,
          what + " contains duplicate key '" + name + "'");
    }
  }
  return rules;
}

[[nodiscard]] err::Expected<std::map<std::string, std::vector<std::string>>>
parseMountRules(const std::string& role, Yaml::Node& node) noexcept {
  const std::string what = "role '" + role + "': mount";
  if (isBlank(node)) {
    return std::map<std::string, std::vector<std::string>>{};
  }
  if (auto res = checkNotFlow(node, what); res.hasError()) {
    return res.error();
  }
  if (!node.IsMap()) {
    return err::Error(
        std::errc::invalid_argument,
        what + " must be a map of destination path to filesystem type list");
  }

  std::map<std::string, std::vector<std::string>> rules;
  bool hasRoot = false;
  bool hasRootGlob = false;
  for (auto it = node.Begin(); it != node.End(); it++) {
    const auto& [writtenPath, value] = *it;
    std::string path = writtenPath;
    if (path.size() >= 2 &&
        ((path.front() == '\'' && path.back() == '\'') ||
         (path.front() == '"' && path.back() == '"'))) {
      path = path.substr(1, path.size() - 2);
    }
    if (path.empty() || path.front() != '/') {
      return err::Error(
          std::errc::invalid_argument,
          what + " key '" + path + "' must be an absolute path");
    }
    if (path == "/") {
      hasRoot = true;
    } else if (path == "/*") {
      hasRootGlob = true;
    }
    if (hasRoot && hasRootGlob) {
      return err::Error(
          std::errc::invalid_argument,
          what + " cannot contain both '/' and '/*'");
    }

    std::vector<std::string> types;
    bool explicitEmpty = false;
    if (value.IsScalar() && !isBlank(value)) {
      const std::string text = value.As<std::string>();
      const auto first = text.find_first_not_of(" \t\n\r\f\v");
      const auto last = text.find_last_not_of(" \t\n\r\f\v");
      explicitEmpty = first != std::string::npos &&
          text.substr(first, last - first + 1) == "[]";
    }
    if (!isBlank(value) && !explicitEmpty) {
      if (auto res = checkNotFlow(value, what + " value for '" + path + "'");
          res.hasError()) {
        return res.error();
      }
      if (!value.IsSequence()) {
        return err::Error(
            std::errc::invalid_argument,
            what + " value for '" + path + "' must be a list");
      }
      std::set<std::string> seen;
      for (auto typeIt = value.Begin(); typeIt != value.End(); typeIt++) {
        auto& typeNode = (*typeIt).second;
        if (!typeNode.IsScalar() || isBlank(typeNode)) {
          return err::Error(
              std::errc::invalid_argument,
              what + " filesystem types for '" + path +
                  "' must be non-empty strings");
        }
        const std::string type = typeNode.As<std::string>();
        if (type.size() >= 64) {
          return err::Error(
              std::errc::invalid_argument,
              what + " filesystem type '" + type + "' is too long");
        }
        if (!seen.insert(type).second) {
          return err::Error(
              std::errc::invalid_argument,
              what + " lists filesystem type '" + type + "' twice");
        }
        types.push_back(type);
      }
    }
    if (!rules.emplace(path, std::move(types)).second) {
      return err::Error(
          std::errc::invalid_argument,
          what + " contains destination '" + path + "' twice");
    }
  }
  return rules;
}

[[nodiscard]] err::Expected<std::map<std::string, RolePolicy>> parseRoles(
    Yaml::Node& node,
    const std::map<std::string, std::string>& certs) noexcept {
  std::map<std::string, RolePolicy> roles;
  if (isBlank(node)) {
    return roles;
  }

  if (auto res = checkNotFlow(node, "'roles'"); res.hasError()) {
    return res.error();
  }

  if (!node.IsMap()) {
    return err::Error(
        std::errc::invalid_argument,
        "'roles' must be a map of role id to policy");
  }

  for (auto it = node.Begin(); it != node.End(); it++) {
    const auto& [id, value] = *it;

    RolePolicy policy;

    // "scratch:" with nothing under it arrives as a scalar holding the line
    // break, meaning the same as an absent body: a role subject to nothing.
    if (!isBlank(value)) {
      if (auto res = checkNotFlow(value, "role '" + id + "'"); res.hasError()) {
        return res.error();
      }

      if (!value.IsMap()) {
        return err::Error(
            std::errc::invalid_argument, "role '" + id + "' must be a map");
      }

      const std::set<std::string_view> allowedKeys = {
          kAny,           kFsAny,        kVerityAny,       kEnforceBinaryCerts,
          kPaths,         kBpfPod,       kBpfRoles,        kBpfAny,
          kLkmAny,        kMqSysvPod,    kMqSysvRoles,     kMqSysvAny,
          kMqPosixPod,    kMqPosixRoles, kMqPosixAny,      kMqPosixPattern,
          kShmSysvPod,    kShmSysvRoles, kShmSysvAny,      kShmPosixPod,
          kShmPosixRoles, kShmPosixAny,  kShmPosixPattern, kKillPod,
          kKillRoles,     kKillAny,      kPtracePod,       kPtraceRoles,
          kPtraceAny,     kKeyringOwn,   kKeyringRoles,    kKeyringAny,
          kEnrollRoles,   kEnrollAny,    kUnprivEnroll,    kOverrideStacked,
          kUntrackedBpf,  kMinSeq,       kUnixBind,        kUnixConnect,
          kUnixDgram,     kMount,        kUmount,
      };
      for (auto field = value.Begin(); field != value.End(); field++) {
        const auto& [key, child] = *field;
        (void)child;
        if (!allowedKeys.contains(key)) {
          return err::Error(
              std::errc::invalid_argument,
              "role '" + id + "' has unknown option '" + key + "'");
        }
      }

      const auto parseFlag = [&](std::string_view key,
                                 bool& out) -> err::Expected<err::Unit> {
        if (Yaml::Node* flagNode = findChild(value, key)) {
          auto parsed = parseRoleFlag(id, key, *flagNode);
          if (parsed.hasError()) {
            return parsed.error();
          }
          out = *parsed;
        }
        return err::unit;
      };

      const auto parseScoped =
          [&](std::string_view podKey,
              std::string_view rolesKey,
              std::string_view anyKey,
              std::vector<std::string>& targets,
              AccessMode& mode) -> err::Expected<err::Unit> {
        bool pod = false;
        bool allowAny = false;
        if (auto res = parseFlag(podKey, pod); res.hasError()) {
          return res.error();
        }
        if (auto res = parseFlag(anyKey, allowAny); res.hasError()) {
          return res.error();
        }

        bool hasRoles = false;
        if (Yaml::Node* rolesNode = findChild(value, rolesKey)) {
          auto parsed = parseIdList(
              "role '" + id + "': " + std::string(rolesKey), *rolesNode);
          if (parsed.hasError()) {
            return parsed.error();
          }
          targets = std::move(*parsed);
          hasRoles = true;
        }

        if (static_cast<unsigned>(pod) + static_cast<unsigned>(hasRoles) +
                static_cast<unsigned>(allowAny) >
            1) {
          return err::Error(
              std::errc::invalid_argument,
              "role '" + id + "': " + std::string(podKey) + ", " +
                  std::string(rolesKey) + " and " + std::string(anyKey) +
                  " are mutually exclusive");
        }
        mode = allowAny ? AccessMode::Any
            : hasRoles  ? AccessMode::Roles
            : pod       ? AccessMode::Pod
                        : AccessMode::Deny;
        return err::unit;
      };

      if (auto res = parseFlag(kAny, policy.any); res.hasError()) {
        return res.error();
      }

      if (Yaml::Node* certRefs = findChild(value, kEnforceBinaryCerts)) {
        auto refs = parseCertRefs(id, *certRefs, certs);
        if (refs.hasError()) {
          return refs.error();
        }
        if (refs->empty()) {
          return err::Error(
              std::errc::invalid_argument,
              "role '" + id + "': enforce-binary-certs must not be empty");
        }
        policy.enforceBinaryCerts = std::move(*refs);
      }
      if (auto res = parseFlag(kVerityAny, policy.verityAny); res.hasError()) {
        return res.error();
      }
      if (policy.verityAny && !policy.enforceBinaryCerts.empty()) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id +
                "': verity-any and enforce-binary-certs are mutually exclusive");
      }

      if (Yaml::Node* paths = findChild(value, kPaths)) {
        auto parsed = parsePaths(id, *paths);
        if (parsed.hasError()) {
          return parsed.error();
        }
        policy.paths = std::move(*parsed);
        policy.hasPaths = true;
      }
      const auto parseUnix =
          [&](std::string_view key,
              std::map<std::string, bool>& rules) -> err::Expected<err::Unit> {
        if (Yaml::Node* rulesNode = findChild(value, key)) {
          auto parsed = parseUnixRules(id, key, *rulesNode);
          if (parsed.hasError()) {
            return parsed.error();
          }
          rules = std::move(*parsed);
        }
        return err::unit;
      };
      if (auto res = parseUnix(kUnixBind, policy.unixBind); res.hasError()) {
        return res.error();
      }
      if (auto res = parseUnix(kUnixConnect, policy.unixConnect);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseUnix(kUnixDgram, policy.unixDgram); res.hasError()) {
        return res.error();
      }

      if (Yaml::Node* mount = findChild(value, kMount)) {
        auto parsed = parseMountRules(id, *mount);
        if (parsed.hasError()) {
          return parsed.error();
        }
        policy.mount = std::move(*parsed);
      }
      if (Yaml::Node* umount = findChild(value, kUmount)) {
        auto allowed = parseRoleFlag(id, kUmount, *umount);
        if (allowed.hasError()) {
          return allowed.error();
        }
        policy.umount = *allowed;
        policy.hasUmount = true;
      }

      if (auto res = parseFlag(kFsAny, policy.fsAny); res.hasError()) {
        return res.error();
      }
      if (policy.fsAny && policy.hasPaths) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id + "': fs-any and paths are mutually exclusive");
      }

      if (auto res = parseScoped(
              kBpfPod, kBpfRoles, kBpfAny, policy.bpf, policy.bpfMode);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseFlag(kLkmAny, policy.lkmAny); res.hasError()) {
        return res.error();
      }
      if (auto res = parseScoped(
              kMqSysvPod,
              kMqSysvRoles,
              kMqSysvAny,
              policy.mqSysv,
              policy.mqSysvMode);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseScoped(
              kMqPosixPod,
              kMqPosixRoles,
              kMqPosixAny,
              policy.mqPosix,
              policy.mqPosixMode);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseScoped(
              kShmSysvPod,
              kShmSysvRoles,
              kShmSysvAny,
              policy.shmSysv,
              policy.shmSysvMode);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseScoped(
              kShmPosixPod,
              kShmPosixRoles,
              kShmPosixAny,
              policy.shmPosix,
              policy.shmPosixMode);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseScoped(
              kKillPod, kKillRoles, kKillAny, policy.kill, policy.killMode);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseScoped(
              kPtracePod,
              kPtraceRoles,
              kPtraceAny,
              policy.ptrace,
              policy.ptraceMode);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseScoped(
              kKeyringOwn,
              kKeyringRoles,
              kKeyringAny,
              policy.keyring,
              policy.keyringMode);
          res.hasError()) {
        return res.error();
      }

      const auto parsePatterns =
          [&](std::string_view key,
              std::vector<std::string>& patterns,
              AccessMode& mode) -> err::Expected<err::Unit> {
        if (Yaml::Node* patternNode = findChild(value, key)) {
          auto parsed = parseIdList(
              "role '" + id + "': " + std::string(key), *patternNode);
          if (parsed.hasError()) {
            return parsed.error();
          }
          if (mode == AccessMode::Any) {
            return err::Error(
                std::errc::invalid_argument,
                "role '" + id + "': " + std::string(key) +
                    " cannot be combined with the corresponding any option");
          }
          patterns = std::move(*parsed);
          if (mode == AccessMode::Deny) {
            mode = AccessMode::Pod;
          }
        }
        return err::unit;
      };
      if (auto res = parsePatterns(
              kMqPosixPattern, policy.mqPosixPatterns, policy.mqPosixMode);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parsePatterns(
              kShmPosixPattern, policy.shmPosixPatterns, policy.shmPosixMode);
          res.hasError()) {
        return res.error();
      }

      if (auto res = parseFlag(kUntrackedBpf, policy.untrackedBpf);
          res.hasError()) {
        return res.error();
      }

      bool enrollAny = false;
      if (auto res = parseFlag(kEnrollAny, enrollAny); res.hasError()) {
        return res.error();
      }
      if (Yaml::Node* enroll = findChild(value, kEnrollRoles)) {
        auto targets = parseIdList(
            "role '" + id + "': " + std::string(kEnrollRoles), *enroll);
        if (targets.hasError()) {
          return targets.error();
        }
        policy.enroll = std::move(*targets);
        policy.enrollMode = AccessMode::Roles;
      }
      if (enrollAny && policy.enrollMode != AccessMode::Deny) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id +
                "': enroll-any and enroll-roles are mutually exclusive");
      }
      if (enrollAny) {
        policy.enrollMode = AccessMode::Any;
      }

      const auto inheritAny = [&](AccessMode& mode, bool configured) {
        if (policy.any && !configured) {
          mode = AccessMode::Any;
        }
      };
      inheritAny(
          policy.bpfMode,
          findChild(value, kBpfPod) || findChild(value, kBpfRoles) ||
              findChild(value, kBpfAny));
      inheritAny(
          policy.mqSysvMode,
          findChild(value, kMqSysvPod) || findChild(value, kMqSysvRoles) ||
              findChild(value, kMqSysvAny));
      inheritAny(
          policy.mqPosixMode,
          findChild(value, kMqPosixPod) || findChild(value, kMqPosixRoles) ||
              findChild(value, kMqPosixAny) ||
              findChild(value, kMqPosixPattern));
      inheritAny(
          policy.shmSysvMode,
          findChild(value, kShmSysvPod) || findChild(value, kShmSysvRoles) ||
              findChild(value, kShmSysvAny));
      inheritAny(
          policy.shmPosixMode,
          findChild(value, kShmPosixPod) || findChild(value, kShmPosixRoles) ||
              findChild(value, kShmPosixAny) ||
              findChild(value, kShmPosixPattern));
      inheritAny(
          policy.killMode,
          findChild(value, kKillPod) || findChild(value, kKillRoles) ||
              findChild(value, kKillAny));
      inheritAny(
          policy.ptraceMode,
          findChild(value, kPtracePod) || findChild(value, kPtraceRoles) ||
              findChild(value, kPtraceAny));
      inheritAny(
          policy.keyringMode,
          findChild(value, kKeyringOwn) || findChild(value, kKeyringRoles) ||
              findChild(value, kKeyringAny));
      inheritAny(
          policy.enrollMode,
          findChild(value, kEnrollRoles) || findChild(value, kEnrollAny));
      if (policy.any) {
        if (!findChild(value, kLkmAny)) {
          policy.lkmAny = true;
        }
        if (!findChild(value, kPaths) && !findChild(value, kFsAny)) {
          policy.fsAny = true;
        }
        if (!findChild(value, kEnforceBinaryCerts) &&
            !findChild(value, kVerityAny)) {
          policy.verityAny = true;
        }
      }
      if (policy.untrackedBpf && policy.bpfMode == AccessMode::Deny) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id +
                "': untracked-bpf needs bpf-pod, bpf-roles, bpf-any or any");
      }

      // Absent is the same as false, as for the flags above: a role that says
      // nothing about stacking takes its place in the vote like any other.
      if (Yaml::Node* override = findChild(value, kOverrideStacked)) {
        auto wins = parseRoleFlag(id, kOverrideStacked, *override);
        if (wins.hasError()) {
          return wins.error();
        }
        policy.overrideStacked = *wins;
      }

      // Absent is the same as false here, unlike the two above: a role
      // nobody opened up is one only root may enroll in.
      if (Yaml::Node* unprivEnroll = findChild(value, kUnprivEnroll)) {
        auto allowed = parseRoleFlag(id, kUnprivEnroll, *unprivEnroll);
        if (allowed.hasError()) {
          return allowed.error();
        }
        policy.unprivEnroll = *allowed;
      }

      if (Yaml::Node* minSeq = findChild(value, kMinSeq)) {
        auto floor = parseMinSeq(id, *minSeq);
        if (floor.hasError()) {
          return floor.error();
        }
        policy.minSeq = *floor;
        policy.hasMinSeq = true;
      }

      // A sequence number is carried by a signature, so without a certificate
      // to check it against the key would arm a gate nothing ever reaches.
      if (policy.hasMinSeq && policy.enforceBinaryCerts.empty()) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id + "': " + std::string(kMinSeq) + " needs " +
                std::string(kEnforceBinaryCerts) +
                ", or nothing would be sequence-checked");
      }
    }

    roles.emplace(id, std::move(policy));
  }

  return roles;
}

/// @brief Reject a role reference that names no role, which would otherwise
/// read as a role that owns and runs nothing and quietly grant nothing.
/// `what` reads into the message as "role 'x' <what> 'y'".
[[nodiscard]] err::Expected<err::Unit> checkRoleRefs(
    const std::map<std::string, RolePolicy>& roles,
    const std::string& id,
    const std::vector<std::string>& refs,
    std::string_view what) noexcept {
  for (const auto& target : refs) {
    if (roles.find(target) == roles.end()) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + id + "' " + std::string(what) + " '" + target +
              "', which is not in roles");
    }
  }

  return err::unit;
}

[[nodiscard]] err::Expected<Policy> parseRoot(Yaml::Node& root) noexcept {
  if (!root.IsMap() && !root.IsNone()) {
    return err::Error(
        std::errc::invalid_argument, "policy must be a map of certs and roles");
  }

  Policy policy;

  auto certs = parseCerts(root[std::string(kCerts)]);
  if (certs.hasError()) {
    return certs.error();
  }
  policy.certs = std::move(*certs);

  auto roles = parseRoles(root[std::string(kRoles)], policy.certs);
  if (roles.hasError()) {
    return roles.error();
  }
  policy.roles = std::move(*roles);

  // Once every role is known, since a role may name one defined later.
  for (const auto& [id, rolePolicy] : policy.roles) {
    if (auto res = checkRoleRefs(
            policy.roles, id, rolePolicy.bpf, "allows BPF access to");
        res.hasError()) {
      return res.error();
    }

    if (auto res = checkRoleRefs(
            policy.roles,
            id,
            rolePolicy.mqSysv,
            "allows System V message-queue access to");
        res.hasError()) {
      return res.error();
    }

    if (auto res = checkRoleRefs(
            policy.roles,
            id,
            rolePolicy.mqPosix,
            "allows POSIX message-queue access to");
        res.hasError()) {
      return res.error();
    }

    if (auto res = checkRoleRefs(
            policy.roles,
            id,
            rolePolicy.shmSysv,
            "allows System V shared-memory access to");
        res.hasError()) {
      return res.error();
    }

    if (auto res = checkRoleRefs(
            policy.roles,
            id,
            rolePolicy.shmPosix,
            "allows POSIX shared-memory access to");
        res.hasError()) {
      return res.error();
    }

    if (auto res =
            checkRoleRefs(policy.roles, id, rolePolicy.kill, "allows killing");
        res.hasError()) {
      return res.error();
    }

    if (auto res = checkRoleRefs(
            policy.roles, id, rolePolicy.ptrace, "allows ptracing");
        res.hasError()) {
      return res.error();
    }

    if (auto res = checkRoleRefs(
            policy.roles, id, rolePolicy.keyring, "allows keyring writes to");
        res.hasError()) {
      return res.error();
    }

    if (auto res = checkRoleRefs(
            policy.roles, id, rolePolicy.enroll, "allows enrolling in");
        res.hasError()) {
      return res.error();
    }
  }

  auto vars = parseVars(root[std::string(kVars)]);
  if (vars.hasError()) {
    return vars.error();
  }
  policy.vars = std::move(*vars);

  Yaml::Node& baseRole = root[std::string(kBaseRole)];
  if (!isBlank(baseRole)) {
    if (!baseRole.IsScalar()) {
      return err::Error(
          std::errc::invalid_argument, "'base-role' must be a role id");
    }

    policy.baseRole = baseRole.As<std::string>();

    // Unlike a mistyped cert id this fails quietly: an unknown base role is
    // still applied host-wide, just without the policy meant to go with it.
    if (policy.roles.find(policy.baseRole) == policy.roles.end()) {
      return err::Error(
          std::errc::invalid_argument,
          "base-role '" + policy.baseRole + "' is not in roles");
    }
  }

  return policy;
}

} // namespace

err::Expected<std::string> decodeCertificate(std::string_view text) noexcept {
  const auto begin = text.find(kPemBegin);
  if (begin == std::string_view::npos) {
    return base64::decode(text);
  }

  const auto bodyStart = begin + kPemBegin.size();
  const auto end = text.find(kPemEnd, bodyStart);
  if (end == std::string_view::npos) {
    return err::Error(
        std::errc::invalid_argument, "PEM certificate has no END line");
  }

  return base64::decode(text.substr(bodyStart, end - bodyStart));
}

err::Expected<Policy> Policy::parseFile(const std::string& path) noexcept {
  Yaml::Node root;
  try {
    Yaml::Parse(root, path.c_str());
  } catch (const std::exception& e) {
    return err::Error(
        std::errc::invalid_argument,
        "failed to read policy " + path + ": " + e.what());
  }

  auto policy = parseRoot(root);
  if (policy.hasError()) {
    return err::Error(
        policy.error().code(), path + ": " + policy.error().message());
  }

  return policy;
}

err::Expected<Policy> Policy::parse(const std::string& text) noexcept {
  Yaml::Node root;
  try {
    Yaml::Parse(root, text);
  } catch (const std::exception& e) {
    return err::Error(
        std::errc::invalid_argument,
        std::string("failed to parse policy: ") + e.what());
  }

  return parseRoot(root);
}

} // namespace bpfjailer
