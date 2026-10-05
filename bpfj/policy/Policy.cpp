// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/policy/Policy.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <exception>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "bpfj/lib/Base64.h"
#include "toml/toml.hpp"

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
constexpr std::string_view kProcPod = "proc-pod";
constexpr std::string_view kProcRoles = "proc-roles";
constexpr std::string_view kAnyProc = "any-proc";
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
constexpr std::string_view kExecPaths = "exec-paths";
constexpr std::string_view kExecAny = "exec-any";
constexpr std::string_view kPath = "path";
constexpr std::string_view kAllow = "allow";
constexpr std::string_view kExec = "exec";
constexpr std::string_view kSetId = "set-id";
constexpr std::string_view kSharedObject = "shared-object";
constexpr std::string_view kUnixBind = "unix-bind";
constexpr std::string_view kUnixConnect = "unix-connect";
constexpr std::string_view kUnixDgram = "unix-dgram";
constexpr std::string_view kMount = "mount";
constexpr std::string_view kMountAny = "mount-any";
constexpr std::string_view kUmount = "umount";
constexpr std::string_view kUmountAny = "umount-any";

constexpr std::string_view kPemBegin = "-----BEGIN CERTIFICATE-----";
constexpr std::string_view kPemEnd = "-----END CERTIFICATE-----";

[[nodiscard]] const toml::node* findChild(
    const toml::table& table,
    std::string_view key) noexcept {
  return table.get(key);
}

[[nodiscard]] err::Expected<std::string> parseString(
    const toml::node* node,
    const std::string& what) noexcept {
  if (node == nullptr || !node->is_string()) {
    return err::Error(std::errc::invalid_argument, what + " must be a string");
  }
  return node->value<std::string>().value();
}

[[nodiscard]] err::Expected<std::vector<std::string>> parseIdList(
    const std::string& what,
    const toml::node* node) noexcept {
  std::vector<std::string> ids;
  if (node == nullptr) {
    return ids;
  }
  if (node->is_string()) {
    ids.push_back(node->value<std::string>().value());
    return ids;
  }
  const auto* array = node->as_array();
  if (array == nullptr) {
    return err::Error(
        std::errc::invalid_argument,
        what + " must be an id or an array of ids");
  }
  for (const auto& entry : *array) {
    if (!entry.is_string()) {
      return err::Error(
          std::errc::invalid_argument, what + " entries must be ids");
    }
    ids.push_back(entry.value<std::string>().value());
  }
  return ids;
}

[[nodiscard]] err::Expected<std::vector<std::string>> parseVars(
    const toml::node* node) noexcept {
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

[[nodiscard]] err::Expected<std::map<std::string, std::string>> parseCerts(
    const toml::node* node) noexcept {
  std::map<std::string, std::string> certs;
  if (node == nullptr) {
    return certs;
  }
  const auto* table = node->as_table();
  if (table == nullptr) {
    return err::Error(
        std::errc::invalid_argument, "'certs' must be a table of id to X.509");
  }
  for (const auto& [key, value] : *table) {
    const std::string id{key.str()};
    auto encoded = parseString(&value, "cert '" + id + "'");
    if (encoded.hasError()) {
      return encoded.error();
    }
    auto der = decodeCertificate(*encoded);
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

[[nodiscard]] err::Expected<std::vector<std::string>> parseCertRefs(
    const std::string& role,
    const toml::node* node,
    const std::map<std::string, std::string>& certs) noexcept {
  auto refs = parseIdList("role '" + role + "': enforce-binary-certs", node);
  if (refs.hasError()) {
    return refs.error();
  }
  for (const auto& ref : *refs) {
    if (!certs.contains(ref)) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + role + "' names cert '" + ref +
              "', which is not in certs");
    }
  }
  return refs;
}

[[nodiscard]] err::Expected<bool> parseRoleFlag(
    const std::string& role,
    std::string_view key,
    const toml::node* node) noexcept {
  if (node == nullptr || !node->is_boolean()) {
    return err::Error(
        std::errc::invalid_argument,
        "role '" + role + "': " + std::string(key) + " must be true or false");
  }
  return node->value<bool>().value();
}

[[nodiscard]] err::Expected<std::uint64_t> parseMinSeq(
    const std::string& role,
    const toml::node* node) noexcept {
  const std::string what = "role '" + role + "': " + std::string(kMinSeq);
  if (node == nullptr || !node->is_integer()) {
    return err::Error(
        std::errc::invalid_argument, what + " must be a non-negative integer");
  }
  const auto value = node->value<std::int64_t>().value();
  if (value < 0) {
    return err::Error(
        std::errc::invalid_argument, what + " must be a non-negative integer");
  }
  return static_cast<std::uint64_t>(value);
}

[[nodiscard]] err::Expected<err::Unit> validatePathPattern(
    const std::string& what,
    const std::string& path) noexcept {
  if (path.empty() || path.front() != '/') {
    return err::Error(
        std::errc::invalid_argument,
        what + " path '" + path + "' must start with '/'");
  }
  if (path.find("**") != std::string::npos) {
    return err::Error(
        std::errc::invalid_argument,
        what + " path '" + path +
            "' uses unsupported '**'; use a directory path for its subtree "
            "or '*' for one component");
  }
  return err::unit;
}

[[nodiscard]] err::Expected<std::map<std::string, FileMode>> parsePaths(
    const std::string& role,
    const toml::node* node) noexcept {
  const std::string what = "role '" + role + "': paths";
  const auto* table = node != nullptr ? node->as_table() : nullptr;
  if (table == nullptr) {
    return err::Error(
        std::errc::invalid_argument,
        what + " must be a table of path pattern to mode");
  }
  std::map<std::string, FileMode> paths;
  for (const auto& [key, value] : *table) {
    const std::string path{key.str()};
    if (auto valid = validatePathPattern(what, path); valid.hasError()) {
      return valid.error();
    }
    auto mode = parseString(&value, what + " mode for '" + path + "'");
    if (mode.hasError()) {
      return mode.error();
    }
    FileMode parsed;
    if (*mode == "NONE") {
      parsed = FileMode::None;
    } else if (*mode == "RDONLY") {
      parsed = FileMode::ReadOnly;
    } else if (*mode == "RDWR") {
      parsed = FileMode::ReadWrite;
    } else {
      return err::Error(
          std::errc::invalid_argument,
          what + " mode for '" + path + "' is '" + *mode +
              "'; expected NONE, RDONLY or RDWR");
    }
    paths.emplace(path, parsed);
  }
  return paths;
}

[[nodiscard]] err::Expected<std::map<std::string, ExecPathPolicy>>
parseExecPaths(const std::string& role, const toml::node* node) noexcept {
  const std::string what = "role '" + role + "': exec-paths";
  const auto* rules = node != nullptr ? node->as_array() : nullptr;
  if (rules == nullptr) {
    return err::Error(
        std::errc::invalid_argument, what + " must be an array of rule tables");
  }
  if (rules->empty()) {
    return err::Error(
        std::errc::invalid_argument, what + " must contain at least one rule");
  }

  std::map<std::string, ExecPathPolicy> paths;
  for (const auto& ruleNode : *rules) {
    const auto* rule = ruleNode.as_table();
    if (rule == nullptr) {
      return err::Error(
          std::errc::invalid_argument, what + " entries must be rule tables");
    }
    const std::set<std::string_view> allowedKeys = {kPath, kAllow};
    for (const auto& [key, child] : *rule) {
      (void)child;
      if (!allowedKeys.contains(key.str())) {
        return err::Error(
            std::errc::invalid_argument,
            what + " rule has unknown option '" + std::string(key.str()) + "'");
      }
    }

    auto pathValue = parseString(findChild(*rule, kPath), what + " rule path");
    if (pathValue.hasError()) {
      return pathValue.error();
    }
    const std::string path = std::move(*pathValue);
    if (auto valid = validatePathPattern(what, path); valid.hasError()) {
      return valid.error();
    }

    ExecPathPolicy parsed;
    std::set<std::string> seen;
    const auto* allowNode = findChild(*rule, kAllow);
    const auto* permissions =
        allowNode != nullptr ? allowNode->as_array() : nullptr;
    if (permissions == nullptr) {
      return err::Error(
          std::errc::invalid_argument,
          what + " rule for '" + path + "': allow must be an array");
    }
    for (const auto& permissionNode : *permissions) {
      if (!permissionNode.is_string()) {
        return err::Error(
            std::errc::invalid_argument,
            what + " rule for '" + path + "': allow entries must be strings");
      }
      const std::string permission =
          permissionNode.value<std::string>().value();
      if (!seen.insert(permission).second) {
        return err::Error(
            std::errc::invalid_argument,
            what + " rule for '" + path + "' lists permission '" + permission +
                "' twice");
      }
      if (permission == kExec) {
        parsed.allowExec = true;
      } else if (permission == kSetId) {
        parsed.allowSetuid = true;
      } else if (permission == kSharedObject) {
        parsed.allowSharedObject = true;
      } else {
        return err::Error(
            std::errc::invalid_argument,
            what + " rule for '" + path + "' has unknown permission '" +
                permission + "'");
      }
    }
    if (parsed.allowSetuid && !parsed.allowExec) {
      return err::Error(
          std::errc::invalid_argument,
          what + " rule for '" + path + "': set-id requires exec");
    }
    if (!paths.emplace(path, parsed).second) {
      return err::Error(
          std::errc::invalid_argument,
          what + " contains path '" + path + "' twice");
    }
  }
  return paths;
}

[[nodiscard]] err::Expected<std::map<std::string, bool>> parseUnixRules(
    const std::string& role,
    std::string_view key,
    const toml::node* node) noexcept {
  const std::string what = "role '" + role + "': " + std::string(key);
  const auto* table = node != nullptr ? node->as_table() : nullptr;
  if (table == nullptr) {
    return err::Error(
        std::errc::invalid_argument,
        what + " must be a table of socket name to true or false");
  }
  std::map<std::string, bool> rules;
  bool hasRoot = false;
  bool hasRootGlob = false;
  for (const auto& [nameKey, value] : *table) {
    const std::string name{nameKey.str()};
    if (name.empty() || (name.front() != '/' && name.front() != '@')) {
      return err::Error(
          std::errc::invalid_argument,
          what + " key '" + name + "' must start with '/' or '@'");
    }
    hasRoot = hasRoot || name == "/";
    hasRootGlob = hasRootGlob || name == "/*";
    if (hasRoot && hasRootGlob) {
      return err::Error(
          std::errc::invalid_argument,
          what + " cannot contain both '/' and '/*'");
    }
    auto allowed = parseRoleFlag(role, key, &value);
    if (allowed.hasError()) {
      return allowed.error();
    }
    rules.emplace(name, *allowed);
  }
  return rules;
}

[[nodiscard]] err::Expected<std::map<std::string, std::vector<std::string>>>
parseMountRules(const std::string& role, const toml::node* node) noexcept {
  const std::string what = "role '" + role + "': mount";
  const auto* table = node != nullptr ? node->as_table() : nullptr;
  if (table == nullptr) {
    return err::Error(
        std::errc::invalid_argument,
        what + " must be a table of destination path to filesystem type array");
  }
  std::map<std::string, std::vector<std::string>> rules;
  bool hasRoot = false;
  bool hasRootGlob = false;
  for (const auto& [pathKey, value] : *table) {
    const std::string path{pathKey.str()};
    if (path.empty() || path.front() != '/') {
      return err::Error(
          std::errc::invalid_argument,
          what + " key '" + path + "' must be an absolute path");
    }
    hasRoot = hasRoot || path == "/";
    hasRootGlob = hasRootGlob || path == "/*";
    if (hasRoot && hasRootGlob) {
      return err::Error(
          std::errc::invalid_argument,
          what + " cannot contain both '/' and '/*'");
    }
    const auto* array = value.as_array();
    if (array == nullptr) {
      return err::Error(
          std::errc::invalid_argument,
          what + " value for '" + path + "' must be an array");
    }
    std::vector<std::string> types;
    std::set<std::string> seen;
    for (const auto& typeNode : *array) {
      if (!typeNode.is_string()) {
        return err::Error(
            std::errc::invalid_argument,
            what + " filesystem types for '" + path + "' must be strings");
      }
      std::string type = typeNode.value<std::string>().value();
      if (type.empty() || type.size() >= 64) {
        return err::Error(
            std::errc::invalid_argument,
            what + " filesystem type '" + type + "' is empty or too long");
      }
      if (type == "any") {
        type = "ANY";
      }
      if (!seen.insert(type).second) {
        return err::Error(
            std::errc::invalid_argument,
            what + " lists filesystem type '" + type + "' twice");
      }
      types.push_back(type);
    }
    rules.emplace(path, std::move(types));
  }
  return rules;
}

[[nodiscard]] err::Expected<std::map<std::string, bool>> parseUmountRules(
    const std::string& role,
    const toml::node* node) noexcept {
  const std::string what = "role '" + role + "': umount";
  const auto* table = node != nullptr ? node->as_table() : nullptr;
  if (table == nullptr) {
    return err::Error(
        std::errc::invalid_argument,
        what + " must be a table of mountpoint pattern to NONE or ANY");
  }
  std::map<std::string, bool> rules;
  bool hasRoot = false;
  bool hasRootGlob = false;
  for (const auto& [pathKey, value] : *table) {
    const std::string path{pathKey.str()};
    if (path.empty() || path.front() != '/') {
      return err::Error(
          std::errc::invalid_argument,
          what + " path '" + path + "' must be absolute");
    }
    hasRoot = hasRoot || path == "/";
    hasRootGlob = hasRootGlob || path == "/*";
    if (hasRoot && hasRootGlob) {
      return err::Error(
          std::errc::invalid_argument,
          what + " cannot contain both '/' and '/*'");
    }
    auto permission =
        parseString(&value, what + " permission for '" + path + "'");
    if (permission.hasError()) {
      return permission.error();
    }
    bool allowed;
    if (*permission == "ANY" || *permission == "any") {
      allowed = true;
    } else if (*permission == "NONE" || *permission == "none") {
      allowed = false;
    } else {
      return err::Error(
          std::errc::invalid_argument,
          what + " permission for '" + path + "' is '" + *permission +
              "'; expected NONE or ANY");
    }
    rules.emplace(path, allowed);
  }
  return rules;
}

[[nodiscard]] err::Expected<std::map<std::string, RolePolicy>> parseRoles(
    const toml::node* node,
    const std::map<std::string, std::string>& certs) noexcept {
  std::map<std::string, RolePolicy> roles;
  if (node == nullptr) {
    return roles;
  }
  const auto* table = node->as_table();
  if (table == nullptr) {
    return err::Error(
        std::errc::invalid_argument, "'roles' must be a table of role ids");
  }
  for (const auto& [roleKey, value] : *table) {
    const std::string id{roleKey.str()};
    const auto* body = value.as_table();
    if (body == nullptr) {
      return err::Error(
          std::errc::invalid_argument, "role '" + id + "' must be a table");
    }
    RolePolicy policy;
    const std::set<std::string_view> allowedKeys = {
        kAny,           kFsAny,        kVerityAny,       kEnforceBinaryCerts,
        kPaths,         kBpfPod,       kBpfRoles,        kBpfAny,
        kLkmAny,        kMqSysvPod,    kMqSysvRoles,     kMqSysvAny,
        kMqPosixPod,    kMqPosixRoles, kMqPosixAny,      kMqPosixPattern,
        kShmSysvPod,    kShmSysvRoles, kShmSysvAny,      kShmPosixPod,
        kShmPosixRoles, kShmPosixAny,  kShmPosixPattern, kKillPod,
        kKillRoles,     kKillAny,      kPtracePod,       kPtraceRoles,
        kPtraceAny,     kProcPod,      kProcRoles,       kAnyProc,
        kKeyringOwn,    kKeyringRoles, kKeyringAny,      kEnrollRoles,
        kEnrollAny,     kUnprivEnroll, kOverrideStacked, kUntrackedBpf,
        kMinSeq,        kUnixBind,     kUnixConnect,     kUnixDgram,
        kMount,         kMountAny,     kUmount,          kUmountAny,
        kExecPaths,     kExecAny,
    };
    for (const auto& [key, child] : *body) {
      (void)child;
      if (!allowedKeys.contains(key.str())) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id + "' has unknown option '" + std::string(key.str()) +
                "'");
      }
    }
    const auto parseFlag = [&](std::string_view key,
                               bool& out) -> err::Expected<err::Unit> {
      if (const auto* flag = findChild(*body, key)) {
        auto parsed = parseRoleFlag(id, key, flag);
        if (parsed.hasError()) {
          return parsed.error();
        }
        out = *parsed;
      }
      return err::unit;
    };
    const auto parseScoped = [&](std::string_view podKey,
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
      const auto* rolesNode = findChild(*body, rolesKey);
      const bool hasRoles = rolesNode != nullptr;
      if (hasRoles) {
        auto parsed = parseIdList(
            "role '" + id + "': " + std::string(rolesKey), rolesNode);
        if (parsed.hasError()) {
          return parsed.error();
        }
        targets = std::move(*parsed);
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
    if (const auto* child = findChild(*body, kEnforceBinaryCerts)) {
      auto refs = parseCertRefs(id, child, certs);
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
    if (const auto* child = findChild(*body, kPaths)) {
      auto parsed = parsePaths(id, child);
      if (parsed.hasError()) {
        return parsed.error();
      }
      policy.paths = std::move(*parsed);
      policy.hasPaths = true;
    }
    if (const auto* child = findChild(*body, kExecPaths)) {
      auto parsed = parseExecPaths(id, child);
      if (parsed.hasError()) {
        return parsed.error();
      }
      policy.execPaths = std::move(*parsed);
      policy.hasExecPaths = true;
    }
    if (auto res = parseFlag(kExecAny, policy.execAny); res.hasError()) {
      return res.error();
    }
    if (policy.execAny && policy.hasExecPaths) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + id + "': exec-any and exec-paths are mutually exclusive");
    }
    const auto parseUnix =
        [&](std::string_view key,
            std::map<std::string, bool>& rules) -> err::Expected<err::Unit> {
      if (const auto* child = findChild(*body, key)) {
        auto parsed = parseUnixRules(id, key, child);
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
    if (const auto* child = findChild(*body, kMount)) {
      auto parsed = parseMountRules(id, child);
      if (parsed.hasError()) {
        return parsed.error();
      }
      policy.mount = std::move(*parsed);
      policy.hasMount = true;
    }
    if (auto res = parseFlag(kMountAny, policy.mountAny); res.hasError()) {
      return res.error();
    }
    if (findChild(*body, kMount) && findChild(*body, kMountAny)) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + id + "': mount and mount-any are mutually exclusive");
    }
    if (const auto* child = findChild(*body, kUmount)) {
      auto parsed = parseUmountRules(id, child);
      if (parsed.hasError()) {
        return parsed.error();
      }
      policy.umount = std::move(*parsed);
      policy.hasUmount = true;
    }
    if (auto res = parseFlag(kUmountAny, policy.umountAny); res.hasError()) {
      return res.error();
    }
    if (findChild(*body, kUmount) && findChild(*body, kUmountAny)) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + id + "': umount and umount-any are mutually exclusive");
    }
    if (auto res = parseFlag(kFsAny, policy.fsAny); res.hasError()) {
      return res.error();
    }
    if (policy.fsAny && policy.hasPaths) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + id + "': fs-any and paths are mutually exclusive");
    }
    const auto parseScope = [&](std::string_view pod,
                                std::string_view rolesKey,
                                std::string_view any,
                                std::vector<std::string>& targets,
                                AccessMode& mode) -> err::Expected<err::Unit> {
      return parseScoped(pod, rolesKey, any, targets, mode);
    };
    if (auto res =
            parseScope(kBpfPod, kBpfRoles, kBpfAny, policy.bpf, policy.bpfMode);
        res.hasError()) {
      return res.error();
    }
    if (auto res = parseFlag(kLkmAny, policy.lkmAny); res.hasError()) {
      return res.error();
    }
    const struct Scoped {
      std::string_view pod;
      std::string_view roles;
      std::string_view any;
      std::vector<std::string>* targets;
      AccessMode* mode;
    } scoped[] = {
        {kMqSysvPod,
         kMqSysvRoles,
         kMqSysvAny,
         &policy.mqSysv,
         &policy.mqSysvMode},
        {kMqPosixPod,
         kMqPosixRoles,
         kMqPosixAny,
         &policy.mqPosix,
         &policy.mqPosixMode},
        {kShmSysvPod,
         kShmSysvRoles,
         kShmSysvAny,
         &policy.shmSysv,
         &policy.shmSysvMode},
        {kShmPosixPod,
         kShmPosixRoles,
         kShmPosixAny,
         &policy.shmPosix,
         &policy.shmPosixMode},
        {kKillPod, kKillRoles, kKillAny, &policy.kill, &policy.killMode},
        {kPtracePod,
         kPtraceRoles,
         kPtraceAny,
         &policy.ptrace,
         &policy.ptraceMode},
        {kProcPod, kProcRoles, kAnyProc, &policy.proc, &policy.procMode},
        {kKeyringOwn,
         kKeyringRoles,
         kKeyringAny,
         &policy.keyring,
         &policy.keyringMode},
    };
    for (const auto& entry : scoped) {
      if (auto res = parseScope(
              entry.pod, entry.roles, entry.any, *entry.targets, *entry.mode);
          res.hasError()) {
        return res.error();
      }
    }
    const auto parsePatterns =
        [&](std::string_view key,
            std::vector<std::string>& patterns,
            AccessMode& mode) -> err::Expected<err::Unit> {
      if (const auto* child = findChild(*body, key)) {
        auto parsed =
            parseIdList("role '" + id + "': " + std::string(key), child);
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
    if (const auto* child = findChild(*body, kEnrollRoles)) {
      auto parsed =
          parseIdList("role '" + id + "': " + std::string(kEnrollRoles), child);
      if (parsed.hasError()) {
        return parsed.error();
      }
      policy.enroll = std::move(*parsed);
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
        findChild(*body, kBpfPod) || findChild(*body, kBpfRoles) ||
            findChild(*body, kBpfAny));
    inheritAny(
        policy.mqSysvMode,
        findChild(*body, kMqSysvPod) || findChild(*body, kMqSysvRoles) ||
            findChild(*body, kMqSysvAny));
    inheritAny(
        policy.mqPosixMode,
        findChild(*body, kMqPosixPod) || findChild(*body, kMqPosixRoles) ||
            findChild(*body, kMqPosixAny) || findChild(*body, kMqPosixPattern));
    inheritAny(
        policy.shmSysvMode,
        findChild(*body, kShmSysvPod) || findChild(*body, kShmSysvRoles) ||
            findChild(*body, kShmSysvAny));
    inheritAny(
        policy.shmPosixMode,
        findChild(*body, kShmPosixPod) || findChild(*body, kShmPosixRoles) ||
            findChild(*body, kShmPosixAny) ||
            findChild(*body, kShmPosixPattern));
    inheritAny(
        policy.killMode,
        findChild(*body, kKillPod) || findChild(*body, kKillRoles) ||
            findChild(*body, kKillAny));
    inheritAny(
        policy.ptraceMode,
        findChild(*body, kPtracePod) || findChild(*body, kPtraceRoles) ||
            findChild(*body, kPtraceAny));
    inheritAny(
        policy.procMode,
        findChild(*body, kProcPod) || findChild(*body, kProcRoles) ||
            findChild(*body, kAnyProc));
    inheritAny(
        policy.keyringMode,
        findChild(*body, kKeyringOwn) || findChild(*body, kKeyringRoles) ||
            findChild(*body, kKeyringAny));
    inheritAny(
        policy.enrollMode,
        findChild(*body, kEnrollRoles) || findChild(*body, kEnrollAny));
    if (policy.any) {
      if (!findChild(*body, kUnixBind)) {
        policy.unixBind.emplace("/", true);
      }
      if (!findChild(*body, kUnixConnect)) {
        policy.unixConnect.emplace("/", true);
      }
      if (!findChild(*body, kUnixDgram)) {
        policy.unixDgram.emplace("/", true);
      }
      if (!findChild(*body, kMount) && !findChild(*body, kMountAny)) {
        policy.mountAny = true;
      }
      if (!findChild(*body, kUmount) && !findChild(*body, kUmountAny)) {
        policy.umountAny = true;
      }
      if (!findChild(*body, kLkmAny)) {
        policy.lkmAny = true;
      }
      if (!findChild(*body, kPaths) && !findChild(*body, kFsAny)) {
        policy.fsAny = true;
      }
      if (!findChild(*body, kEnforceBinaryCerts) &&
          !findChild(*body, kVerityAny)) {
        policy.verityAny = true;
      }
      if (!findChild(*body, kExecPaths) && !findChild(*body, kExecAny)) {
        policy.execAny = true;
      }
    }
    if (policy.untrackedBpf && policy.bpfMode == AccessMode::Deny) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + id +
              "': untracked-bpf needs bpf-pod, bpf-roles, bpf-any or any");
    }
    if (auto res = parseFlag(kOverrideStacked, policy.overrideStacked);
        res.hasError()) {
      return res.error();
    }
    if (auto res = parseFlag(kUnprivEnroll, policy.unprivEnroll);
        res.hasError()) {
      return res.error();
    }
    if (const auto* child = findChild(*body, kMinSeq)) {
      auto parsed = parseMinSeq(id, child);
      if (parsed.hasError()) {
        return parsed.error();
      }
      policy.minSeq = *parsed;
      policy.hasMinSeq = true;
    }
    if (policy.hasMinSeq && policy.enforceBinaryCerts.empty()) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + id + "': " + std::string(kMinSeq) + " needs " +
              std::string(kEnforceBinaryCerts) +
              ", or nothing would be sequence-checked");
    }
    roles.emplace(id, std::move(policy));
  }
  return roles;
}

[[nodiscard]] err::Expected<err::Unit> checkRoleRefs(
    const std::map<std::string, RolePolicy>& roles,
    const std::string& id,
    const std::vector<std::string>& refs,
    std::string_view what) noexcept {
  for (const auto& target : refs) {
    if (!roles.contains(target)) {
      return err::Error(
          std::errc::invalid_argument,
          "role '" + id + "' " + std::string(what) + " '" + target +
              "', which is not in roles");
    }
  }
  return err::unit;
}

[[nodiscard]] err::Expected<Policy> parseRoot(
    const toml::table& root) noexcept {
  const std::set<std::string_view> allowedKeys = {
      kBaseRole, kCerts, kRoles, kVars};
  for (const auto& [key, value] : root) {
    (void)value;
    if (!allowedKeys.contains(key.str())) {
      return err::Error(
          std::errc::invalid_argument,
          "policy has unknown option '" + std::string(key.str()) + "'");
    }
  }

  Policy policy;
  auto certs = parseCerts(findChild(root, kCerts));
  if (certs.hasError()) {
    return certs.error();
  }
  policy.certs = std::move(*certs);
  auto roles = parseRoles(findChild(root, kRoles), policy.certs);
  if (roles.hasError()) {
    return roles.error();
  }
  policy.roles = std::move(*roles);
  for (const auto& [id, role] : policy.roles) {
    const std::pair<const std::vector<std::string>*, std::string_view> refs[] =
        {
            {&role.bpf, "allows BPF access to"},
            {&role.mqSysv, "allows System V message-queue access to"},
            {&role.mqPosix, "allows POSIX message-queue access to"},
            {&role.shmSysv, "allows System V shared-memory access to"},
            {&role.shmPosix, "allows POSIX shared-memory access to"},
            {&role.kill, "allows killing"},
            {&role.ptrace, "allows ptracing"},
            {&role.proc, "allows proc access to"},
            {&role.keyring, "allows keyring writes to"},
            {&role.enroll, "allows enrolling in"},
        };
    for (const auto& [targets, what] : refs) {
      if (auto res = checkRoleRefs(policy.roles, id, *targets, what);
          res.hasError()) {
        return res.error();
      }
    }
  }
  auto vars = parseVars(findChild(root, kVars));
  if (vars.hasError()) {
    return vars.error();
  }
  policy.vars = std::move(*vars);
  if (const auto* node = findChild(root, kBaseRole)) {
    auto baseRole = parseString(node, "'base-role'");
    if (baseRole.hasError()) {
      return baseRole.error();
    }
    policy.baseRole = std::move(*baseRole);
    if (!policy.roles.contains(policy.baseRole)) {
      return err::Error(
          std::errc::invalid_argument,
          "base-role '" + policy.baseRole + "' is not in roles");
    }
  }
  return policy;
}

[[nodiscard]] err::Error parseError(
    const toml::parse_error& error,
    std::string_view source) noexcept {
  return err::Error(
      std::errc::invalid_argument,
      "failed to parse " + std::string(source) + ": " +
          std::string(error.description()));
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
  try {
    auto policy = parseRoot(toml::parse_file(path));
    if (policy.hasError()) {
      return err::Error(
          policy.error().code(), path + ": " + policy.error().message());
    }
    return policy;
  } catch (const toml::parse_error& error) {
    return parseError(error, "policy " + path);
  } catch (const std::exception& error) {
    return err::Error(
        std::errc::invalid_argument,
        "failed to read policy " + path + ": " + error.what());
  }
}

err::Expected<Policy> Policy::parse(const std::string& text) noexcept {
  try {
    return parseRoot(toml::parse(text));
  } catch (const toml::parse_error& error) {
    return parseError(error, "policy");
  } catch (const std::exception& error) {
    return err::Error(
        std::errc::invalid_argument,
        "failed to parse policy: " + std::string(error.what()));
  }
}

} // namespace bpfjailer
