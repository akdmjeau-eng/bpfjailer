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
constexpr std::string_view kBpf = "bpf";
constexpr std::string_view kNoBpf = "no-bpf";
constexpr std::string_view kNoLkm = "no-lkm";
constexpr std::string_view kMqSysv = "mq-sysv";
constexpr std::string_view kNoMqSysv = "no-mq-sysv";
constexpr std::string_view kMqPosix = "mq-posix";
constexpr std::string_view kNoMqPosix = "no-mq-posix";
constexpr std::string_view kKill = "kill";
constexpr std::string_view kNoKill = "no-kill";
constexpr std::string_view kPtrace = "ptrace";
constexpr std::string_view kNoPtrace = "no-ptrace";
constexpr std::string_view kKeyring = "keyring";
constexpr std::string_view kNoKeyring = "no-keyring";
constexpr std::string_view kUnprivEnroll = "unpriv-enroll";
constexpr std::string_view kEnroll = "enroll";
constexpr std::string_view kOverrideStacked = "override-stacked";
constexpr std::string_view kUntrackedBpf = "untracked-bpf";
constexpr std::string_view kMinSeq = "min-seq";

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

      if (Yaml::Node* certRefs = findChild(value, kEnforceBinaryCerts)) {
        auto refs = parseCertRefs(id, *certRefs, certs);
        if (refs.hasError()) {
          return refs.error();
        }
        policy.enforceBinaryCerts = std::move(*refs);
      }

      // Written at all, not written non-empty: an empty `bpf` confines the role
      // to objects its own role owns, while leaving it out means unconfigured.
      if (Yaml::Node* bpf = findChild(value, kBpf)) {
        auto targets = parseIdList("role '" + id + "': bpf", *bpf);
        if (targets.hasError()) {
          return targets.error();
        }
        policy.bpf = std::move(*targets);
        policy.hasBpf = true;
      }

      // Absent is the same as false, as for `unpriv-enroll` and unlike the
      // lists: a role that says nothing about bpf(2) is not denied it.
      if (Yaml::Node* noBpf = findChild(value, kNoBpf)) {
        auto denied = parseRoleFlag(id, kNoBpf, *noBpf);
        if (denied.hasError()) {
          return denied.error();
        }
        policy.noBpf = *denied;
      }

      // The two say opposite things about the same syscall, and silently
      // picking one would enforce something the policy does not read as.
      if (policy.noBpf && policy.hasBpf) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id + "': " + std::string(kNoBpf) + " and " +
                std::string(kBpf) +
                " contradict each other; no-bpf denies bpf(2) outright, so "
                "there is nothing for bpf to grant");
      }

      if (Yaml::Node* noLkm = findChild(value, kNoLkm)) {
        auto denied = parseRoleFlag(id, kNoLkm, *noLkm);
        if (denied.hasError()) {
          return denied.error();
        }
        policy.noLkm = *denied;
      }

      const auto parseMq = [&](std::string_view listKey,
                               std::string_view denyKey,
                               std::vector<std::string>& targets,
                               bool& configured,
                               bool& denied) -> err::Expected<err::Unit> {
        if (Yaml::Node* list = findChild(value, listKey)) {
          auto parsed =
              parseIdList("role '" + id + "': " + std::string(listKey), *list);
          if (parsed.hasError()) {
            return parsed.error();
          }
          targets = std::move(*parsed);
          configured = true;
        }

        if (Yaml::Node* noMq = findChild(value, denyKey)) {
          auto parsed = parseRoleFlag(id, denyKey, *noMq);
          if (parsed.hasError()) {
            return parsed.error();
          }
          denied = *parsed;
        }

        if (configured && denied) {
          return err::Error(
              std::errc::invalid_argument,
              "role '" + id + "': " + std::string(listKey) + " and " +
                  std::string(denyKey) + " contradict each other");
        }
        return err::unit;
      };

      if (auto res = parseMq(
              kMqSysv,
              kNoMqSysv,
              policy.mqSysv,
              policy.hasMqSysv,
              policy.noMqSysv);
          res.hasError()) {
        return res.error();
      }
      if (auto res = parseMq(
              kMqPosix,
              kNoMqPosix,
              policy.mqPosix,
              policy.hasMqPosix,
              policy.noMqPosix);
          res.hasError()) {
        return res.error();
      }

      // Absent is the same as false again. What it turns off is ownership,
      // not permission, so it is read after both of the above.
      if (Yaml::Node* untracked = findChild(value, kUntrackedBpf)) {
        auto exempt = parseRoleFlag(id, kUntrackedBpf, *untracked);
        if (exempt.hasError()) {
          return exempt.error();
        }
        policy.untrackedBpf = *exempt;
      }

      // Rejected rather than accepted as a no-op, a role that did not write
      // `bpf` already owning nothing. Covers `no-bpf` too, which the check
      // above has established cannot appear alongside `bpf`.
      if (policy.untrackedBpf && !policy.hasBpf) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id + "': " + std::string(kUntrackedBpf) + " needs " +
                std::string(kBpf) +
                "; only a role configured for bpf(2) takes ownership of what "
                "it creates, so there is nothing here to exempt");
      }

      // Written at all again: an empty `kill` confines the role to its own
      // pods, leaving it out leaves it unrestricted.
      if (Yaml::Node* kill = findChild(value, kKill)) {
        auto targets = parseIdList("role '" + id + "': kill", *kill);
        if (targets.hasError()) {
          return targets.error();
        }
        policy.kill = std::move(*targets);
        policy.hasKill = true;
      }

      if (Yaml::Node* noKill = findChild(value, kNoKill)) {
        auto denied = parseRoleFlag(id, kNoKill, *noKill);
        if (denied.hasError()) {
          return denied.error();
        }
        policy.noKill = *denied;
      }

      if (policy.noKill && policy.hasKill) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id + "': " + std::string(kNoKill) + " and " +
                std::string(kKill) +
                " contradict each other; no-kill denies signalling outright, "
                "so there is nothing for kill to grant");
      }

      if (Yaml::Node* ptrace = findChild(value, kPtrace)) {
        auto targets = parseIdList("role '" + id + "': ptrace", *ptrace);
        if (targets.hasError()) {
          return targets.error();
        }
        policy.ptrace = std::move(*targets);
        policy.hasPtrace = true;
      }

      if (Yaml::Node* noPtrace = findChild(value, kNoPtrace)) {
        auto denied = parseRoleFlag(id, kNoPtrace, *noPtrace);
        if (denied.hasError()) {
          return denied.error();
        }
        policy.noPtrace = *denied;
      }

      if (policy.noPtrace && policy.hasPtrace) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id + "': " + std::string(kNoPtrace) + " and " +
                std::string(kPtrace) +
                " contradict each other; no-ptrace denies ptrace outright, "
                "so there is nothing for ptrace to grant");
      }

      if (Yaml::Node* keyring = findChild(value, kKeyring)) {
        auto targets = parseIdList("role '" + id + "': keyring", *keyring);
        if (targets.hasError()) {
          return targets.error();
        }
        policy.keyring = std::move(*targets);
        policy.hasKeyring = true;
      }

      if (Yaml::Node* noKeyring = findChild(value, kNoKeyring)) {
        auto denied = parseRoleFlag(id, kNoKeyring, *noKeyring);
        if (denied.hasError()) {
          return denied.error();
        }
        policy.noKeyring = *denied;
      }

      if (policy.noKeyring && policy.hasKeyring) {
        return err::Error(
            std::errc::invalid_argument,
            "role '" + id + "': " + std::string(kNoKeyring) + " and " +
                std::string(kKeyring) +
                " contradict each other; no-keyring denies keyring writes "
                "outright, so there is nothing for keyring to grant");
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

      // Written at all again: an empty `enroll` forbids stacking anything, and
      // leaving it out leaves the role unrestricted.
      if (Yaml::Node* enroll = findChild(value, kEnroll)) {
        auto targets = parseIdList("role '" + id + "': enroll", *enroll);
        if (targets.hasError()) {
          return targets.error();
        }
        policy.enroll = std::move(*targets);
        policy.hasEnroll = true;
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
