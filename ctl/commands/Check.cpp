// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/commands/Check.h"

#include <argp.h>
#include <iostream>
#include <string_view>

#include "bpfj/policy/Policy.h"
#include "ctl/Options.h"

namespace bpfjailer::ctl {

namespace {

constexpr char kDoc[] = "Parse a policy and report what it holds";
constexpr char kCompiledDoc[] =
    "Parse the compiled-in policy and report what it holds";
constexpr char kArgsDoc[] = "POLICY_PATH";

// No pin flags on either of these: they read a policy and nothing else,
// which is what lets them run unprivileged and off a host with no bpffs --
// including from a build, where `make cmd` runs `check` over CMD_POLICY so a
// policy that does not parse is caught before it is signed in.
error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto** path = static_cast<const char**>(state->input);
  switch (key) {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        *path = arg;
      } else {
        argp_usage(state);
      }
      return 0;
    case ARGP_KEY_END:
      if (state->arg_num < 1) {
        argp_usage(state);
      }
      return 0;
    default:
      return ARGP_ERR_UNKNOWN;
  }
}

error_t parseCompiledOpt(int key, char* /*arg*/, struct argp_state* state) {
  if (key == ARGP_KEY_ARG) {
    argp_usage(state);
    return 0;
  }

  return ARGP_ERR_UNKNOWN;
}

const struct argp kArgp = {nullptr, parseOpt, kArgsDoc, kDoc};
const struct argp kCompiledArgp = {
    nullptr,
    parseCompiledOpt,
    nullptr,
    kCompiledDoc};

void report(const Policy& policy, std::string_view source) {
  std::cout << source << ": " << policy.roles.size() << " role(s), "
            << policy.certs.size() << " cert(s)";
  if (!policy.baseRole.empty()) {
    std::cout << ", base role " << policy.baseRole;
  }
  std::cout << std::endl;
}

} // namespace

int checkRun(int argc, char** argv) {
  const char* path = nullptr;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &path);

  auto policy = Policy::parseFile(path);
  if (!policy) {
    std::cerr << "policy failed: " << policy.error() << std::endl;
    return 1;
  }

  report(*policy, path);
  return 0;
}

int checkCompiledRun(int argc, char** argv, std::string_view builtin) {
  argp_parse(&kCompiledArgp, argc, argv, 0, nullptr, nullptr);

  auto policy = compiledPolicy(builtin);
  if (!policy) {
    std::cerr << "policy failed: " << policy.error() << std::endl;
    return 1;
  }

  report(*policy, kCompiledSource);
  return 0;
}

} // namespace bpfjailer::ctl
