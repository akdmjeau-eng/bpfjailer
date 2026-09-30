// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/commands/Replace.h"

#include <argp.h>
#include <iostream>
#include <string_view>

#include "bpfj/enforce/Replace.h"
#include "bpfj/policy/Policy.h"
#include "ctl/Options.h"

namespace bpfjailer::ctl {

namespace {

struct ReplaceArgs {
  PinConfig pin;
  const char* policyPath = nullptr;
};

constexpr char kDoc[] =
    "Reload the jailer without releasing the tasks it jails";
constexpr char kCompiledDoc[] =
    "Reload the jailer against the compiled-in policy, keeping its tasks";
constexpr char kArgsDoc[] = "POLICY_PATH";

error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto* args = static_cast<ReplaceArgs*>(state->input);
  switch (key) {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        args->policyPath = arg;
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
      return parsePinOpt(key, arg, args->pin);
  }
}

const struct argp kArgp = {kPinOptions, parseOpt, kArgsDoc, kDoc};

/// @brief Stand a new jailer up against `policy` and migrate the old one's
/// pods across.
/// @param source what to call the policy in the line this prints.
int replacePolicy(
    const PinConfig& pin,
    const Policy& policy,
    std::string_view source) {
  auto stats = replaceJailer(pin, policy);
  if (!stats) {
    std::cerr << "replace failed: " << stats.error() << std::endl;
    return 1;
  }

  std::cout << "Jailer replaced, pinned under " << pin.root() << ", "
            << policy.roles.size() << " role(s) from " << source << ", carried "
            << stats->pods << " pod(s) across " << stats->tasks << " task(s), "
            << stats->owners << " BPF object owner(s)" << std::endl;
  return 0;
}

} // namespace

int replaceRun(int argc, char** argv) {
  ReplaceArgs args;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &args);

  // Parsed before anything is attached, so a policy that does not read leaves
  // the running jailer alone.
  auto policy = Policy::parseFile(args.policyPath);
  if (!policy) {
    std::cerr << "policy failed: " << policy.error() << std::endl;
    return 1;
  }

  return replacePolicy(args.pin, *policy, args.policyPath);
}

int replaceCompiledRun(int argc, char** argv, std::string_view builtin) {
  PinConfig pin;
  parsePinOnly(argc, argv, kCompiledDoc, pin);

  auto policy = compiledPolicy(builtin);
  if (!policy) {
    std::cerr << "policy failed: " << policy.error() << std::endl;
    return 1;
  }

  return replacePolicy(pin, *policy, kCompiledSource);
}

} // namespace bpfjailer::ctl
