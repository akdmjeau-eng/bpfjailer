// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/commands/Show.h"

#include <argp.h>
#include <iostream>

#include "bpfj/enforce/Pods.h"
#include "ctl/Options.h"
#include "ctl/PodPrinter.h"

namespace bpfjailer::ctl {

namespace {

struct ShowArgs {
  PinConfig pin;
  const char* pid = nullptr;
};

constexpr char kDoc[] = "Show the pods a running process is enrolled in";
constexpr char kArgsDoc[] = "PID";

error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto* args = static_cast<ShowArgs*>(state->input);
  switch (key) {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        args->pid = arg;
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

} // namespace

int showRun(int argc, char** argv) {
  ShowArgs args;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &args);

  auto pid = parsePid(args.pid);
  if (!pid) {
    std::cerr << "show failed: " << pid.error() << std::endl;
    return 1;
  }

  auto pods = listPods(args.pin, *pid);
  if (!pods) {
    std::cerr << "show failed: " << pods.error() << std::endl;
    return 1;
  }

  if (pods->empty()) {
    std::cout << "pid " << *pid << " is not jailed" << std::endl;
    return 0;
  }

  auto nowNs = monotonicNs();
  if (!nowNs) {
    std::cerr << "show failed: " << nowNs.error() << std::endl;
    return 1;
  }

  const auto varNames = jailVarNames(args.pin);
  std::cout << "pid " << *pid << " is in " << pods->size() << " pod(s)"
            << std::endl;
  for (const auto& pod : *pods) {
    printPod(std::cout, pod, *nowNs, varNames);
  }

  return 0;
}

} // namespace bpfjailer::ctl
