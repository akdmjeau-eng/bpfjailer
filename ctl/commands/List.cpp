// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/commands/List.h"

#include <argp.h>
#include <iostream>

#include "bpfj/enforce/Pods.h"
#include "ctl/Options.h"
#include "ctl/PodPrinter.h"

namespace bpfjailer::ctl {

namespace {

constexpr char kDoc[] = "List every pod and the processes enrolled in it";

error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto* cfg = static_cast<PinConfig*>(state->input);
  switch (key) {
    case ARGP_KEY_ARG:
      argp_usage(state);
      return 0;
    default:
      return parsePinOpt(key, arg, *cfg);
  }
}

const struct argp kArgp = {kPinOptions, parseOpt, nullptr, kDoc};

void printPids(const std::vector<pid_t>& pids) {
  std::cout << "    pids:   ";
  if (pids.empty()) {
    std::cout << " none";
  }

  for (const pid_t pid : pids) {
    std::cout << " " << pid;
  }

  std::cout << "\n";
}

} // namespace

int listRun(int argc, char** argv) {
  PinConfig cfg;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &cfg);

  auto members = listAllPods(cfg);
  if (!members) {
    std::cerr << "list failed: " << members.error() << std::endl;
    return 1;
  }

  if (members->empty()) {
    std::cout << "no pods" << std::endl;
    return 0;
  }

  auto nowNs = monotonicNs();
  if (!nowNs) {
    std::cerr << "list failed: " << nowNs.error() << std::endl;
    return 1;
  }

  auto arena = PodArena::open(cfg);
  std::cout << members->size() << " pod(s)" << std::endl;
  for (const auto& member : *members) {
    printPod(std::cout, member.pod, *nowNs, arena ? arena->base() : nullptr);
    printPids(member.pids);
  }

  std::cout << std::flush;
  return 0;
}

} // namespace bpfjailer::ctl
