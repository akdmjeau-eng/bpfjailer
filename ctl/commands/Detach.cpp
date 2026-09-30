// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/commands/Detach.h"

#include <argp.h>
#include <iostream>

#include "bpfj/enforce/Jailer.h"
#include "ctl/Options.h"

namespace bpfjailer::ctl {

namespace {

constexpr char kDoc[] = "Detach the jailer BPF programs by unpinning them";

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

} // namespace

int detachRun(int argc, char** argv) {
  PinConfig cfg;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &cfg);

  if (auto res = Jailer::unload(cfg); !res) {
    std::cerr << "detach failed: " << res.error() << std::endl;
    return 1;
  }

  std::cout << "Jailer detached from " << cfg.root() << std::endl;
  return 0;
}

} // namespace bpfjailer::ctl
