// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/Options.h"

#include <cerrno>
#include <cstdlib>
#include <limits>
#include <string>
#include <utility>

namespace bpfjailer::ctl {

const struct argp_option kPinOptions[] = {
    {"bpffs-path",
     kBpffsPathKey,
     "PATH",
     0,
     "bpffs mount to pin under (default /sys/fs/bpf)",
     0},
    {"pin-dir",
     kPinDirKey,
     "DIR",
     0,
     "Directory under the bpffs mount (default bpfj-pins)",
     0},
    {},
};

error_t parsePinOpt(int key, const char* arg, PinConfig& cfg) {
  switch (key) {
    case kBpffsPathKey:
      cfg.bpffsPath = arg;
      return 0;
    case kPinDirKey:
      cfg.pinDir = arg;
      return 0;
    default:
      return ARGP_ERR_UNKNOWN;
  }
}

Expected<pid_t> parsePid(const char* arg) noexcept {
  errno = 0;
  char* end = nullptr;
  const long long value = std::strtoll(arg, &end, 10);
  if (errno != 0 || end == arg || *end != '\0' || value <= 0 ||
      value > std::numeric_limits<pid_t>::max()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "bad pid: ", arg));
  }

  return static_cast<pid_t>(value);
}

namespace {

error_t parsePinOnlyOpt(int key, char* arg, struct argp_state* state) {
  auto* cfg = static_cast<PinConfig*>(state->input);
  if (key == ARGP_KEY_ARG) {
    argp_usage(state);
    return 0;
  }

  return parsePinOpt(key, arg, *cfg);
}

} // namespace

void parsePinOnly(int argc, char** argv, const char* doc, PinConfig& cfg) {
  // A local is enough: argp_parse() does not outlive the call.
  const struct argp spec = {kPinOptions, parsePinOnlyOpt, nullptr, doc};
  argp_parse(&spec, argc, argv, 0, nullptr, &cfg);
}

Expected<Policy> compiledPolicy(std::string_view builtin) noexcept {
  if (builtin.empty()) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "no policy was compiled into this binary -- build one in with "
        "`make cmd CMD_POLICY=...`, or use the command that takes a path"));
  }

  return Policy::parse(std::string(builtin));
}

} // namespace bpfjailer::ctl
