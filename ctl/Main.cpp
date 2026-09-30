// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <argp.h>
#include <iostream>

#include "ctl/Dispatch.h"

const char* argp_program_version = "bpfjctl 0.1";

// Everything after the \v is argp's post-doc, which is where the command list
// belongs: argp only knows this program's flags, not its subcommands.
static constexpr char doc[] =
    "bpfjctl -- control the bpfjailer LSM"
    "\vCommands:\n"
    "  attach ARGS...    Attach and pin the jailer BPF programs\n"
    "  detach ARGS...    Detach the jailer BPF programs by unpinning them\n"
    "  enroll ARGS...    Enroll a running process in a new pod\n"
    "  wrap ARGS...      Run a command in a new pod, with privileges dropped\n"
    "  show ARGS...      Show the pods a running process is enrolled in\n"
    "  list ARGS...      List every pod and the processes enrolled in it\n"
    "  check ARGS...     Parse a policy and report what it holds\n"
    "\n"
    "Run a command with --help for its own arguments.\n"
    "\n"
    "attach, replace and check each have an -compiled twin -- attach-compiled\n"
    "and so on -- which takes no path and uses the policy compiled into the\n"
    "binary. Only a bpfjcmd built with `make cmd CMD_POLICY=...` carries one,\n"
    "so in bpfjctl they have nothing to read and say so.";
static constexpr char args_doc[] = "COMMAND [ARGS...]";

static struct argp top_argp = {{}, nullptr, args_doc, doc};

int main(int argc, char** argv) {
  if (auto rc = bpfjailer::ctl::dispatch(argc, argv)) {
    return *rc;
  }

  if (argc >= 2) {
    std::cerr << "Unknown command: " << argv[1] << std::endl;
  }
  argp_help(
      &top_argp, stderr, ARGP_HELP_STD_USAGE | ARGP_HELP_POST_DOC, argv[0]);
  return 1;
}
