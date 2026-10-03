#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Launch a jailed shell. Deliberately no sudo anywhere in here.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

require_built "$BPFJCLIENT"

# Anything after `--` replaces the shell, the same way `bpfjctl wrap` takes a
# command.
if [ "$#" -gt 0 ]; then
  cmd=("$@")
else
  cmd=("${SHELL:-/bin/bash}")
fi

echo "Enrolling $$ in role '$ROLE' through bpfjsrv, then exec ${cmd[0]}."
echo "Running as uid $(id -u) ($(id -un)) -- no privileges are used here."
echo
echo "To see the jail enforce something, start a process outside it first:"
echo "    sleep 300 &            # in another terminal, as the same user"
echo "then in here:"
echo "    kill <that pid>        # denied: 'kill-pod:' confines signals to this pod"
echo "    kill \$\$                # allowed: same pod"
echo "    cat /proc/1/status     # denied: 'proc-pod:' confines proc access"
echo "The same kill from outside succeeds, so it is the jail refusing and not"
echo "file permissions."
echo
echo "sudo bpfjctl list          # from outside, shows this pod"
echo "exit                       # leaves the jail with the process"
echo
echo "Note that bpfjctl itself does not work in here: the role denies bpf(2),"
echo "so the jail refuses even to be inspected from inside."
echo "Setuid execution is denied, and Unix-socket bind is limited to the abstract"
echo "name @bpfj-sandbox-demo. System V IPC stays in the pod; POSIX MQ/SHM also"
echo "allow names matching /bpfj-example-* for deliberate sharing."
echo

# execs, so the jailed command replaces this script rather than running under
# it.
exec "$BPFJCLIENT" "$ROLE" "$(id -un)" -- "${cmd[@]}"
