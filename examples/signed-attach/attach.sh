#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Bootstrap the jailer from the same policy that is compiled into bpfjcmd.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

require_built "$BPFJCTL"
[ -r "$POLICY" ] || die "$POLICY is missing -- run ./build.sh first"

echo "Attaching the jailer with $POLICY..."
sudo "$BPFJCTL" attach "$POLICY"

echo "Starting and enrolling a helper in $ROLE..."
sudo rm -rf "$CONTROL"
sudo mkdir -p "$CONTROL"
sudo "$here/role-runner.sh" &
for _ in $(seq 1 50); do
  if sudo test -r "$RUNNER_PIDFILE"; then
    break
  fi
  sleep 0.1
done
sudo test -r "$RUNNER_PIDFILE" ||
  die "the enrolled helper did not start"
sudo "$BPFJCTL" enroll "$ROLE" "$WRAP_USER" "$(runner_pid)"

echo
echo "Attached. The jailer is live for the whole host, so run ./detach.sh when done."
echo "  base role:  $BASE_ROLE (every process on the host)"
echo "  role:       $ROLE (held by the enrolled helper only)"
echo
# Ownership of a BPF object is taken by the role of the
# process that created it, and at this point no such process existed: the
# binary that ran this attach was execed before the jailer was loaded, so
# nothing could have enrolled it in $ROLE yet. The base role it lands in a
# moment later owns nothing either, by untracked-bpf. Its objects are therefore
# unowned, and the signed bpfjailer role carries bpf-any for this bootstrap.
echo "Note: the jailer's own maps are unowned right now. The floor role denies"
echo "access to them; the signed updater carries bpf-any so it can perform the"
echo "first replacement before the ownership handoff."
echo
echo "Next: ./upgrade.sh"
