#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Attach the jailer and start bpfjsrv. This is the half that needs root.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

require_built "$BPFJCTL" "$BPFJSRV"

command -v systemd-socket-activate >/dev/null ||
  die "systemd-socket-activate is missing; it stands in for systemd here (see README.md)"

if [ -e "$PIDFILE" ] && sudo kill -0 "$(sudo cat "$PIDFILE")" 2>/dev/null; then
  die "already attached -- run ./detach.sh first"
fi

echo "Attaching the jailer with $POLICY..."
sudo "$BPFJCTL" attach "$POLICY"

# systemd-socket-activate stands in for the bpfjsrv.socket unit: it binds the
# abstract socket and spawns one bpfjsrv per connection with the connection
# passed down, which is what Accept=yes does. `echo $$` before the exec records
# the pid the activator will have.
echo "Starting bpfjsrv on $SOCKET..."

# Truncated first, or the readiness check below matches the previous run's
# "Listening on" and returns before this activator has bound anything.
sudo truncate -s 0 "$LOGFILE" 2>/dev/null || sudo sh -c ": > '$LOGFILE'"
#
# The outer redirect matters as much as the inner one: without it the activator
# holds whatever stdout this script was called with, and a caller piping
# attach.sh into anything waits forever for an EOF that never comes.
sudo setsid sh -c '
  echo $$ > "$1"
  exec systemd-socket-activate --accept --seqpacket --listen="$2" -- "$3" >>"$4" 2>&1
' sh "$PIDFILE" "$SOCKET" "$BPFJSRV" "$LOGFILE" </dev/null >/dev/null 2>&1 &

# Waiting for the bind means run.sh cannot race the activator's startup.
for _ in $(seq 50); do
  if sudo grep -qs "Listening on" "$LOGFILE"; then
    break
  fi
  sleep 0.1
done
sudo grep -qs "Listening on" "$LOGFILE" ||
  die "bpfjsrv did not come up; see $LOGFILE"

echo
echo "Attached. The jailer is live for the whole host, so run ./detach.sh when done."
echo "  role:    $ROLE (BPF denied; process and IPC access confined to its pod)"
echo "  socket:  $SOCKET"
echo "  logs:    sudo cat $LOGFILE"
echo
echo "Next: ./run.sh    (no sudo)"
