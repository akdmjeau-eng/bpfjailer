#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Stop bpfjsrv and unload the jailer. Needs root, like attach.sh.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

if [ -e "$PIDFILE" ]; then
  pid=$(sudo cat "$PIDFILE")
  echo "Stopping bpfjsrv ($pid)..."
  sudo kill "$pid" 2>/dev/null || true
  sudo rm -f "$PIDFILE"
else
  echo "No socket activator recorded at $PIDFILE, skipping."
fi

echo "Detaching the jailer..."
sudo "$BPFJCTL" detach

echo
echo "Detached. Nothing of this example is left running."
