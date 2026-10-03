#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Detach the jailer and take the signing filesystem down with it.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

stuck() {
  echo >&2
  echo "error: the jailer is still attached and nothing here could detach it." >&2
  echo "  $WORK has been left alone, so a fixed binary can be rebuilt into it." >&2
  echo "  The floor role cannot unlink $PINS: that is part of the self-protection" >&2
  echo "  this example demonstrates. Recover with another correctly signed detach" >&2
  echo "  binary, or reboot into an environment where the BPF LSM is not active." >&2
  exit 1
}

# The signed binary first. Once the upgrade has run, the jailer's own maps are
# owned by $ROLE and only a process in that role can open them, so this is the
# only thing on the host that can take the jailer down. A detach with nothing
# attached still succeeds, so a failure here is a real one.
if [ -x "$DETACH" ]; then
  echo "Detaching with the signed $(basename "$DETACH")..."
  run_in_role "$DETACH"
  [ "$RUN_IN_ROLE_RC" -eq 0 ] || stuck
elif [ -x "$BPFJCTL" ]; then
  # No signed binary staged, so this is a tree from a run that died before
  # build.sh finished. Nothing it left behind is owned yet, and an unowned
  # object is not gated, so plain bpfjctl can still do it.
  echo "Detaching with $BPFJCTL..."
  sudo "$BPFJCTL" detach || stuck
else
  # Once the hardened policy is active, an unsigned stat of $PINS is denied
  # whether the tree exists or not. Never mistake that denial for a detached
  # jailer and delete the only remaining recovery material.
  stuck
fi

stop_runner

# Everything below runs only once the detach above has succeeded, and `stuck`
# exits rather than reaching it: $WORK holds the one binary able to detach
# this jailer, so removing it while the jailer is still up would strand the
# host with no way back.
#
# The binary that just ran the detach lives on this filesystem, and the kernel
# can hold its executable inode for a moment after it exits -- so the first
# umount often loses a race it is about to win. Retried rather than slept
# through, with the last attempt left bare so a mount that is genuinely busy
# still reports why.
if mountpoint -q "$MNT" 2>/dev/null; then
  echo "Unmounting $MNT..."
  for attempt in $(seq 1 50); do
    if [ "$attempt" -eq 50 ]; then
      sudo umount "$MNT"
      break
    fi
    if sudo umount "$MNT" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
fi

# Best effort from here. Every step is allowed to find its subject already
# gone, because this is the script that has to work when an earlier one died
# halfway.
if [ -r "$LOOPFILE" ]; then
  loop=$(sudo cat "$LOOPFILE")
  if [ -b "$loop" ]; then
    echo "Detaching $loop..."
    sudo losetup -d "$loop" || true
  fi
fi

if [ -e "$WORK" ]; then
  echo "Removing $WORK..."
  sudo rm -rf "$WORK"
fi

echo
echo "Done. The key, the certificate and the signed binaries are all gone with it."
