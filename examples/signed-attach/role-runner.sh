#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# A long-lived helper that is enrolled once and then execs staged binaries on
# request. It starts before the first upgrade while the pin tree is still
# unowned, so it keeps the privileged role across the ownership handoff.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

mkdir -p "$CONTROL"
rm -f "$REQUEST_FIFO" "$RESPONSE_RC" "$RESPONSE_OUT"
mkfifo -m 600 "$REQUEST_FIFO"
printf '%s\n' "$$" >"$RUNNER_PIDFILE"

while IFS= read -r cmd <"$REQUEST_FIFO"; do
  if [ "$cmd" = "__stop__" ]; then
    printf '0\n' >"$RESPONSE_RC"
    exit 0
  fi

  set +e
  out=$("$cmd" 2>&1)
  rc=$?
  set -e

  printf '%s' "$out" >"$RESPONSE_OUT"
  printf '%s\n' "$rc" >"$RESPONSE_RC"
done
