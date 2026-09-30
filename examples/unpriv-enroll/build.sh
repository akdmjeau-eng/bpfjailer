#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Build the three binaries this example uses.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

# bpfjclient is built on its own line to show what it costs: no libbpf and no
# BPF skeletons, because srv/Client.h is header-only.
echo "Building bpfjctl and bpfjsrv (needs clang, bpftool and libbpf)..."
make -C "$ROOT" BUILD="$BUILD" -j"$(nproc)" "$BPFJCTL" "$BPFJSRV"

echo
echo "Building bpfjclient (needs only a C++ compiler)..."
make -C "$ROOT" BUILD="$BUILD" "$BPFJCLIENT"

echo
echo "Built into $BUILD:"
for bin in "$BPFJCTL" "$BPFJSRV" "$BPFJCLIENT"; do
  printf '  %-12s %s\n' "$(basename "$bin")" "$bin"
done
echo
echo "Next: ./attach.sh"
