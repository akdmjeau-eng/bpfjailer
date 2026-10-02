#!/bin/bash

set -euo pipefail

source_tree=""
libarena=""
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
resources="${BUCK_DEFAULT_RUNTIME_RESOURCES:-}"

# antlir2 VM tests execute source-backed sh_tests from the mounted checkout,
# while packaged Buck resources use BUCK_DEFAULT_RUNTIME_RESOURCES. Support
# both layouts: the former is what contbuild uses today and the latter keeps
# the runner valid if sh_test resource staging changes.
for root in "$script_dir/.." "$script_dir/../.." "$resources" "$resources/fbcode" "$(dirname "${resources:-/nonexistent}")"; do
  [[ -n "$root" ]] || continue
  if [[ -z "$source_tree" && -f "$root/bpfjailer_oss/Makefile" ]]; then
    source_tree="$root/bpfjailer_oss"
  fi
  if [[ -z "$source_tree" && -f "$root/fbcode/bpfjailer_oss/Makefile" ]]; then
    source_tree="$root/fbcode/bpfjailer_oss"
  fi
  if [[ -z "$libarena" && -f "$root/third-party/libarena/src/libarena/include/bpf_arena_spin_lock.h" ]]; then
    libarena="$root/third-party/libarena/src"
  fi
done

if [[ -z "$source_tree" ]]; then
  echo "bpfjailer_oss source tree is missing (script: $script_dir, resources: $resources)" >&2
  exit 1
fi
if [[ -z "$libarena" ]]; then
  echo "libarena headers are missing (script: $script_dir, resources: $resources)" >&2
  exit 1
fi

workdir="$(mktemp -d /tmp/bpfjailer-oss-make-test.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT

# Buck resources are read-only. Dereference the runfile symlinks into a normal
# writable tree so make can create dependency files and generated skeletons.
mkdir "$workdir/source"
cp -aL "$source_tree/." "$workdir/source/"

if ! make -C "$workdir/source" \
  -j"$(nproc)" \
  LIBARENA="$libarena" \
  SUDO= \
  test >"$workdir/make.log" 2>&1; then
  echo "make test failed; final 400 log lines follow" >&2
  tail -n 400 "$workdir/make.log" >&2
  exit 1
fi

cat "$workdir/make.log"
