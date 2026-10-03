# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Shared paths and settings for the unpriv-enroll example.
#
# Sourced, not executed. The caller sets `here` to its own directory.
# shellcheck shell=bash
# shellcheck disable=SC2034  # these are for the scripts that source this

ROOT=$(cd -- "${here:?common.sh needs \$here set by the caller}/../.." && pwd)

# A relative BUILD has to be resolved against ROOT and not the caller's cwd,
# because that is where `make -C "$ROOT"` will put it.
BUILD=${BUILD:-$ROOT/build}
case $BUILD in
  /*) ;;
  *) BUILD=$ROOT/$BUILD ;;
esac

BPFJCTL="$BUILD/bpfjctl"
BPFJSRV="$BUILD/bpfjsrv"
BPFJCLIENT="$BUILD/bpfjclient"

POLICY="$here/policy.toml"

# The role in policy.toml, and the only one this example enrolls into.
ROLE=sandbox

# Matches kDefaultSocketPath in srv/Protocol.h, so bpfjclient needs no
# --socket. The leading @ is the abstract namespace: no file, no directory to
# create, and no permissions to keep anyone out -- which is the point, since
# what a caller may obtain is decided by the role's unpriv-enroll policy.
SOCKET=@bpfj

# Where attach.sh leaves the socket activator, so detach.sh can find it.
PIDFILE=/run/bpfj-unpriv-example.pid
LOGFILE=/run/bpfj-unpriv-example.log

die() {
  echo "error: $*" >&2
  exit 1
}

require_built() {
  for bin in "$@"; do
    [ -x "$bin" ] || die "$(basename "$bin") is not built -- run ./build.sh first"
  done
}
