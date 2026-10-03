# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Shared paths and settings for the signed-attach example.
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

# Everything this example mints lives here, off the source tree. The tree is
# often on a filesystem that supports neither fs-verity nor user xattrs -- an
# EdenFS checkout supports neither -- and both are load-bearing below.
WORK=${WORK:-/var/tmp/bpfj-signed-attach}

# An ext4 image on a loop device, because fs-verity needs a filesystem that
# implements it and /var/tmp generally is not one. The same shape the test
# harness builds for the fs-verity tests, minus the mount namespace: this one
# has to outlive the script that creates it.
IMAGE="$WORK/ext4.img"
MNT="$WORK/mnt"
LOOPFILE="$WORK/loop.dev"

KEY="$WORK/signer_key.pem"
CERT="$WORK/signer_cert.der"
POLICY="$WORK/policy.toml"
TEMPLATE="$here/policy.toml.in"

# The signed binary, an older signed one that verify.sh uses to show rollback
# is refused, and an unsigned twin that differs only in the signature. All
# three live on the ext4 image.
SIGNED="$MNT/bpfjcmd"
ROLLBACK="$MNT/bpfjcmd-rollback"
IMPOSTOR="$MNT/bpfjcmd-unsigned"

# The other signed binary. Once the upgrade has run, the jailer's own maps are
# owned by $ROLE and only a process in it can open them -- so the teardown
# needs a binary in the role just as much as the upgrade does. bpfjctl carries
# no role and its detach fails on the first map it reads.
DETACH="$MNT/bpfjcmd-detach"

# Where the jailer pins itself, which is bpfjctl's default. Named here because
# detach.sh has to point at it when all else fails and verify.sh reads it.
PINS=/sys/fs/bpf/bpfj-pins
CONTROL="$WORK/control"
RUNNER_PIDFILE="$CONTROL/runner.pid"
REQUEST_FIFO="$CONTROL/request.fifo"
RESPONSE_RC="$CONTROL/response.rc"
RESPONSE_OUT="$CONTROL/response.out"

# The role a pre-enrolled helper enters for upgrades and detach, and the floor
# every process on the host lands on. Both are in policy.toml.in.
ROLE=bpfjailer
BASE_ROLE=floor
WRAP_USER=signed-attach@example

# The command compiled into bpfjcmd. `replace-compiled` rather than
# `attach-compiled` because an upgrade has to keep the jail: attach is
# destructive and releases every task it had jailed.
CMD_ARGS=replace-compiled

# The current binary sequence the policy accepts, and the older one staged only
# for verify.sh to show that a signature alone is no longer enough once a role
# carries a min-seq floor.
CURRENT_SEQ=2
ROLLBACK_SEQ=1

# And into the teardown binary. No policy is compiled into that one: `detach`
# reads none, and `make cmd` says so rather than signing one in to be ignored.
DETACH_ARGS=detach

# Spelled as BPFJ_EXEC_POLICY_XATTR and BPFJ_EXEC_SIG_XATTR in
# bpfj/enforce/bpf/types.h. This example deliberately leaves ROLE_XATTR unset on
# its staged binaries and enters $ROLE through a helper that was enrolled
# before the first signed replace.
ROLE_XATTR=user.bpfj.policy.exec
SIG_XATTR=user.bpfj.sig
SEQ_XATTR=user.bpfj.seq

die() {
  echo "error: $*" >&2
  exit 1
}

require_built() {
  for bin in "$@"; do
    [ -x "$bin" ] || die "$(basename "$bin") is not built -- run ./build.sh first"
  done
}

require_staged() {
  if [ ! -d "$MNT" ] || ! mountpoint -q "$MNT"; then
    die "the signing filesystem is not mounted -- run ./build.sh first"
  fi
  [ -x "$SIGNED" ] || die "$SIGNED is missing -- run ./build.sh first"
}

runner_pid() {
  sudo cat "$RUNNER_PIDFILE"
}

require_runner() {
  require_built "$BPFJCTL"
  sudo test -p "$REQUEST_FIFO" ||
    die "the enrolled helper is missing -- run ./attach.sh again"
  sudo test -r "$RUNNER_PIDFILE" ||
    die "the enrolled helper pid is missing -- run ./attach.sh again"
}

run_in_role() {
  require_runner
  sudo rm -f "$RESPONSE_RC" "$RESPONSE_OUT"
  printf '%s\n' "$1" | sudo tee "$REQUEST_FIFO" >/dev/null
  for _ in $(seq 1 300); do
    if sudo test -f "$RESPONSE_RC"; then
      RUN_IN_ROLE_RC=$(sudo cat "$RESPONSE_RC")
      if sudo test -f "$RESPONSE_OUT"; then
        RUN_IN_ROLE_OUT=$(sudo cat "$RESPONSE_OUT")
      else
        RUN_IN_ROLE_OUT=
      fi
      return 0
    fi
    sleep 0.1
  done
  die "the enrolled helper did not answer"
}

stop_runner() {
  if sudo test -p "$REQUEST_FIFO" 2>/dev/null; then
    printf '%s\n' "__stop__" | sudo tee "$REQUEST_FIFO" >/dev/null || true
  fi
}
