#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Show the two things the policy buys, by trying to do them and failing.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

require_staged
[ -x "$ROLLBACK" ] || die "$(basename "$ROLLBACK") is missing -- run ./build.sh first"
command -v bpftool >/dev/null || die "bpftool is missing"

# Under sudo because the bpffs mount is 0700 root, so an unprivileged test
# cannot tell a missing pin tree from one it may not look at.
sudo test -d "$PINS" ||
  die "no jailer attached -- run ./attach.sh and ./upgrade.sh first"

fail=0
check() {
  if [ "$1" = "$2" ]; then
    printf '  \033[32mok\033[0m   %s\n' "$3"
  else
    printf '  \033[31mFAIL\033[0m %s (wanted %s, got %s)\n' "$3" "$2" "$1"
    fail=1
  fi
}

echo "1. An unsigned binary entered through the privileged role"
echo "   $IMPOSTOR runs through the enrolled helper in $ROLE, carries fs-verity and seq,"
echo "   and differs from $SIGNED only by missing the signature."
run_in_role "$IMPOSTOR"
echo "   \$ enrolled-helper $(basename "$IMPOSTOR")"
echo "     rc=$RUN_IN_ROLE_RC  ${RUN_IN_ROLE_OUT:-(no output)}"
check "$((RUN_IN_ROLE_RC != 0))" 1 "refused at exec by the fs-verity enforcer"

echo
echo "2. An older signed binary below the role's min-seq floor"
echo "   $ROLLBACK is signed and entered through $ROLE, but carries seq $ROLLBACK_SEQ."
echo "   The running policy for $ROLE requires at least $CURRENT_SEQ."
run_in_role "$ROLLBACK"
echo "   \$ enrolled-helper $(basename "$ROLLBACK")"
echo "     rc=$RUN_IN_ROLE_RC  ${RUN_IN_ROLE_OUT:-(no output)}"
check "$((RUN_IN_ROLE_RC != 0))" 1 "refused at exec by the anti-rollback floor"

echo
echo "3. Opening a map the $ROLE role owns, from a process that is not in it"
echo "   This shell is in $BASE_ROLE, which reaches only what $BASE_ROLE owns"
echo "   -- and untracked-bpf means that is nothing."
set +e
out=$(sudo bpftool map dump pinned "$PINS/maps/bpfj_pod_map" 2>&1)
rc=$?
set -e
echo "   \$ sudo bpftool map dump pinned $PINS/maps/bpfj_pod_map"
echo "     rc=$rc  $(echo "$out" | head -1)"
check "$((rc != 0))" 1 "refused by the BPF object enforcer"

echo
echo "4. The current signed binary still works"
run_in_role "$SIGNED"
check "$RUN_IN_ROLE_RC" 0 "the signed bpfjcmd can still replace the jailer"

echo
echo "5. The retired signed binary does not become privileged on a direct exec"
echo "   It carries no role xattr, so outside the enrolled helper it stays in $BASE_ROLE."
set +e
out=$(sudo "$ROLLBACK" 2>&1)
rc=$?
set -e
echo "   \$ sudo $(basename "$ROLLBACK")"
echo "     rc=$rc  ${out:-(no output)}"
check "$((rc != 0))" 1 "direct exec cannot replace the jailer from $BASE_ROLE"

echo
if [ "$fail" -ne 0 ]; then
  die "something that should have been refused was allowed"
fi
echo "All five behaved. Run ./detach.sh to tear this down."
