#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Run the signed bpfjcmd. This is the upgrade: it reloads the jailer and every
# enforcer from the policy compiled into it, keeping the tasks already jailed.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

require_staged

# Three things have to line up for this upgrade to be allowed:
#
#   1. the helper started by attach.sh is already enrolled in the `bpfjailer`
#      pod, so its child inherits that role across fork and exec.
#   2. bprm_check_security sees that role carrying `enforce-binary-certs`,
#      reads the file's fs-verity digest and the signature from its xattr, and
#      verifies one against the other through the role's keyring. `min-seq`
#      compares the signed sequence to the policy floor on this same path.
#   3. only then does main() run, and it ignores argv entirely.
echo "Running the signed $SIGNED..."
echo "  through the enrolled helper in $ROLE"
echo "  (no arguments: the command and the policy are both compiled in)"
echo
run_in_role "$SIGNED"
[ "$RUN_IN_ROLE_RC" -eq 0 ] || {
  printf '%s\n' "${RUN_IN_ROLE_OUT:-(no output)}" >&2
  exit "$RUN_IN_ROLE_RC"
}

echo
echo "Upgraded. From here the jailer's objects are owned by $ROLE, so nothing"
echo "outside that role can open them."
echo
echo "Next: ./verify.sh"
