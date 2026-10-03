#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Mint a signing key, render bootstrap and hardened policies, build a bpfjcmd
# with the hardened policy compiled in, sign it, and stage it somewhere
# fs-verity works. Needs root for the loop mount.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
source "$here/common.sh"

for tool in openssl fsverity setfattr mkfs.ext4 losetup; do
  command -v "$tool" >/dev/null || die "$tool is missing"
done

# A signed bpfjcmd is statically linked, so the static archives have to be
# there. Most distributions package them apart from the shared ones, and
# without this the failure is a bare `cannot find -lbpf` several minutes into
# the build, after the image is already mounted.
missing=
for lib in libbpf.a libelf.a libz.a libzstd.a; do
  find /usr/lib64 /usr/lib -name "$lib" -print -quit 2>/dev/null | grep -q . ||
    missing="$missing $lib"
done
[ -z "$missing" ] || die "static libraries missing:$missing
    On CentOS/Fedora: sudo dnf install libbpf-static elfutils-libelf-devel-static \\
        zlib-static libzstd-static libstdc++-static glibc-static"

[ -e "$WORK" ] && die "$WORK already exists -- run ./detach.sh first"

echo "Building bpfjctl (needs clang, bpftool and libbpf)..."
make -C "$ROOT" BUILD="$BUILD" -j"$(nproc)" "$BPFJCTL"

sudo mkdir -p "$WORK" "$MNT"

# fs-verity needs a filesystem that implements it, and neither the source tree
# nor /var/tmp is likely to be one. -b 4096 because fs-verity will not work on
# a block size other than the page size, and mkfs picks 1024 for an image this
# small. -I 256 because it pairs that choice with inodes too narrow to carry
# the verity descriptor. Neither shows up until enabling verity returns EINVAL.
echo
echo "Making an ext4 image with verity support at $IMAGE..."
sudo truncate -s 96M "$IMAGE"
sudo mkfs.ext4 -q -F -b 4096 -I 256 -O verity "$IMAGE"

loop=$(sudo losetup --find --show "$IMAGE")
echo "$loop" | sudo tee "$LOOPFILE" >/dev/null
sudo mount "$loop" "$MNT"
echo "  mounted $loop on $MNT"

# A self-signed pair, in the shapes the rest of the chain wants: the private
# key as PEM for openssl, the certificate as DER because that is what
# Keyring::addPKey() loads and what the policy carries.
echo
echo "Minting a signing key and certificate..."
sudo openssl genrsa -out "$KEY" 2048 2>/dev/null
sudo chmod 600 "$KEY"
sudo openssl req -new -x509 -key "$KEY" -out "$CERT" -outform der -days 365 \
  -subj "/CN=bpfj signed-attach example"

# TOML carries the base64 certificate as one quoted string.
echo "Writing the bootstrap and hardened policies..."
cert_b64=$(sudo base64 -w0 "$CERT")
# The placeholders occur only in TOML quoted strings. BUILD and the example
# directory must remain executable after attach: attach.sh still invokes the
# freshly built bpfjctl to enroll the helper, and the later workflow scripts
# live beside this template.
render_policy() {
  sudo awk \
    -v cert="$cert_b64" \
    -v seq="$CURRENT_SEQ" \
    -v build="$BUILD" \
    -v example="$here" '
    {
      sub("@CERT@", cert)
      sub("@CURRENT_SEQ@", seq)
      sub("@BUILD@", build)
      sub("@EXAMPLE@", example)
      print
    }
  ' "$1" | sudo tee "$2" >/dev/null
}

render_policy "$BOOTSTRAP_TEMPLATE" "$BOOTSTRAP_POLICY"
render_policy "$TEMPLATE" "$POLICY"

"$BPFJCTL" check "$BOOTSTRAP_POLICY"
"$BPFJCTL" check "$POLICY"

# SIGNDIR is the ext4 image: `make cmd` refuses a SIGNDIR with no user xattr
# support, because the signature has nowhere else to go. Building there also
# means the file that gets fs-verity enabled below is the same one the digest
# was taken over.
#
# The teardown and retired binaries come first, because `make cmd` stages under
# the binary's own name and the final current build would otherwise overwrite
# them. Moving them aside is safe: fs-verity covers a file's contents and the
# signature is taken over those, so neither the digest nor the xattrs care what
# the file ends up being called.
#
# It needs no policy compiled in. `detach` reads none -- it takes the tree down
# by path -- and `make cmd` warns rather than signing one in to be ignored.
# None of these binaries claim $ROLE through an xattr: the example enters that
# role only through a helper enrolled ahead of time, which keeps a direct exec
# from becoming a privileged one.
echo
echo "Building and signing the detach binary..."
sudo make -C "$ROOT" BUILD="$BUILD" cmd \
  CMD_ARGS="$DETACH_ARGS" \
  CMD_SEQ="$CURRENT_SEQ" \
  SIGNING_KEY="$KEY" \
  SIGNING_CERT="$CERT" \
  SIGNDIR="$MNT"
sudo mv "$SIGNED" "$DETACH"

echo
echo "Building and signing a retired rollback candidate..."
sudo make -C "$ROOT" BUILD="$BUILD" cmd \
  CMD_ARGS="$CMD_ARGS" \
  CMD_POLICY="$POLICY" \
  CMD_SEQ="$ROLLBACK_SEQ" \
  SIGNING_KEY="$KEY" \
  SIGNING_CERT="$CERT" \
  SIGNDIR="$MNT"
sudo mv "$SIGNED" "$ROLLBACK"

echo
echo "Building and signing the current bpfjcmd with the policy compiled in..."
sudo make -C "$ROOT" BUILD="$BUILD" cmd \
  CMD_ARGS="$CMD_ARGS" \
  CMD_POLICY="$POLICY" \
  CMD_SEQ="$CURRENT_SEQ" \
  SIGNING_KEY="$KEY" \
  SIGNING_CERT="$CERT" \
  SIGNDIR="$MNT"

# An unsigned twin, for verify.sh. `cp` carries the sequence xattr across and
# loses only the signature -- which is the point: the one thing separating it
# from the real binary is the thing under test.
sudo cp --preserve=xattr "$SIGNED" "$IMPOSTOR"
sudo setfattr -x "$SIG_XATTR" "$IMPOSTOR"

# Enabling verity freezes the file's contents and is irreversible, so it comes
# after the copy. Extended attributes are not part of those contents, which is
# why the signature and sequence xattrs survive enabling verity.
echo
echo "Enabling fs-verity..."
for bin in "$SIGNED" "$ROLLBACK" "$DETACH" "$IMPOSTOR"; do
  sudo fsverity enable "$bin"

  signed=no
  if sudo getfattr -n "$SIG_XATTR" "$bin" >/dev/null 2>&1; then
    signed=yes
  fi
  seq=-
  if sudo getfattr -n "$SEQ_XATTR" "$bin" >/dev/null 2>&1; then
    seq_hex=$(sudo getfattr -n "$SEQ_XATTR" --only-values "$bin" | xxd -p -c 8)
    seq=$((16#$seq_hex))
  fi
  role=-
  if sudo getfattr -n "$ROLE_XATTR" "$bin" >/dev/null 2>&1; then
    role=$(sudo getfattr -n "$ROLE_XATTR" --only-values "$bin")
  fi
  printf '  %-30s verity=on role=%s signed=%s seq=%s\n' \
    "$(basename "$bin")" \
    "$role" \
    "$signed" \
    "$seq"
done

echo
echo "Built. Nothing is enforcing yet -- the jailer is not attached."
echo "Next: ./attach.sh"
