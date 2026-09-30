# signed-attach

A signed `bpfjcmd` that is the only thing on the host allowed to update
bpfjailer's own BPF programs.

Everything that decides what this binary does — the command it runs and the
policy it runs against — is compiled into it and covered by the fs-verity
digest its signature is taken over. There is no argument to pass and no file
to point at, so there is nothing an attacker can change without invalidating
the signature.

There are two current such binaries, for the two things anyone is allowed to do
to a running jailer: `bpfjcmd` replaces it, and `bpfjcmd-detach` takes it down.
Both carry the current sequence number and are signed by the same key.
`build.sh` also stages one older signed `bpfjcmd-rollback`, only so `verify.sh`
can show that a valid signature below the rollback floor is now refused.

## Running it

```
./build.sh     # mint a key, stage current+retired signed binaries      (root)
./attach.sh    # bootstrap the jailer from the same policy            (root)
./upgrade.sh   # run the current signed binary: the actual upgrade    (root)
./verify.sh    # try the things the policy forbids                    (root)
./detach.sh    # run the current signed detach binary, then clean up  (root)
```

Needs `openssl`, `fsverity`, `setfattr`, `mkfs.ext4`, `losetup` and `bpftool`,
and the static archives a statically linked binary needs — `build.sh` checks
for those and names the packages if any are missing.

## The policy

```yaml
base-role: floor
certs:
  signer: |
    <the minted certificate>
roles:
  floor:
    bpf:
    untracked-bpf: true
    keyring:
  bpfjailer:
    override-stacked: true
    enforce-binary-certs:
      - signer
    min-seq: 2
    bpf:
    keyring:
```

`floor` is the base role, so every process on the host is in it. It names no
certificate, so ordinary execs are not signature-checked.

`floor` writes an empty `bpf:`, which restricts every process on the host to
the objects `floor` itself owns, and `untracked-bpf: true` is what makes that
none. Configuring a role for bpf is also what makes it take ownership of what
it creates, and `floor` is held by every process — so on its own the empty
`bpf:` would hand `floor` every BPF object on the machine, including the
jailer's own maps, and restrict the host to the host. `untracked-bpf` keeps
the restriction and drops the ownership.

`override-stacked: true` on `bpfjailer` is what makes that safe to combine
with a specific role. A task that execs `bpfjcmd` holds `[floor, bpfjailer]`;
every enforcer walks a task's roles newest first and stops at the first one
carrying the flag, so `bpfjailer` answers and `floor` gets no say over the
upgrade binary. Without it the two would both be consulted, and the base role
every process holds would be voting on what the jailer may do to itself.

`bpfjailer` is the privileged role a helper process enters through
`bpfjctl enroll` during `attach.sh`. `enforce-binary-certs` is what makes later
execs in that role require a signature; `bpf:` written empty confines it to the
objects its own role owns, which are the jailer's; `keyring:` written empty
lets it rewrite its own role's keyring, which is what a replace does when it
reloads the fs-verity enforcer, and no other role's. `min-seq: 2` is the
anti-rollback floor: a binary signed by the same key but carrying sequence 1 is
refused before `main()` runs.

## What has to line up

Three separate mechanisms meet at the exec, in this order:

1. **`bpfjctl enroll`** — `attach.sh` starts one helper process, enrolls that
   process in `bpfjailer`, and keeps the user's shell in `floor`. Every later
   signed command is fork/execed by that already-enrolled helper, so the child
   inherits the role across exec.
2. **`bprm_check_security`** — the fs-verity enforcer sees a role carrying
   `enforce-binary-certs`, reads the file's fs-verity digest and the PKCS#7
   signature from `user.bpfj.sig`, and verifies one against the other through
   the role's keyring. If the role also carries `min-seq`, the signed payload is
   the digest with the `user.bpfj.seq` value appended, and exec is refused when
   that sequence is below the policy floor.
3. **`main()`** runs, ignoring `argc` and `argv` entirely.

`make cmd CMD_SEQ=2` sets the signature and sequence xattrs, and the enrolled
helper is what decides which policy applies. A binary with no valid signature
does not execute in `bpfjailer`; a binary with a valid signature but a retired
sequence is refused the same way; and a direct exec of one of these binaries
claims no role at all, which keeps an older signed binary from self-promoting
into the update role.

## What anti-rollback changes

Before `min-seq`, signing answered only "did this key vouch for this file?"
Once a role carries it, signing answers "did this key vouch for this file at or
above the oldest version the policy still accepts?" `verify.sh` stages one older
signed `bpfjcmd-rollback` to make that visible: it has the right key and
fs-verity enabled, and is still refused in `bpfjailer` because its sequence is
1 while the running policy now requires 2.

## Why the teardown needs a signed binary too

Once `upgrade.sh` has run, the jailer's own maps are owned by `bpfjailer`, and
`bpf:` written empty on `floor` means no other role can open them. `detach` is
not exempt from that: `Jailer::unload()` reads the fs-verity keyring map before
it removes anything, so a plain `bpfjctl detach` — which claims no role, and is
therefore in `floor` like everything else — is refused on that first map and
takes nothing down.

```
$ sudo bpfjctl detach
detach failed: Operation not permitted: failed to open pinned map
    /sys/fs/bpf/bpfj-pins/maps/bpfj_key_map
```

So the example signs a second binary with `detach` compiled in, and
`detach.sh` runs it through that same enrolled helper in `bpfjailer`. It is the
same bargain as the upgrade: the only thing that can take this jailer down is a
binary the signer vouched for, run in the one role allowed to touch the
jailer's own maps.

`detach.sh` will not remove the staging filesystem if the detach failed — the
signed binary lives there, and deleting it while the jailer is up would leave
the host with nothing able to detach it. `sudo rm -rf /sys/fs/bpf/bpfj-pins`
is the way out of that: unlinking a pin is `unlink()` rather than `bpf(2)`, so
it is not gated. It leaves this tree's keyrings linked in the root user keyring
with nothing naming them.

## Why the ext4 image

fs-verity needs a filesystem that implements it, and the source tree usually is
not one — an EdenFS checkout supports neither fs-verity nor user xattrs, and
the signature has nowhere to live without the latter. So `build.sh` makes a
small ext4 image on a loop device and stages everything there, the same shape
the fs-verity tests build. `mkfs` needs `-O verity`, `-b 4096` because
fs-verity will not work on a block size other than the page size, and `-I 256`
because mkfs otherwise pairs a small image with inodes too narrow to carry the
verity descriptor. Neither of the last two shows up until enabling verity
returns `EINVAL`.

Enabling fs-verity is irreversible and freezes the file's contents, which is
why it happens on a throwaway image and after everything is copied into place.
Extended attributes are not part of those contents, so both the signature and
sequence xattrs can be set either side of it without invalidating the digest
they were taken over.

## The gap this example does not close

The bootstrap `attach` leaves the jailer's own maps **unowned**, and an unowned
object is not gated. Ownership is taken from the role of the process that
created the object, and the binary that ran the bootstrap was execed before the
jailer existed — so nothing could have enrolled it in `bpfjailer` yet. The base
role it is seeded into a moment later does not own either, which is what
`untracked-bpf` on `floor` says.

The first signed upgrade is what takes ownership: `bpfjcmd` execs under a live
jailer from that pre-enrolled helper, enters `bpfjailer`, and the objects it
creates are recorded against that role. `verify.sh` is therefore only
meaningful after `upgrade.sh` has run.

Closing the window entirely would need the jailer to be brought up by something
already inside a role, which is not possible for the process that installs it.
This example also leaves one broader product gap in place: file-xattr
self-enrollment is still weaker than explicit enrollment for anti-rollback, so
the example avoids self-claiming binaries entirely and uses a pre-enrolled
helper as the role entry point instead.
