# BpfJailer

eBPF based Mandatory Access Control for Linux.

**This project is a full rewrite of the closed source BpfJailer and is
completely experimental. It leverages newer features like bpf arena that were
not available when the internal BpfJailer was written. Issues are expected and
are not eligible for bug bounty or considered security findings. Once properly
evaluated it will replace the internal closed source version.**

BpfJailer uses eBPF LSM programs to put processes into jails, called pods, each
bound to a role from a TOML policy. A pod is inherited across `fork` and
`exec`, so everything a jailed process starts stays in the jail. The policy
then decides what each role may do:

- **Signed binaries** — a role can require that every binary it executes
  carries an fs-verity signature from one of a named set of certificates.
- **`kill` and `ptrace`** — which roles' processes a role may signal or attach
  to.
- **`bpf`** — which roles' eBPF maps and programs a role may open, or whether it
  may call `bpf(2)` at all. This is also what stops a jailed process from
  editing the jailer's own maps.
- **`keyring`** — which roles' fs-verity keyrings a role may add certificates
  to, or whether it may write keyrings at all.
- **Filesystem paths** — read, write and execute access using cached glob
  matchers evaluated in PID 1's mount namespace.
- **Kernel loading** — kernel module and kexec loading.
- **IPC** — ownership-aware System V and POSIX message queues and shared
  memory, plus variable-expanded name patterns for POSIX objects.
- **Unix sockets** — pathname and abstract-name policy for bind, connect and
  datagram destinations.
- **Mounts** — destination and filesystem-type rules, unmount policy, and the
  legacy and new mount APIs.

Denials and lifecycle events are written to pinned ring buffers. `bpfjlog`
prints the human-readable BPF diagnostics and structured events and follows
the ring buffers across a live policy replacement.

A binary can claim a role through the `user.bpfj.policy.exec` xattr and is
enrolled in it at exec time. Running processes can also be enrolled directly,
and an unprivileged process can enroll itself through `bpfjsrv`.

## Components

| Directory | Binary        | Purpose |
|-----------|---------------|---------|
| `bpfj/`   |               | The core library and BPF programs: jailer, enforcers, policy parser, libbpf C++ helpers. |
| `ctl/`    | `bpfjctl`     | General purpose tool for attaching, reloading, inspecting and detaching the jailer, and for enrolling processes. |
| `cmd/`    | `bpfjcmd`     | `bpfjctl` with its arguments, and optionally its policy, compiled in. It ignores `argv`, so it can be statically linked and fs-verity signed as a single unit. |
| `srv/`    | `bpfjsrv`     | Socket activated server that enrolls unprivileged callers into roles that allow it. |
| `client/` | `bpfjclient`  | Minimal client for `bpfjsrv`. It depends only on libc. |
| `log/`    | `bpfjlog`     | Consumer for the pinned diagnostic and structured-event ring buffers. |
| `tests/`  | `bpfjtest`    | Test suite. |

## Requirements

- Linux 6.16 or newer with BPF LSM enabled (`CONFIG_BPF_LSM=y` and `bpf` in
  the `lsm=` boot parameter). BpfJailer is only tested on 6.16+, and older
  kernels are not supported.
- clang (for BPF codegen), `bpftool`, and a C++20 compiler.
- libbpf and libkeyutils, with headers.
- A checkout of [libarena](https://github.com/libbpf/libarena), which provides
  the arena spin lock the BPF programs use. It ships as source, not as a
  package.
- For signed builds: `openssl`, `fsverity` and `setfattr`, plus the static
  archives listed in the `Makefile` (`STATIC=1`).

Set `LIBBPF_CFLAGS` / `LIBBPF_LIBS` if pkg-config cannot find libbpf. Point
`LIBARENA` at the libarena checkout on every build:

```
git clone https://github.com/libbpf/libarena ~/libarena
make LIBARENA=~/libarena
```

The build stops with these instructions if `LIBARENA` is unset or wrong. Run
`make config` to see the resolved toolchain and flags.

## Building

Every `make` below also needs `LIBARENA` (see Requirements), set on the
command line or exported in the environment.

```
make                # build/bpfjctl
make STATIC=1       # bpfjctl with no shared object dependencies
make client         # build/bpfjclient, no BPF toolchain needed
make log            # build/bpfjlog
make signing-key    # generate a development signing key and certificate
make signed SIGNING_KEY=... SIGNING_CERT=...   # static, fs-verity signed bpfjctl
make srv  SIGNING_KEY=... SIGNING_CERT=...     # static, signed bpfjsrv
make cmd  SIGNING_KEY=... SIGNING_CERT=... \
     CMD_ARGS="replace-compiled" CMD_POLICY=policy.toml CMD_ROLE=bpfjailer
make clean
```

All output goes under `build/`. Set `BUILD=` to build somewhere else, for
example `make BUILD=build-asan SANITIZE=address,undefined`.

## Testing

```
make test
```

The tests have to run as root, because each one creates a mount namespace and
mounts a bpffs. `make test` builds as the invoking user and runs only the test
binary under `sudo`.

## Usage

```
sudo bpfjctl check  policy.toml          # parse a policy and report what it holds
sudo bpfjctl attach policy.toml          # load and pin the jailer
sudo bpfjctl replace policy.toml         # reload without releasing jailed tasks
sudo bpfjctl wrap ROLE USER_ID -- CMD    # run CMD in a new pod
sudo bpfjctl enroll ROLE USER_ID PID     # enroll a running process
sudo bpfjctl show PID                    # pods a process is in
sudo bpfjctl list                        # every pod and its processes
sudo bpfjctl detach                      # unpin and unload
```

The programs are pinned under `/sys/fs/bpf/bpfj-pins` by default. Use
`--bpffs-path` and `--pin-dir` to change this. They stay loaded until `detach`
runs.

`bpfjctl wrap` without `--drop-cap` and a non-root `--uid` leaves the command
able to remove itself from the jail. See `bpfjctl wrap --help`.

Run `sudo build/bpfjlog` while the jailer is attached to observe it. BPF
diagnostics are written to stderr and structured events to stdout. The logger
automatically reconnects when `replace` swaps in a new set of pinned maps.

`replace` loads a complete second jailer beside the active one, migrates pod
membership, variables and tracked resource ownership, then atomically swaps
the pin trees. Both trees remain attached during the handoff, forks and
enrollment are coordinated with the migration, and ownership changes are
journaled and replayed. Replacement fails closed if persisted layout versions
are incompatible or the state cannot be copied safely.

## Policy

```toml
base-role = "floor"           # optional: every process on the host starts here
vars = ["vm_uuid"]            # the only variable names a pod may carry

[certs]
corp-ca = "MIIDXTCCAkWgAwIBAgIJAK..." # PEM or base64 DER certificate

[roles.floor]
any = true                    # open tracking-only base role

[roles.webserver]
enforce-binary-certs = ["corp-ca"] # execs must be signed by one of these
kill-roles = ["floor"]        # may signal its own pod, plus these roles
ptrace-pod = true             # its own pod only
proc-roles = ["floor"]        # may open proc files for these roles
bpf-pod = true                # only BPF objects from its own pod
lkm-any = false               # deny module and kexec loading
mq-sysv-pod = true            # only SysV queues from its own pod
mq-posix-pod = true           # only POSIX queues from its own pod
mq-posix-pattern = ["service-${vm_uuid}-*"]
shm-sysv-pod = true           # only SysV SHM from its own pod
shm-posix-pod = true          # only POSIX SHM from its own pod
shm-posix-pattern = ["service-${vm_uuid}-*"]
umount = false                # deny unmount and mount-source removal
keyring-own = true            # only its own role's keyring

[roles.webserver.exec-paths."/usr/bin/webserver"]
allow-exec = true
allow-setuid = false
allow-shared-object = false

[roles.webserver.exec-paths."/usr/lib/**"]
allow-exec = false
allow-setuid = false
allow-shared-object = true

[roles.webserver.paths]       # cached path glob policy
"/usr" = "RDEXEC"
"/etc" = "RDONLY"
"/srv/web" = "RDWR"
"/" = "NONE"

[roles.webserver.unix-bind]   # pathname bind rules, longest path wins
"/run/webserver" = true
"/" = false

[roles.webserver.unix-connect]
"@control-${vm_uuid}" = true

[roles.webserver.unix-dgram]
"/dev/log" = true

[roles.webserver.mount]       # destination -> permitted filesystem types
"/srv/data" = ["ext4", "xfs"]
"/" = []                     # empty list blocks every other destination

[roles.sandbox]
unpriv-enroll = true          # every unspecified operation remains denied
override-stacked = true       # answers alone, ignoring roles stacked below
```

Most operation gates are denied when a role has no corresponding option. The
`*-pod` options allow resources from the same pod, `*-roles` adds the named
owner roles, and `*-any` opens that operation completely. `keyring-own` is the
role-scoped counterpart because fs-verity keyrings belong to roles rather than
pods. `enroll-roles` names the only roles bpfjsrv may add; without it enrollment
through bpfjsrv is denied. Unix-socket and mount path maps differ: an
unconfigured or unmatched operation is allowed, so use an explicit root deny
when the map is intended as an allowlist. An absent `umount` abstains.

`any = true` opens every operation that has no more specific option. This is
useful for a pod used only for attribution. A scoped option such as `bpf-pod`,
`kill-roles`, `paths`, or `enforce-binary-certs` overrides `any` for that
operation. `lkm-any`, `fs-any`, and `verity-any` are the operation-specific
fully-open forms.

`paths` maps path patterns to `NONE`, `RDONLY`, `RDWR`, or `RDEXEC`. Matches
are resolved in PID 1's mount namespace, the longest path wins, and a `$NAME`
component expands a variable carried by the pod. Path results are cached by
mount identity and pod variable bindings and invalidated across filesystem
mutation. `fs-any` and `paths` are mutually exclusive.

Every queue created by a jailed process is owned by its newest pod. A
restricted process can acquire a queue from that exact pod, or from a role its
list names; a queue with no known jailed owner is denied. System V ids can be
copied as integers, so lookup, control, send, and receive are all checked.
POSIX queues are tracked by the mqueuefs superblock device and inode number;
`mq_open` and descriptor receipt are checked. The device number distinguishes
the separate mqueuefs instances used by IPC namespaces, so the IPC namespace
inode is not part of the key.

`mq-posix-pattern` and `shm-posix-pattern` are lists of POSIX object names that
override the corresponding owner-role list. Patterns match the name without
its leading slash and support literals, `?`, `*`, and `${NAME}` references to
the acquiring pod's declared variables. Every referenced variable must be
present on that pod or the pattern does not match. A pattern establishes a
restricted policy and cannot be combined with the corresponding `*-any`.
Patterns apply to opens, descriptor receipt, and the later queue or mapping
operations checked by the enforcer. They do not apply to System V IPC.

POSIX descriptors already held when a process is enrolled, or inherited by a
fork inside a pod, are capabilities and are not revoked. Descriptor transfer
through kernel paths that invoke `security_file_receive` (including Unix
socket descriptor passing) is checked, but BpfJailer does not provide dynamic
revocation of a descriptor after it has been acquired.

Shared memory follows the same owner-pod and role-list model. System V lookup,
control, and attach are checked. POSIX shared-memory objects are tracked by
the `/dev/shm` tmpfs device and inode, and open, descriptor receipt, mapping,
protection changes, truncation, and unlink are checked. Existing mappings are
capabilities and cannot be revoked; direct loads and stores after enrollment
do not pass through an LSM hook. `memfd_create` is not POSIX shared memory and
is intentionally outside `shm-posix`. BpfJailer registers `/dev/shm` for each
enrolled mount namespace; a replacement preserves those registrations.

`unix-bind`, `unix-connect`, and `unix-dgram` are maps from Unix-socket names
to booleans. Pathname rules start with `/`, apply recursively, and use the
longest matching path; an equally specific denial wins. An unmatched operation
is allowed, so `/: false` is the usual default-deny rule and a deeper `true`
entry opens a subtree. `unix-bind` gates creation of pathname sockets,
`unix-connect` gates stream and seqpacket connection to the server pathname,
and `unix-dgram` gates datagram sends to the destination pathname.

Abstract socket names use systemd's spelling with a leading `@`. They support
the same literals, `?`, `*`, and `${NAME}` variables as POSIX IPC patterns.
The most specific matching pattern wins (then the longer pattern, then denial
on a tie); if a referenced variable is not present on the pod, that pattern
does not match. Abstract bind, stream/seqpacket connect, and datagram send are
covered. A Unix socket descriptor that was connected before enrollment,
inherited, or passed between processes remains a capability: this version does
not re-check descriptor transfer between pods or revoke an already-connected
socket.

`mount` maps destination paths to lists of filesystem type names. Rules apply
recursively, the longest matching path wins, and unmatched destinations are
allowed. An empty list denies every mount at that path, so `'/':` is a
default-deny rule. `umount` is a role-wide boolean; leaving it out abstains,
`false` denies unmounting, and `true` permits it. `move_mount` requires mount
permission for the destination and umount permission for the source;
`pivot_root` applies the same pair to the new and old paths. Legacy remounts
are checked at their destination and relayed to `sb_remount`. A standalone
new-mount-API reconfigure has no destination path in its LSM hook and is denied
for a role carrying mount rules. Legacy bind and move mounts do not expose the
source filesystem type to the LSM hook, so a matched typed destination denies
them rather than guessing; use `move_mount` when type-aware movement is
required.

A process holding several roles is allowed an operation only if every role
agrees. Roles are consulted newest first, and an `override-stacked` role
answers for the roles under it. The target side of `kill` and `ptrace` ignores
override: every role the target holds has to be listed. The full semantics are
documented in `bpfj/policy/Policy.h`.

`vars` is an allowlist. An enrollment setting a variable the policy does not
list is refused, and with no `vars` at all no pod carries any. A `replace`
carries each pod's variables across by name, and fails if the new policy no
longer lists one a pod is carrying.

See [POLICY.md](POLICY.md) for the complete option matrix, matching semantics
and replacement behavior.

## Examples

- [`examples/signed-attach`](examples/signed-attach/README.md): a signed
  `bpfjcmd` that is the only binary on the host allowed to update BpfJailer's
  own BPF programs.
- [`examples/unpriv-enroll`](examples/unpriv-enroll/README.md): a non-root
  process jailing itself through `bpfjsrv`.

## License

BpfJailer is MIT licensed, as found in the [LICENSE](LICENSE) file. The BPF
programs are licensed `Dual MIT/GPL`, so that the kernel treats them as GPL
compatible.

`toml/toml.hpp` is vendored from
[toml++](https://github.com/marzer/tomlplusplus) and keeps its own MIT license
notice.
