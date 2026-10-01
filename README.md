# BpfJailer

eBPF based Mandatory Access Control for Linux.

**This project is a full rewrite of the closed source BpfJailer and is
completely experimental. It leverages newer features like bpf arena that were
not available when the internal BpfJailer was written. Issues are expected and
are not eligible for bug bounty or considered security findings. Once properly
evaluated it will replace the internal closed source version.**

**Many features are not implemented yet that are present in the closed source
version. This includes basic functionality like logging. This will come soon.**

BpfJailer uses eBPF LSM programs to put processes into jails, called pods, each
bound to a role from a YAML policy. A pod is inherited across `fork` and
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
| `tests/`  | `bpfjtest`    | Test suite. |

## Requirements

- Linux 6.16 or newer with BPF LSM enabled (`CONFIG_BPF_LSM=y` and `bpf` in
  the `lsm=` boot parameter). BpfJailer is only tested on 6.16+, and older
  kernels are not supported.
- clang (for BPF codegen), `bpftool`, and a C++20 compiler.
- libbpf and libkeyutils, with headers.
- For signed builds: `openssl`, `fsverity` and `setfattr`, plus the static
  archives listed in the `Makefile` (`STATIC=1`).

Set `LIBBPF_CFLAGS` / `LIBBPF_LIBS` if pkg-config cannot find libbpf. Run
`make config` to see the resolved toolchain and flags.

## Building

```
make                # build/bpfjctl
make STATIC=1       # bpfjctl with no shared object dependencies
make client         # build/bpfjclient, no BPF toolchain needed
make signing-key    # generate a development signing key and certificate
make signed SIGNING_KEY=... SIGNING_CERT=...   # static, fs-verity signed bpfjctl
make srv  SIGNING_KEY=... SIGNING_CERT=...     # static, signed bpfjsrv
make cmd  SIGNING_KEY=... SIGNING_CERT=... \
     CMD_ARGS="replace-compiled" CMD_POLICY=policy.yaml CMD_ROLE=bpfjailer
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
sudo bpfjctl check  policy.yaml          # parse a policy and report what it holds
sudo bpfjctl attach policy.yaml          # load and pin the jailer
sudo bpfjctl replace policy.yaml         # reload without releasing jailed tasks
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

## Policy

```yaml
base-role: floor               # optional: every process on the host starts here
certs:
  corp-ca: |                   # PEM or base64 DER certificate
    MIIDXTCCAkWgAwIBAgIJAK...
roles:
  floor:
  webserver:
    enforce-binary-certs:      # execs must be signed by one of these
      - corp-ca
    kill:                      # may signal its own pod, plus these roles
      - floor
    ptrace:                    # empty: its own pod only
    bpf:                       # empty: only BPF objects its role owns
    keyring:                   # empty: only its own role's keyring
  sandbox:
    no-bpf: true               # bpf(2) denied outright
    no-kill: true              # kill denied outright
    no-keyring: true           # keyring writes denied outright
    unpriv-enroll: true        # bpfjsrv may enroll non-root callers
    enroll:                    # empty: bpfjsrv may add no further role
    override-stacked: true     # answers alone, ignoring roles stacked below
vars:                          # the only variable names a pod may carry
  - vm_uuid
```

For `kill`, `ptrace`, `bpf` and `keyring`, leaving a key out and writing it
empty mean different things. A missing key leaves that operation unrestricted,
an empty one confines the role to itself, and a list adds the roles named.
`no-bpf`, `no-kill`, `no-ptrace` and `no-keyring` are the outright-deny states
those lists cannot spell, and so each is rejected if written alongside its
list.
`enroll` has the same three states over which roles bpfjsrv may add to a
process already holding this one: missing is unrestricted, empty allows none
(not even this role again), and a list allows those roles.

A process holding several roles is allowed an operation only if every role
that configured it agrees; roles that did not configure it abstain. Roles are
consulted newest first, and an `override-stacked` role answers for the roles
under it. The target side of `kill` and `ptrace` ignores override: every role
the target holds has to be listed. The full semantics are documented in
`bpfj/policy/Policy.h`.

`vars` is an allowlist. An enrollment setting a variable the policy does not
list is refused, and with no `vars` at all no pod carries any. A `replace`
carries each pod's variables across by name, and fails if the new policy no
longer lists one a pod is carrying.

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

`yaml/` is vendored from
[mini-yaml](https://github.com/jimmiebergmann/mini-yaml) and keeps its own MIT
license notice.
