# Unprivileged enrollment

A process jails itself without being able to jail anything else.

Attaching the jailer needs root, and so does writing its maps. Enrolling
through `bpfjsrv` does not: the server does the privileged half, reads the
caller's pid off the connection with `SO_PEERCRED`, and decides what it is
allowed to ask for from the role's policy. So `run.sh` takes no `sudo` and
still ends up in a jail it cannot leave.

## Running it

```
./build.sh     # bpfjctl, bpfjsrv, bpfjclient
./attach.sh    # sudo: attach the jailer, start bpfjsrv
./run.sh       # no sudo: a jailed shell
./detach.sh    # sudo: stop bpfjsrv, unload the jailer
```

`attach.sh` loads BPF LSM programs for the whole host, so run `detach.sh`
when you are done. Nothing here survives it.

`run.sh` with no arguments gives a shell; with arguments it runs those
instead, the same way `bpfjctl wrap` takes a command:

```
./run.sh id
./run.sh bash -c 'echo in the jail'
```

## What it shows

`policy.yaml` has one role, `sandbox`:

```yaml
roles:
  sandbox:
    unpriv-enroll: true
    fs-any: true
    verity-any: true
    kill-pod: true
    ptrace-pod: true
```

`unpriv-enroll: true` is the only reason a non-root caller may take this role.
Leave it out and `bpfjsrv` refuses with `role sandbox is not open to
unprivileged callers`, which is what every other role gets by default.

BPF is omitted because absence is the load-bearing denial: a jailed process
holding `CAP_BPF` cannot delete its own entry from the jailer's maps and walk
out. `bpf-pod: true` would instead permit BPF objects from its own pod.

The two pod options confine signalling and ptrace to the pod. `fs-any` and
`verity-any` keep ordinary file access and unsigned executables open so the
shell can run; all other unspecified operations remain denied. Enrollment is
omitted, so a process in the jail cannot ask `bpfjsrv` for any further role.

To watch the jail refuse something, start a process outside it and try to
signal it from inside:

```
sleep 300 &        # another terminal, same user
./run.sh
  kill <that pid>  # Operation not permitted
```

The same `kill` from outside the jail succeeds. Same user, same command, so
it is the `kill-pod:` policy refusing and not file permissions — which is the
point, since an example that only shows root-only operations being denied to
a non-root process would demonstrate nothing.

`bpfjctl` does not work inside the jail either: the role denies `bpf(2)`, so
the jail will not even be inspected from within. Use `sudo bpfjctl list` from
outside.

## The pieces

`bpfjclient`, built from `client/Main.cpp`, is the unprivileged counterpart to
`bpfjctl wrap`: the same `ROLE USER_ID -- COMMAND`
shape, except it enrolls over the socket instead of writing the maps, then
execs. Jail membership survives exec, so the command inherits the pod.

It is also the smallest demonstration of what `srv/Client.h` costs a caller:

```
$ ldd build/bpfjclient
    libstdc++.so.6 ... libc.so.6 ...
```

No libbpf, no BPF skeletons. `build.sh` builds it on its own
line for that reason — a service that wants to jail itself needs a C++
compiler and nothing else.

## systemd

In a real deployment `bpfjsrv` is socket activated by the units in `srv/`:
`bpfjsrv.socket` binds `@bpfj` with `Accept=yes`, and `bpfjsrv@.service`
handles one connection per instance.

`attach.sh` uses `systemd-socket-activate` instead, which does the same thing
without installing anything. The one difference is where the connection
arrives: the tool passes it as fd 3 with `LISTEN_FDS=1`, while the unit's
`StandardInput=socket` puts it on stdin. `bpfjsrv` accepts either and checks
the descriptor is a connected socket rather than trusting the environment.
