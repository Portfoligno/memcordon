# Sealed provider operation

The sealed provider is private MemCordon machinery distributed with the
`memcordon` Cargo package and Linux and Windows native release archives. The public request
remains `memcordon --sealed ... COMMAND ARGUMENT...`; the CLI never accepts a
provider endpoint, platform principal, boundary handle, or cleanup hook.

## Acquisition and administration

Cargo installs the public CLI and its exact-version companion together:

```console
cargo install --locked memcordon
sudo ~/.cargo/bin/memcordon-sealed-agent package install
~/.cargo/bin/memcordon-sealed-agent package verify --json
~/.cargo/bin/memcordon doctor --require sealed
sudo ~/.cargo/bin/memcordon-sealed-agent package upgrade
sudo ~/.cargo/bin/memcordon-sealed-agent package uninstall
```

On Windows, run the corresponding commands from an elevated Command Prompt or
PowerShell window:

```console
cargo install --locked memcordon
%USERPROFILE%\.cargo\bin\memcordon-sealed-agent.exe package install
%USERPROFILE%\.cargo\bin\memcordon-sealed-agent.exe package verify --json
%USERPROFILE%\.cargo\bin\memcordon.exe doctor --require sealed
%USERPROFILE%\.cargo\bin\memcordon-sealed-agent.exe package upgrade
%USERPROFILE%\.cargo\bin\memcordon-sealed-agent.exe package uninstall
```

A verified Linux native archive contains `memcordon`,
`memcordon-sealed-agent`, and `runtime-manifest.json` at its root. The Windows
archive additionally contains `memcordon-target-desktop-bootstrap.exe` and
`memcordon-session-broker.exe`. The Linux flow is equivalent:

```console
sudo ./memcordon-sealed-agent package install
./memcordon-sealed-agent package verify --json
./memcordon doctor --require sealed
sudo ./memcordon-sealed-agent package upgrade
sudo ./memcordon-sealed-agent package uninstall
```

The Windows archive equivalents, again from an elevated terminal, are
`memcordon-sealed-agent.exe package install`, `package verify --json`, `package
upgrade`, and `package uninstall`, plus `memcordon.exe doctor --require sealed`.

`package inspect --json` is credential-free and reports the current agent,
embedded baseline-unit or Windows service metadata digests, protocol, report schemas,
source commit, and executable digest. `package install`, `upgrade`, and
`uninstall` remain explicit root or elevated mutations. CLI/provider version
mismatch fails before target authorization; installation and upgrade never
download or compile a component.

## Trust and transport

Linux mechanism v2 uses the fixed public local socket `/run/memcordon/sealed-agent.sock` and the root-only private broker socket `/run/memcordon/sealed-launcher.sock`. The hardened `memcordon-sealed-agent.service` control plane owns the public socket, runs with `NoNewPrivileges=yes`, authenticates the peer, captures its execution envelope, rejects callers already inside an active attempt, and never executes caller code. The minimally scoped `memcordon-sealed-launcher.service` accepts only the authenticated control service, runs with `NoNewPrivileges=no`, and creates the target from the caller's mount and privilege-transition context. A packaged tmpfiles declaration recreates `/run/memcordon` as mode `0750` `root:memcordon` before either socket activates, so reboot cannot replace the traversable public endpoint parent with a root-only directory.

The optional network launcher units are selected with the Linux private-tcp
feature. Installed files alone do not grant a workload. The authenticated launcher
independently captures the caller, resolves the current protected local grant and
epoch, pins the approved ELF and reserves the exact target account before creating
its private boundary. Discovery reports actual package, service and local profile
state as advisory data.

Windows uses the restricted LocalService control service and restricted
LocalSystem launcher, with authenticated local pipes. Installation provisions eight
demand-start guardian slots without automatic restart or required privileges.
Each attempt owns one fresh guardian process; SCM status, pipe peer, image, token,
service SID, attempt and nonce must agree before capability transfer. The launcher
cannot create or reconfigure services. Fixed directory/pipe ACLs and service
privilege lists are installed through native SCM APIs. The client independently
verifies installed component bytes, authenticated server identity and current
native readiness. Caller identity and native state come from authenticated kernel
objects; saved self-test output never grants launch permission.

Linux messages use the bounded binary [provider protocol v2](../spec/sealed-provider-protocol-v2.md); Windows messages use the bounded [Windows provider protocol v1](../spec/sealed-windows-provider-v1.md). Unknown versions, kinds, oversized lengths, replayed launch identities, transferred-handle mismatches, and caller-envelope mismatches are rejected before target authorization. Post-launch Windows frames bind the attempt id, nonce, and request digest. The public launch payload remains mechanism-free. Programs and arguments remain separate native values and are never represented as shell commands.

## Attempts and recovery

Every attempt advances through `Allocated`, `BoundaryCreated`, `GuardianReady`, `TargetCreatedGated`, `AssignmentVerified`, `ResourceInheritanceVerified`, `Authorized`, `Running`, `Terminating`, `Empty`, and `Retired`. Authorization cannot precede authenticated caller-envelope capture, launcher authentication, caller mount-namespace adoption, caller capability-envelope reproduction, exact descriptor verification, and all existing boundary checks. Retirement cannot precede an emptiness proof.

Before authorization the provider persists only recovery identity: attempt/provider generation, native boundary identity, helper identities, front-end identity, authorization/cleanup state, and an integrity digest. It does not persist command arguments, environment values, stream contents, or secrets.

Provider startup resolves authenticated abandoned attempts before advertising capability. Ambiguous live state quarantines the record and keeps sealed unavailable. Names, paths, and numeric process ids alone are never sufficient authority to kill or retire a workload.

Front-end loss triggers the independent guardian. Provider loss cannot produce ordinary success: Linux retains a per-attempt root guardian and broker-owned `cgroup.kill` authority outside the workload, while Windows combines a guardian with Job kill-on-last-handle authority and launcher-side guardian-liveness checks. Upgrade and uninstall refuse to mutate provider state while an authenticated attempt is live or recovery is ambiguous.
