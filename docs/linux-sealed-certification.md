# Linux sealed certification

Linux sealed support is a native release claim, not an inference from compilation or the standard cgroup backend. The blocking suite is:

The installed package contains a hardened public control service/socket and a separate root-only launcher service/socket. The control service retains `NoNewPrivileges=yes`, an explicit narrow capability bounding set, no ambient capabilities, and its filesystem sandbox. The launcher uses `NoNewPrivileges=no`, has no ambient capabilities, and omits `PrivateTmp`, `ProtectSystem`, `RestrictSUIDSGID`, and a guessed capability bounding set so that it can reproduce the authenticated caller's mount context, `NoNewPrivs`, and capability ceiling. Before authorization, the target has the caller's UID/GID/groups and bounding set but no provider effective, permitted, inheritable, or ambient capabilities.

```text
cargo run --locked --package memcordon-ci -- suite backend-linux-sealed-v2
```

The Rust CI driver builds the exact provider, installs the four ephemeral root-owned unit artifacts through the provider's private package interface, verifies their no-follow identities and exact bytes, and exercises upgrade/recovery. It obtains a complete qualification-schema-2 receipt, requires `doctor --require sealed`, and runs every scenario by exact name with one passing test and zero skips. The v2 inventory includes set-ID, `sudo -n -u`, file-capability, caller `NoNewPrivs`, reduced caller capability bounding set, caller mount-context, recursive-provider rejection, post-transition escape probes, front-end/provider/launcher/guardian loss, and terminal leak checks. Cleanup always invokes the private uninstall operation and proves that no test user, attempt process, record, cgroup, fixture, or unit remains.

The suite accepts only `linux-pid-namespace-cgroup-v2`, provider protocol v2, qualification schema 2, terminal receipt v2, and report schemas 8/7/5. Every caller-envelope reproduction fact, transition-certification digest, post-transition membership fact, terminal emptiness fact, helper reap, and boundary retirement must be present. Linux x86-64 release certification requires usable set-ID, `sudo`, and file-capability scenarios; host unavailability is not a passing result there. A v1 provider, standard-boundary fallback, missing artifact, unrecognized schema, skipped scenario, or incomplete native receipt fails certification.

The release artifact contains newline-terminated structured reports for package verification, qualification v2, set-ID, `sudo`, file capabilities, caller envelope, mount context, fault injection, and cleanup/leak proof. See [the Linux mechanism v2 specification](../spec/sealed-linux-v2.md) and [sealed provider operation](sealed-provider.md).
