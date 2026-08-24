# Linux sealed certification

Linux sealed support is a native release claim, not an inference from compilation or the standard cgroup backend. The blocking suite is:

The installed provider has an explicit systemd capability bounding set. `CAP_SYS_PTRACE` is present only because the trusted provider must read kernel-owned `/proc` descriptor, namespace, credential, cgroup, and mount facts after the gated target changes to the authenticated nonroot caller identity. The service retains `NoNewPrivileges=yes`, grants no ambient capabilities, and keeps its filesystem sandbox. The target clears every capability before readback and authorization; certification fails if any target capability, including `CAP_SYS_PTRACE`, is present.

```text
cargo run --locked --package memcordon-ci -- suite backend-linux-sealed
```

The Rust CI driver builds the exact provider, installs the ephemeral root service through the provider's private package interface, verifies its complete no-follow root-owned installed package, and exercises the upgrade path. It then obtains a complete sacrificial qualification receipt, requires `doctor --require sealed`, and runs every scenario by exact name with one passing test and zero skips. Those scenarios include real unsafe-permission rejection and an upgrade after staging an authenticated abandoned attempt that must be retired before the repaired service is advertised. Cleanup always invokes the private uninstall operation. Privileged and time-consuming behavior belongs on the fresh Linux certification runner.

The suite accepts only `linux-pid-namespace-cgroup-v1`. Every affirmative qualification predicate, provider identity, receipt digest, terminal emptiness fact, helper reap, and boundary retirement must be present. Unavailability, a standard-boundary fallback, a missing artifact, an unrecognized schema, or an incomplete native receipt fails certification.

See [the Linux mechanism specification](../spec/sealed-linux-v1.md) and [sealed provider operation](sealed-provider.md).
