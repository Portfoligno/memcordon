# Linux sealed certification

Linux sealed support is a native release claim, not an inference from compilation or the standard cgroup backend. The blocking suite is:

```text
cargo run --locked --package memcordon-ci -- suite backend-linux-sealed
```

The Rust CI driver builds the exact provider, verifies its package, installs and upgrades the ephemeral root service through the provider's private package interface, obtains a complete sacrificial qualification receipt, requires `doctor --require sealed`, and runs every scenario by exact name with one passing test and zero skips. Cleanup always invokes the private uninstall operation. Privileged and time-consuming behavior belongs on the fresh Linux certification runner.

The suite accepts only `linux-pid-namespace-cgroup-v1`. Every affirmative qualification predicate, provider identity, receipt digest, terminal emptiness fact, helper reap, and boundary retirement must be present. Unavailability, a standard-boundary fallback, a missing artifact, an unrecognized schema, or an incomplete native receipt fails certification.

See [the Linux mechanism specification](../spec/sealed-linux-v1.md) and [sealed provider operation](sealed-provider.md).
