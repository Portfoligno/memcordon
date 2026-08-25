# MemCordon core library

`memcordon-core` provides the platform-neutral policies, outcomes, restart
state, and typed report models used by MemCordon. It does not start or contain
processes; applications that need execution use `memcordon-platform` or the
`memcordon` CLI.

`BoundaryRequirement::Sealed` expresses the fail-closed sealed-supervision
contract without exposing platform mechanisms. Certified Linux mechanism v2
satisfies the request only through a matching, qualified provider. A missing or
mismatched provider rejects execution before authorization and never falls
back to a standard backend. Execution reports use schema 8.

## Install

```console
cargo add memcordon-core
```

## Minimal API path

Create a memory policy and inspect its exact byte budget:

```rust
use memcordon_core::{ByteSize, Policy};

fn main() {
    let policy = Policy::new(ByteSize::from_bytes(512 * 1024 * 1024));
    assert_eq!(
        policy.memory.map(ByteSize::bytes),
        Some(512 * 1024 * 1024)
    );
}
```

The example is complete when it compiles and exits without an assertion
failure.

## Reference

See the [generated API documentation](https://docs.rs/memcordon-core) for all
public types and methods.
