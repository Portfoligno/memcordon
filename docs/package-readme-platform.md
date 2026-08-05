# MemCordon platform library

`memcordon-platform` probes and operates MemCordon's platform backends: cgroup
v2 containment on Linux, Job Objects on Windows, and sampled watchdog
monitoring on macOS. Most users should install the `memcordon` CLI; this crate
is for applications that embed backend probing or execution.

## Install

```console
cargo add memcordon-platform
```

## Minimal API path

Probe the current host without starting a child process:

```rust
fn main() {
    let report = memcordon_platform::probe();

    if let Some(backend) = report.selected {
        println!("selected backend: {}", backend.name);
    } else {
        for unavailable in report.unavailable {
            eprintln!("{}: {}", unavailable.name, unavailable.reason);
        }
    }
}
```

The example is complete when it prints the selected backend or explicit reasons
that no backend is available.

Execution also requires a `memcordon_core::Policy` and `CommandSpec`. On Linux
and macOS, the execution APIs require an explicit path to the installed
MemCordon executable for the launcher or guardian protocol.

## Reference

See the [generated API documentation](https://docs.rs/memcordon-platform) for
the probing, execution, supervision, and cleanup APIs.
