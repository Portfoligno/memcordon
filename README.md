# MemCordon

MemCordon runs a command and its descendants with optional workload-wide memory
and elapsed-time limits. Use it when builds, tests, workers, or other commands
can spawn child processes and need one containment boundary with reliable
cleanup and exit-status reporting.

![MemCordon command containment overview](docs/assets/banner.png)

## Install

Download the [latest release](https://github.com/Portfoligno/memcordon/releases/latest)
for your platform and put `memcordon` (`.exe`) on `PATH`, or install with Cargo:

```console
cargo install memcordon
```

Installation from source requires Rust 1.85 or newer.

## Run a command

Apply a 1 GiB memory limit and a 10-minute deadline:

```console
memcordon +1GiB +10m ./workload
```

`./workload` and any following arguments are passed through unchanged. MemCordon
preserves the workload's exit status unless a limit or supervision failure occurs.

| Status | Meaning |
| ---: | --- |
| `123` | Deadline |
| `124` | Confirmed memory limit |
| `125` | Wrapper or cleanup failure |

`--restart` can relaunch the workload after configured limits; its
[conditions and backoff](docs/reference.md#deadline-and-restart-policy) are configurable.

## Platform support

Linux and Windows use cgroup v2 or Job Objects for hard memory enforcement when
the host permits it. macOS uses sampled watchdog monitoring, which can overshoot
or miss short bursts. `memcordon doctor` reports the selected backend and any
host limitations without launching a workload.

## Reference

- Run `memcordon --help` for command-line help.
- See the [contract reference](docs/reference.md) for policies, platform
  behavior, reports, and exit codes.
- Review the [changelog](CHANGELOG.md) or [MIT license](LICENSE).
