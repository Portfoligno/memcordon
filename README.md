# MemCordon

MemCordon runs a command and its descendants with optional memory and elapsed-time budgets. It uses native containment on Linux and Windows and sampled monitoring on macOS, terminating the workload when a configured limit is detected.

![MemCordon memory-limit terminal banner](docs/assets/banner.png)

## Install

Download the [latest release](https://github.com/Portfoligno/memcordon/releases/latest) for your platform and place `memcordon` (`.exe` on Windows) on `PATH`, or install with Cargo:

```console
cargo install memcordon
```

## Run

```console
memcordon +8GiB -- cargo test --workspace
```

Replace `cargo test --workspace` with your command. Everything after `--` is passed to it unchanged. If the command stays within the 8 GiB budget, its exit status is preserved unless MemCordon encounters a higher-precedence supervision failure; a confirmed memory-limit event returns status 124.

## Reference

- [CLI, platform, and status reference](docs/reference.md)
- [Rust API](https://docs.rs/memcordon/)
- [Changelog](CHANGELOG.md)
