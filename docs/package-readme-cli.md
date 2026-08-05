# MemCordon CLI

`memcordon` runs a command and its descendants with optional memory and
elapsed-time budgets. When it detects a configured limit, it initiates bounded
workload cleanup and reports any cleanup failure.

## Install

```console
cargo install memcordon
```

## Run

From a Rust project, run its checks with a 1 GiB workload memory budget:

```console
memcordon +1GiB -- cargo check
```

Everything after `--` is passed to the child command unchanged. When `cargo
check` finishes normally, MemCordon returns its exit status; monitoring,
cleanup, and reporting failures take precedence.

## Reference

The installed command provides offline help:

```console
memcordon --help
memcordon doctor --help
memcordon plan --help
memcordon clean --help
```

See the [command reference](https://github.com/Portfoligno/memcordon/blob/main/docs/reference.md)
for policies, platform behavior, reports, and exit codes.
