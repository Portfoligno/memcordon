# MemCordon CLI

`memcordon` runs a command and its descendants with optional memory and
elapsed-time budgets. When it detects a configured limit, it initiates bounded
workload cleanup and reports any cleanup failure.

## Install

```console
cargo install --locked memcordon
```

The package installs both `memcordon` and the private
`memcordon-sealed-agent` companion binary. Ordinary supervision needs no
privileged setup. On Linux, enable sealed supervision explicitly from a root
terminal:

```console
sudo ~/.cargo/bin/memcordon-sealed-agent package install
~/.cargo/bin/memcordon doctor --require sealed
```

Use the agent's absolute path because `sudo` may omit the Cargo bin directory
from its secure path. On Windows, use an elevated Command Prompt or PowerShell
window (without `sudo`):

```console
%USERPROFILE%\.cargo\bin\memcordon-sealed-agent.exe package install
%USERPROFILE%\.cargo\bin\memcordon.exe doctor --require sealed
```

Native Linux and Windows release archives provide the same two binaries
together (with `.exe` names on Windows).

## Run

From a Rust project, run its checks with a 1 GiB workload memory budget:

```console
memcordon +1GiB --summary -- cargo check
```

Options and budgets may be interleaved before the command. Once the command or
an explicit `--` boundary starts, all remaining arguments pass through
unchanged.

Time budgets and duration-valued options accept decimal `ms`, `s`, `m`, or `h`
values.

Everything after `--` is passed to the child command unchanged. When `cargo
check` finishes normally, MemCordon returns its exit status; monitoring,
cleanup, and reporting failures take precedence.

`--sealed` requests the stronger process-boundary contract documented in
`docs/sealed-supervision.md`. Certified Linux mechanism v2 and Windows Job
Object mechanism v2 require the matching installed provider, fail before
target authorization when missing or mismatched, and never fall back to a
standard backend.

The default completion mode is `--wait-for command`. When the direct command
exits, the default zero command-exit grace force-cleans any remaining contained
descendants before returning the direct command's status. Set
`--command-exit-grace DURATION` to allow a bounded, signal-free natural drain
before forced cleanup. Use `--wait-for workload` when the direct command is a
launcher and its descendants should continue to natural completion; on
supported backends, that mode can wait indefinitely without a deadline.

Run `memcordon help lifecycle` for completion-mode details and platform
differences.

## Reference

The installed command provides offline help:

```console
memcordon --help
memcordon help
memcordon help memory
memcordon help containment
memcordon help all
memcordon doctor --help
memcordon plan --help
memcordon clean --help
```

See the [command reference](https://github.com/Portfoligno/memcordon/blob/main/docs/reference.md)
for policies, platform behavior, reports, and exit codes.
