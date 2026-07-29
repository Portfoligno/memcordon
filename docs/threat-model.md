# Threat model

MemCordon protects a workstation from accidental runaway allocation,
fork-heavy local tools, crashes, ignored graceful termination, and background
descendants.

It is not a hostile-code sandbox. Same-user code may signal or debug the
wrapper, interfere with delegated controls, or escape a macOS process group
with `setsid`. Use a container, virtual machine, dedicated identity, or platform
sandbox for hostile workloads.

Commands are accepted as an argument vector and are never parsed as shell
source. Internal descriptors are not intentionally inherited by targets.

