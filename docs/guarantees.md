# Guarantees

MemCordon distinguishes kernel-backed enforcement from a sampled watchdog.

Linux cgroup v2 and Windows Job Objects provide workload-wide kernel enforcement
when their host capabilities are available. Setup and assignment complete before
the target is released.

The macOS backend guarantees owned-handle direct-child tracking, prompt reaping,
pre-exec process-group creation, bounded sampling, fail-closed monitor errors,
and repeated best-effort descendant cleanup. It cannot guarantee zero
overshoot, observe every short burst, or contain a process that creates a new
session before discovery.

![Key guarantees](assets/key-guarantees.png)
