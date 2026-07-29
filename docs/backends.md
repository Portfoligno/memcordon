# Backends

Run `memcordon probe` or `memcordon probe --json` before automation.

## macOS watchdog

The target enters a new process group before `exec`. Descendants are discovered
from public libproc process information and retained by PID plus birth time.
Physical footprint is sampled every 50ms by default.
An out-of-workload guardian process watches a control pipe and force-kills the
process group if the wrapper disappears unexpectedly.

## Linux cgroup v2

The direct provider creates a package-owned child cgroup, configures memory and
swap controls, starts a gated launcher, verifies its membership, and only then
releases target execution. Limit evidence comes from `memory.events`.

## Windows Job Object

The target is created suspended, assigned to an unnamed kill-on-close Job
Object, and then resumed. A completion port reports job memory events and
active-process transitions. The configured notification threshold is one native
page below the hard job-wide commit cap.
