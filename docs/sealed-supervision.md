# Sealed supervision

`--sealed` requires MemCordon to establish and verify a certified process-supervision boundary before authorizing the command. It retains cleanup authority outside the workload, restricts inherited supervisor resources, and does not return an ordinary child result until the direct child and helpers are reaped and the boundary is proven empty and retired.

The request fails before target execution when the host cannot satisfy every part of the contract. There is no fallback to standard supervision. The initial implementation reserves the public policy and evidence model but advertises no certified native backend; Linux, Windows, macOS, and other targets therefore fail closed.

## Threat model

The boundary covers ordinary lineage descendants that fork, double-fork, create process groups, call `setsid`, daemonize, outlive the direct command, retain standard streams, ignore graceful termination, or race launch and cleanup. Every restart attempt requires a fresh boundary and terminal retirement proof for the prior attempt.

Sealed supervision is not filesystem, network, syscall, package-manager, secret, kernel, or hypervisor isolation. It does not prevent a workload from asking an unrelated trusted host service to create a process outside its lineage, nor protect files and credentials already available to the caller.

Reports distinguish the requested boundary from the effective boundary and expose the individual authorization and cleanup predicates. A backend may report `sealed` only when every required predicate is supported and verified.
