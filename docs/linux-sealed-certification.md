# Linux sealed native tests

Linux native tests exercise cgroup containment, caller identity, credential
transitions, cancellation and cleanup. Installed consumers use the selected native
archive or packaged crates and exercise real provider installation, protected
files and units, local grants, execution and package recovery. A native setup
failure must remain a failure or an explicit unavailable host.

The installed privileged control and launcher services retain their operational
authentication and isolation requirements. A saved self-test report is diagnostic
output. Every launch performs its actual caller, file-identity and host-control
checks; contract-bound launches also resolve the live local policy.

Useful scenarios cover credential transitions, caller restrictions, mount context,
recursive-provider rejection, frontend/provider/launcher/guardian loss, descendants,
and complete resource retirement. Test cleanup must remove only resources owned
by that test and report any remaining process, cgroup, file, unit or account
obligation honestly.

See [the Linux mechanism specification](../spec/sealed-linux-v2.md) and
[sealed provider operation](sealed-provider.md) for the retained runtime boundaries.
