# Linux image workload contracts

Schema-3 contracts select the combined Linux private-loopback and UNIX-socket
profile. The installed provider authenticates the caller, current policy epoch,
approved plan, immutable runtime and input images, private root layout, and
exclusive execution identity before releasing an attempt.

An administrator imports each measured image with
`memcordon-sealed-agent package policy image install --definition FILE` and
activates its grants with `package policy apply --file FILE`. Imports copy
regular files into fresh protected inodes, check their declared bytes and native
target, reconstruct declared links, and durably publish the immutable image.
Image retirement uses `package policy image retire --definition FILE`; current
policy and live attempt references prevent retirement of an image still in use.

Launch an approved image entrypoint with:

```text
memcordon --sealed --workload-contract contract.json \
  --report-format result-v2 --report result.json \
  --wait-for workload --image-entrypoint builder -- target-argument
```

The entrypoint ID is resolved from the approved runtime image. It need not exist
at a host executable path. Arguments after `--` contain target arguments only.
The provider constructs the trusted startup environment and checks the actual
ELF interpreter and library closure from held image bytes.

Each attempt receives fresh mount, PID, network, and IPC namespaces. Its private
root contains the approved immutable image closure, declared writable roots,
private kernel filesystems, and explicitly selected output destinations.
Loopback TCP and UNIX sockets remain inside that attempt. With
`--wait-for workload`, root command exit does not finish the workload while
descendants still hold resources.

Result-v2 retains the actual public invocation separately from the effective
image invocation. Authenticated native execution and retirement include held
process identities, namespace and root association, relay completion, selected
export measurements, and account reservation retirement. Failed cleanup retains
its exact obligations for recovery. Read-only planning and capability discovery
reserve nothing and never authorize a later launch.

Consumer readiness is a separate CI assessment. It independently joins unchanged
runtime reports to acquired product bytes, owned fixture observations, original
producer artifacts, and installed-lifetime cleanup receipts. Runtime admission
does not consume readiness inventories, fixture transcripts, or CI verdicts.
