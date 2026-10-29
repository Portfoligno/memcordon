# Windows effective-current-token profile

`windows-sealed-current-token-v1` uses the authenticated caller's effective token.
It provides Job supervision and cleanup, not a filesystem or network sandbox.
OS access checks apply independently to the provider endpoint and caller token.
Requests cannot select an identity, token, provider handle, or administrator grant.

The restricted control service authenticates the caller. The launcher creates a
fresh unnamed Job and suspended target with creation-time Job/handle lists,
verifies the caller token, resource limits and inherited streams, and retains an
external guardian before release. Commands, native UTF-16 argv, environment and
working directory retain their actual native values.

Current public/private transport is 4, durable records 5, terminal receipts and
retirement proofs 3, and capability owners 2. Only those current formats are
accepted. Recovery authenticates current records and native resources; no previous
policy registry, approval, activation epoch or durable reader is shipped.

Retirement requires actual direct target wait, Job emptiness, relay/guardian
retirement, slot closure and final handle closure. Frontend ACK and result delivery
remain separate observations. Unknown outcome or incomplete cleanup remains
explicit. Source compilation does not qualify native execution.

Installation requires clean or verified compatible current custody. Unknown
occupied state is refused intact. See the [current request and result contract](../docs/spec-workload-request-v1.md),
[causal diagnostics](windows-causal-diagnostics-v1.md), and
[sampled process observation](windows-process-observation-v2.md).
