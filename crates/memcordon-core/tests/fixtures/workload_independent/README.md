# Independent V1 commitment vectors

These fixed hexadecimal preimages were assembled independently from the V1
domain, field-order, length, and tag specification. They were not emitted by
the MemCordon encoder. SHA-256 answers were calculated with OpenSSL over the
decoded bytes, before running production tests. Tests never regenerate them.

All domains end in NUL then schema 1 as a big-endian u16. Strings and vector
counts use big-endian u16; revisions and restart counts use big-endian u64.

The contract uses plan `11` repeated 32 times, Linux baseline profile digest
`6a8a4c2a8003371ea0c7cd8e3a2c340fb86a33c5980538d806783848578099bb`,
grant `grant-a` revision 1, baseline ceiling tags `01 02 02 02 01`, sorted
requirements `a-pair` (Unix socketpair/datagram) and `z-create` (Unix creation/
stream), zero endpoints, service nonce `03` repeated 16 times, and epoch 1.

The registry has one enabled qualified baseline profile, qualification `22`
repeated 32 times, one enabled grant, sorted Linux callers 1000 and 1001,
sorted plans `11` and `33` each repeated 32 times, and drain disposition 1.
It excludes epoch activation metadata. Effective policy binds the contract,
profile, registry digests, then the five ceiling tags.

The attempt binds request/plan/profile/grant/epoch, registry/qualification,
generation `0.5.3-dev:` followed by 40 ASCII `a` bytes, source 40 `a` bytes,
manifest `22` repeated 32 times, boot `boot-a`, effective digest, attempt
`attempt-a`, restart 2, nonce `04` repeated 16 times, and opaque caller/
invocation reference `05` repeated 16 times. This explicit field sequence
records the implementation's extension of the design's acyclic commitment
order. It is a compatibility fixture, not an independent authentication claim.

The checkpoint binds the attempt digest, Linux restriction tag 1, and six
true observation bytes. It contains no reverse reference in the attempt.

| Preimage | SHA-256 |
| --- | --- |
| contract.hex | 44c496721bec21fa8cc0e7e3f9dc1cd14077e263c7c2683f9ea5c2fe25b92b3c |
| registry.hex | a102255bf66093d7b7398a0d92a05b57007fa7cfc8cc70ee661e3e95d638fe76 |
| effective.hex | 2c50d523b361ef9ecb08efea05a7a09ec25fc3e29c6d5d80202d64830c284592 |
| attempt.hex | 974cebb1ed337a16b68a949070b26a331ad559b5cd32899e40c237941d73d496 |
| checkpoint.hex | 3e68071a6e9971b6e0ac37ac38d43aebcddbad2487939d510e557abe1c9e7eb1 |

## Reproducible fuzz seeds

The ignored `write_portable_fuzz_seed_corpora` integration test emits bounded
starting corpora for the six `workload-*` fuzz targets. Invoke it explicitly:

```text
cargo test --locked --package memcordon-core --test workload_independent_vectors -- --ignored --exact write_portable_fuzz_seed_corpora
```

It writes only under the ignored `fuzz/corpus/workload-*` directories. The
normal tests validate its inputs without writing files. Baseline canonical
bytes come from the independent fixture above. Additional JSON seeds are
produced by public constructors so authenticated discovery and terminal
receipt branches are reachable despite their nested digest dependencies.
These generated starting points are not independent expected-value oracles.

TCP seeds describe a listener and a client referencing its logical endpoint,
with kernel-assigned and range-selected ports. Parsing does not establish a
grant: the Linux baseline still rejects their TCP functionality. Malformed
seeds exercise unresolved and duplicate endpoints, stale schema, substituted
profile digest, incomplete discovery, unavailable terminal evidence, and
trailing canonical bytes. Abstract evidence transition fuzzing does not
replace native registry activation, revocation, or drain tests.
