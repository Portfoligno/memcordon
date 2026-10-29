# Current Linux sealed transport

Ordinary credential-preserving execution uses native transport 3. Private
workload execution uses transport 5 and `memcordon.workload-request` revision 1.
Each accepts only its current kinds and exact bounded input. Unsupported versions
and kinds fail before payload allocation or native mutation.

Frames have a 72-byte big-endian header: version, kind, total length, request nonce,
attempt id and SHA-256 payload digest. Frames are bounded to 1 MiB; input/output
chunks are bounded to 64 KiB. The digest checks integrity. Socket credentials,
held process identities, exact descriptor purposes and transaction association
authenticate the actual source. No shell command or host output pathname crosses
the private workload transport.

One private attempt owns one authenticated session. The provider publishes the
original locator before input, imports fresh bounded snapshot bytes, verifies
native preparation, then sends Prepared42. PreparedAck48 binds the original
association and exact preparation bytes before release. Native work, retries,
input, output and recovery retain the original applicable cutoffs.

Current recovery uses the exact protected `memcordon.private-workload-journal`
revision 1 and original native identities. It never launches a target or invents
an exit status. Current ACK physically retires completed owned metadata only
after all required native owners are settled. Unknown state remains retained.

The [request contract](../docs/spec-workload-request-v1.md) defines fixed account,
snapshot, namespace, output and delivery boundaries.
