# Windows causal diagnostics V1 portable contract

This module defines failure observations, not terminal receipts. Diagnostic
validity never establishes cleanup completion, target outcome, or restart
authority. Native capture, authenticated Windows replay and durable writer
integration must be qualified before a provider advertises this capability.

The public projection omits caller tokens, nonces, process creation identities,
private paths, raw messages, arguments and environment. Details are closed
provider message identifiers or numeric count/limit facts. Native codes preserve
their original domain and full bit pattern; legacy integers remain untyped.

The first observed failure is immutable. The journal retains the next eight
events in observation order, then counts omissions with saturating arithmetic.
Sequences are contiguous across retained events; the last sequence accounts for
retained and omitted events. A durable watermark cannot exceed that sequence.
An unavailable original remains unavailable when recovery appends observations.

JSON decoders reject unknown fields, duplicate fields, unknown enum tags,
excess event entries, invalid digest encoding and contradictory sequences.
Call the bounded journal or projection parser before decoding untrusted input.
Projection input is limited to 16 KiB; journal input to 64 KiB. The bounded text
visitor checks decoded byte length before copying into owned storage. The JSON
parser may require scratch storage for escapes, so the outer byte cap remains
mandatory. All projection digests are lowercase SHA-256 hexadecimal.

## Canonical digest

Hash the following ordered byte stream with SHA-256. Exclude the projection's
digest field. Integer encodings are unsigned big-endian except signed native
values, which preserve their two's-complement bits. No JSON encoding enters the
canonical stream.

1. The ASCII bytes `memcordon:causal-diagnostic:v1` followed by a zero byte.
2. Schema as u32.
3. Provider generation and source commit, each encoded as u64 UTF-8 byte length
   followed by those bytes.
4. Runtime manifest, attempt and request digests, each as 32 raw bytes.
5. Diagnostic sequence as u64. Durable watermark: zero byte if absent; otherwise
   byte 1 followed by u64.
6. Original: byte 0 followed by an event when observed; byte 1 followed by an
   unavailable-reason u16 otherwise.
7. Secondary count as u64, then each event in retained order.
8. Omission count as u32, then one byte each for saturation, persistence failure
   and writer unavailability (false 0, true 1).

Each event contains: sequence u64; origin, category, operation and failure-code
u16 tags; native-code encoding; phase u16; detail encoding; redacted and truncated
boolean bytes; terminalization reference encoding.

Native code uses byte 0 for absent; Win32, NTSTATUS, HRESULT, Winsock, errno and
legacy untyped use bytes 1 through 6 followed by the native 32-bit value.
Detail uses byte 0 for none, byte 1 followed by observed/limit u32 values, or byte
2 followed by the safe-message u16 tag. Terminalization reference uses byte 0 for
absent, byte 1 for the first error, or byte 2 followed by a u8 secondary index.
The index must be below the existing terminalization secondary-event ceiling.

Unit enum tags are explicitly assigned in `crates/memcordon-core/src/diagnostics.rs`.
Those assignments are immutable in V1. New discriminants require explicit schema
review; declaration insertion or reordering cannot renumber existing tags.

## Independent known-answer vector

The regression fixture uses generation `test-provider`, source commit
`0123456789012345678901234567890123456789`, manifest bytes all 1, attempt bytes
all 2 and request bytes all 3. Sequence is 1 with no durable watermark. Its
original event is Launcher/Monitor/ObserveProcessIdentity/
ProcessInventoryObservation, Win32(1234), Monitoring phase, no detail, redacted
true, truncated false, and no terminalization reference. Secondary events and
loss counts are empty/zero. Its digest, calculated independently using Python's
hashlib and explicit integer packing, is:

`ef433f64117baa1db88649ce38386ea3af3c491b3c2645d8415c9f855c97a3e5`

The digest detects mutation only in conjunction with a trusted binding. It is
not a signature. `parse_bound` compares provider, attempt and request bindings
supplied by an already authenticated invocation before returning the wrapper
accepted by `Error::with_provider_failure`. Report parsing independently checks
structural and digest consistency, and never treats that check as authentication.

## Native ownership and retention

The attempt-local observation slot is established before launch setup and lives
through the outer rejection handler. Source failures and cleanup observations
share that sequence owner. Reserved journal copies preserve the secondary-event
capacity during unwinding; reentrant capture records explicit loss.

Every record publication enters a bounded writer lane. A native installation
mutex serializes reservation accounting; a native attempt mutex serializes
publication and removal across processes. A separate writer reservation retains
its charge after the workload admission lease disappears. Only a confirmed local
retirement or a dead prior owner permits releasing that charge. Cleanup submits
diagnostic snapshots without waiting for disk completion.

The effective writer concurrency is one. Each active attempt reserves 80 MiB
within a 128 MiB installation record-state budget. One installation-wide retained
reader can reserve another 48 MiB before reading. Its durable reservation and
native mutex follow the decoded snapshot and, for terminal replay, serialization,
delivery and acknowledgment. The payload is released immediately after delivery;
the reservation remains until acknowledgment handling completes. Immutable outbox backing is
shared by owner and queued snapshots; retained files consume their actual byte
size. Existing terminal payloads remain bounded independently. The serialized
publication image, including pretty layout, escaping and newline, cannot exceed
its fixed-capacity writer reservation. These source-level bounds still require
native storage-stall and cross-process fault qualification before certification.

The writer reservation covers mutually exclusive phases, rather than counting
every serialized image as an independent heap allocation:

| Phase | Charged large allocations and files | Metadata allowance | Ceiling |
| --- | --- | --- | --- |
| Previous-record decode | 16 MiB committed file, 16 MiB opened-file buffer, up to 8 MiB decoded-string scratch, 8 MiB temporary string, 8 MiB previous outbox, 8 MiB shared current outbox | 8 MiB | 72 MiB |
| Publication and readback | 16 MiB committed file, 16 MiB staging file, 16 MiB publication bytes, 16 MiB readback bytes, 8 MiB shared current outbox | 8 MiB | 80 MiB |
| Retained reader decode | 16 MiB opened-file buffer, 8 MiB string scratch, 8 MiB temporary string, 8 MiB shared decoded outbox | 8 MiB | 48 MiB |

Owner, in-flight and two queued records share the immutable `Arc<str>` outbox.
The metadata allowance includes their separate bounded admission/checkpoint
copies, the rejected enqueue candidate, journal buffers, and the transient tagged
enum decode tree. Record text fields are limited to 256 bytes; terminalization
retains at most five errors with 128-byte codes and 2 KiB details. Admission
containers bound requirements to 64 and endpoints to 32, with bounded identifiers
and fixed-size digests/nonces. Before typed decoding, a streaming structural pass
limits JSON to 16,384 nodes, depth 32 and 256 KiB aggregate metadata string bytes.
The outbox string is independently capped at 8 MiB and its embedded JSON receives
the same structural pass. Oversized strings fail before constructing the owned
string/`Arc` pair. Native authentication now constructs the bounded core record
directly and streams canonical bytes into SHA-256, avoiding an additional 16 MiB
serialization/reparse cycle. Reservation scans read only 4 KiB admission markers
and file metadata; they never allocate a full retained image.

Version-two terminal/rejection transport reserves at most 4 MiB per encoded
frame. The generic outer bound remains 16 MiB for other existing message kinds.
This terminal bound follows the admitted production constructors: at most 256
process identities; fixed native service identity and scalar outcome fields;
empty cleanup/restart errors for a receipt carrying retirement authority;
bounded rejection detail; and at most two loader-plan copies, each independently
validated at 64 KiB before authorization. Workload bindings contain bounded
identifiers, digests, nonces and fixed baseline observations. The 256 KiB text
allowance includes both loader-plan copies. The general structural envelope
allows 16,384 ASCII field names of at most 64 bytes, 256 KiB text expanded sixfold
by JSON escaping, and scalar/punctuation overhead, still below 4 MiB. Portable
tests exercise the maximum identity inventory and a maximal escaping envelope.

The reader's 48 MiB phase allowance also covers relay copies: source object,
private serialization, control raw frame and decoded object, authority encoding,
and public serialization. Every terminal frame/authority encoding is capped at
4 MiB. At the ACK record-read phase the launcher has released its source payload;
the control retains only its bounded decoded response. Private replay retains
the same reader permit through this phase. These protocol buffers are accounted
for, rather than excluded from installation memory ownership.

The relay reservation counts simultaneous owners conservatively, including a
sender buffer after its peer has consumed it:

| Relay phase | Simultaneously charged allocations | Ceiling |
| --- | --- | --- |
| Private delivery and public forwarding | Source outbox backing (8 MiB); source decoded response (4 MiB); private serialization (4 MiB); control raw frame (4 MiB); control decoded response (4 MiB); authority response clone (4 MiB); authority serialization (4 MiB); public serialization (4 MiB); decode scratch, bounded metadata and projection copies (8 MiB) | 44 MiB |
| ACK validation | Opened record bytes (16 MiB); decode scratch (8 MiB); temporary outbox string (8 MiB); control retained response (4 MiB); decoded metadata, projection and ACK bookkeeping (8 MiB) | 44 MiB |

The remaining 4 MiB is reserved headroom. ACK validation does not retain the
launcher source response: `release_payload` precedes the ACK read. Its record
decoder has no simultaneous immutable outbox conversion because ACK validation
uses the decoded core record directly. The permit is held until the private
retirement response has been delivered, so another retained reader cannot
overlap these phases without a separate installation reservation.

Retained records consume their actual file lengths in addition to active writer
and reader reservations. A reader may therefore be unavailable while active and
retained state exhausts the installation ceiling. That denial preserves the
record and existing terminal authority. Tombstones conservatively retain a
64 KiB payload reservation until terminal authority permits record retirement;
expiry removes exportable diagnostic content without promising extra capacity.

Retained payloads have a persisted 24-hour monotonic lifetime, a 128-payload
ceiling, and an 8 MiB aggregate reservation. Boot uncertainty or an invalid age
never renews export authority. A safe sweep replaces only the diagnostic journal
with a typed tombstone on completed records; replay protection, cleanup state,
owner identity and unacknowledged terminal outboxes remain intact. Failed
publication retains its quota charge.

Public and private version-two response frames place the compact `message`
discriminator first. Readers inspect at most 256 stack bytes before allocating
the body. `attempt-retained` and `replay-pending` use the 64 KiB diagnostic frame
limit; existing terminal payload limits remain separate. Duplicate JSON keys
are rejected before typed decoding.

Diagnostics accompany live rejection/replay responses, but are excluded by
`terminal_authority_json` from immutable outbox and acknowledgment bytes. Replay
can attach a currently eligible projection or omit an expired one without
changing ordinary terminal authority. Public projections require the exact
authenticated attempt/caller and an independently verified installed manifest.
