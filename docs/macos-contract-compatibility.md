# macOS contract compatibility

The launch-v2 and runtime-evidence-v1 golden vectors are immutable examples of
the current wire grammar. Valid serialized bytes remain unchanged by the strict
decoder corrections. Unknown message or evidence fields are malformed input;
silently dropping them could misrepresent an authority-bearing observation.
Release unit variants now use a private strict wire representation while their
public Rust variants and JSON tags remain unchanged. Delivery writer evidence
also rejects unknown fields. These corrections do not change deadline ordering
or the evidence consistency predicate.

Adding a clock domain or changing runtime consistency semantics requires an
explicit compatibility decision, reviewed vectors, and producer/consumer
validation before adoption. A new domain must specify its epoch, units, overflow
behavior, and cross-boot interpretation. Existing schema-version fields alone
do not authorize reinterpretation of old observations.

`Prepared` and `PreparedBy` describe preparation, never successful persistence.
Unknown release cannot certify complete retirement. Complete retirement must
retain every native cleanup obligation and the original deadline boundaries.
Pending retirement lists remain bounded by the production decoder.

Current launch vectors cover all 36 existing message variants, including the
test-support variants. Their execution is characterization of the existing
implementation; no protocol/channel extraction is authorized until the changed
commit passes both macOS architectures and the required oracle, delivery,
stress, and mutation gates. Local vector success is not native CI attestation.
