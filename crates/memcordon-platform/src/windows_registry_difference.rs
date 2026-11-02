//! Bounded owner-only localization of an already fatal registry digest mismatch.
use crate::windows_registry_manifest::{Declaration, Key, Manifest, Root, ValueRecord};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Instant};

pub const RECORD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadbackStage {
    Copied,
    Sealed,
    Recipient,
}
impl ReadbackStage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Copied => "projection/copied-readback",
            Self::Sealed => "projection/sealed-readback",
            Self::Recipient => "recipient/readback",
        }
    }
}

fn live(deadline: Instant) -> Result<(), &'static str> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err("original-cutoff-exhausted")
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("String formatting");
    }
    text
}
fn units_hash(units: &[u16]) -> String {
    let mut hash = Sha256::new();
    for unit in units {
        hash.update(unit.to_le_bytes());
    }
    hex(&hash.finalize())
}
fn preview(units: &[u16]) -> Value {
    json!({"utf16_prefix":&units[..units.len().min(32)],"total_units":units.len(),"truncated":units.len()>32,"sha256":units_hash(units)})
}
fn root_hash(hash: &mut Sha256, root: &Root) {
    hash.update([root.tag()]);
    if let Root::TransportWinsock { service } = root {
        hash.update((service.len() as u64).to_le_bytes());
        for unit in service {
            hash.update(unit.to_le_bytes());
        }
    }
}
fn location(key: &Key) -> Value {
    let mut hash = Sha256::new();
    hash.update(b"registry-difference-key\0");
    root_hash(&mut hash, &key.root);
    hash.update((key.path.len() as u64).to_le_bytes());
    for component in &key.path {
        hash.update((component.len() as u64).to_le_bytes());
        for unit in component {
            hash.update(unit.to_le_bytes());
        }
    }
    let root = match &key.root {
        Root::Winsock2Parameters => json!({"kind":"winsock2-parameters"}),
        Root::WinsockParameters => json!({"kind":"winsock-parameters"}),
        Root::TransportWinsock { service } => {
            json!({"kind":"transport-winsock","service":preview(service)})
        }
    };
    json!({"root":root,"key_identity_sha256":hex(&hash.finalize()),"path_components":key.path.iter().take(4).map(|part|preview(part)).collect::<Vec<_>>(),"path_component_count":key.path.len(),"path_truncated":key.path.len()>4})
}
fn first_offset<T: PartialEq>(left: &[T], right: &[T]) -> Option<usize> {
    left.iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .or_else(|| (left.len() != right.len()).then_some(left.len().min(right.len())))
}
fn value_fact(value: &ValueRecord) -> Value {
    json!({"type":value.kind,"byte_length":value.bytes.len(),"sha256":hex(&Sha256::digest(&value.bytes))})
}
fn difference(
    expected: &Manifest,
    actual: &Manifest,
    deadline: Instant,
) -> Result<Option<Value>, &'static str> {
    live(deadline)?;
    let left = expected
        .transports
        .iter()
        .map(|item| (&item.service, item))
        .collect::<BTreeMap<_, _>>();
    let right = actual
        .transports
        .iter()
        .map(|item| (&item.service, item))
        .collect::<BTreeMap<_, _>>();
    for service in left
        .keys()
        .chain(right.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        live(deadline)?;
        match (left.get(service), right.get(service)) {
            (Some(left), Some(right)) if left.presence != right.presence => {
                return Ok(Some(
                    json!({"category":"transport-presence","service":preview(service),"expected":left.presence,"actual":right.presence}),
                ));
            }
            (Some(_), None) => {
                return Ok(Some(
                    json!({"category":"transport-missing","service":preview(service)}),
                ));
            }
            (None, Some(_)) => {
                return Ok(Some(
                    json!({"category":"transport-extra","service":preview(service)}),
                ));
            }
            _ => {}
        }
    }
    let left = expected
        .keys
        .iter()
        .map(|key| ((&key.root, &key.path), key))
        .collect::<BTreeMap<_, _>>();
    let right = actual
        .keys
        .iter()
        .map(|key| ((&key.root, &key.path), key))
        .collect::<BTreeMap<_, _>>();
    for identity in left
        .keys()
        .chain(right.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        live(deadline)?;
        let (left, right) = match (left.get(identity), right.get(identity)) {
            (Some(left), Some(right)) => (*left, *right),
            (Some(key), None) => {
                return Ok(Some(
                    json!({"category":"key-missing","location":location(key)}),
                ));
            }
            (None, Some(key)) => {
                return Ok(Some(
                    json!({"category":"key-extra","location":location(key)}),
                ));
            }
            _ => unreachable!("union contains a key"),
        };
        if left.class != right.class {
            return Ok(Some(
                json!({"category":"key-class","location":location(left),"expected_units":left.class.len(),"actual_units":right.class.len(),"expected_sha256":units_hash(&left.class),"actual_sha256":units_hash(&right.class),"first_unit_offset":first_offset(&left.class,&right.class)}),
            ));
        }
        let left_values = left
            .values
            .iter()
            .map(|value| (&value.name, value))
            .collect::<BTreeMap<_, _>>();
        let right_values = right
            .values
            .iter()
            .map(|value| (&value.name, value))
            .collect::<BTreeMap<_, _>>();
        for name in left_values
            .keys()
            .chain(right_values.keys())
            .collect::<std::collections::BTreeSet<_>>()
        {
            live(deadline)?;
            let (a, b) = match (left_values.get(name), right_values.get(name)) {
                (Some(a), Some(b)) => (*a, *b),
                (Some(_), None) => {
                    return Ok(Some(
                        json!({"category":"value-missing","location":location(left),"value_name":preview(name)}),
                    ));
                }
                (None, Some(_)) => {
                    return Ok(Some(
                        json!({"category":"value-extra","location":location(left),"value_name":preview(name)}),
                    ));
                }
                _ => unreachable!("union contains a value"),
            };
            let category = if a.kind != b.kind {
                Some("value-type")
            } else if a.bytes.len() != b.bytes.len() {
                Some("value-length")
            } else if a.bytes != b.bytes {
                Some("value-content")
            } else {
                None
            };
            if let Some(category) = category {
                let result = json!({"category":category,"location":location(left),"value_name":preview(name),"expected":value_fact(a),"actual":value_fact(b),"first_byte_offset":first_offset(&a.bytes,&b.bytes)});
                live(deadline)?;
                return Ok(Some(result));
            }
        }
    }
    live(deadline)?;
    Ok(None)
}
fn counts(manifest: &Manifest) -> Value {
    json!({"version":manifest.version,"view":manifest.view,"keys":manifest.keys.len(),"values":manifest.keys.iter().fold(0usize,|total,key|total.saturating_add(key.values.len())),"transports":manifest.transports.len()})
}
struct Capped(usize);
impl std::io::Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0 {
            return Err(std::io::Error::other("registry difference bound"));
        }
        self.0 -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn bounded(record: Value) -> Value {
    if serde_json::to_writer(Capped(RECORD_BYTES), &record).is_ok() {
        return record;
    }
    json!({"format":"memcordon.fixture-registry-difference","revision":1,"stage":record["stage"],"diagnostic_only":true,"acceptance_authority":false,"expected_declaration_sha256":record["expected_declaration_sha256"],"expected":record["expected"],"actual":record["actual"],"expected_payload_available":record["expected_payload_available"],"difference":{"category":record["difference"]["category"],"location_identity_sha256":record["difference"]["location"]["key_identity_sha256"],"value_name_sha256":record["difference"]["value_name"]["sha256"],"service_sha256":record["difference"]["service"]["sha256"]},"detail_truncated":true,"detail_unavailable":"serialized-bound"})
}

/// Compare only the owner's associated payload; a recipient has no expected
/// payload and continues to rely on the unchanged declaration digest check.
pub fn diagnostic(
    expected: Option<&Manifest>,
    actual: &Manifest,
    declaration: &Declaration,
    deadline: Instant,
    stage: ReadbackStage,
) -> Value {
    let mut record = json!({"format":"memcordon.fixture-registry-difference","revision":1,"stage":stage.label(),"diagnostic_only":true,"acceptance_authority":false,"expected_declaration_sha256":hex(&declaration.sha256),"declaration_version":declaration.version,"declaration_view":declaration.view,"expected":expected.map(counts),"actual":counts(actual),"expected_payload_available":false,"difference":null,"detail_truncated":false,"detail_unavailable":null});
    let result = (|| -> Result<(), &'static str> {
        live(deadline)?;
        declaration.validate().map_err(|_| "invalid-declaration")?;
        let actual_digest = actual.digest().map_err(|_| "invalid-actual-manifest")?;
        record["actual"]["sha256"] = json!(hex(&actual_digest));
        live(deadline)?;
        let Some(expected) = expected else {
            return Err("expected-payload-unavailable");
        };
        let expected_digest = expected.digest().map_err(|_| "invalid-expected-manifest")?;
        record["expected"]["sha256"] = json!(hex(&expected_digest));
        live(deadline)?;
        if expected_digest != declaration.sha256 || expected.view != declaration.view {
            return Err("expected-declaration-association-differs");
        }
        record["expected_payload_available"] = json!(true);
        record["difference"] = json!(difference(expected, actual, deadline)?);
        live(deadline)?;
        Ok(())
    })();
    if let Err(reason) = result {
        record["detail_unavailable"] = json!(reason);
    }
    bounded(record)
}
