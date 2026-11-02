//! Canonical semantic input for the fixture-owned native Winsock registry forest.
//! A digest describes data; native held-key custody supplies the capability.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const VERSION: u32 = 4;
pub const MAX_KEYS: usize = 256;
pub const MAX_DEPTH: usize = 16;
pub const MAX_VALUES: usize = 4096;
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum View {
    Native,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Root {
    Winsock2Parameters,
    WinsockParameters,
    TransportWinsock { service: Vec<u16> },
    WinsockMigrationProviders,
}
impl Root {
    pub const ALL: [Self; 2] = [Self::Winsock2Parameters, Self::WinsockParameters];

    pub fn path(&self) -> Vec<u16> {
        match self {
            Self::Winsock2Parameters => "System\\CurrentControlSet\\Services\\WinSock2\\Parameters"
                .encode_utf16()
                .collect(),
            Self::WinsockParameters => "System\\CurrentControlSet\\Services\\Winsock\\Parameters"
                .encode_utf16()
                .collect(),
            Self::TransportWinsock { service } => {
                let mut path = "System\\CurrentControlSet\\Services\\"
                    .encode_utf16()
                    .collect::<Vec<_>>();
                path.extend(service);
                path.extend("\\Parameters\\Winsock".encode_utf16());
                path
            }
            Self::WinsockMigrationProviders => {
                "System\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers"
                    .encode_utf16()
                    .collect()
            }
        }
    }

    pub const fn tag(&self) -> u8 {
        match self {
            Self::Winsock2Parameters => 1,
            Self::WinsockParameters => 2,
            Self::TransportWinsock { .. } => 3,
            Self::WinsockMigrationProviders => 4,
        }
    }

    pub fn identity_bytes(&self) -> usize {
        match self {
            Self::TransportWinsock { service } => 1 + 4 + service.len() * 2,
            _ => 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum TransportPresence {
    Present,
    Absent { lstatus: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportRoot {
    pub service: Vec<u16>,
    pub presence: TransportPresence,
}
impl TransportRoot {
    pub fn extent_bytes(&self) -> usize {
        // Root tag, native-name length/units, presence tag and fixed status slot.
        1 + 4 + self.service.len() * 2 + 1 + 4
    }
}

fn service_component(service: &[u16]) -> Result<(), String> {
    if service.is_empty()
        || service.len() > 255
        || service.iter().any(|unit| matches!(*unit, 0 | 0x5c | 0x2f))
    {
        return Err("transport service is not one bounded native component".into());
    }
    Ok(())
}

/// Parse exact native REG_MULTI_SZ bytes; zero-only trailing padding is allowed
/// and remains in the original ValueRecord rather than being repaired away.
pub fn parse_transports(value: &ValueRecord) -> Result<Vec<Vec<u16>>, String> {
    if value.kind != 7
        || value.bytes.is_empty()
        || value.bytes.len() > MAX_VALUE_BYTES
        || value.bytes.len() % 2 != 0
    {
        return Err("Transports is not bounded native REG_MULTI_SZ".into());
    }
    let units = value
        .bytes
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    let mut services = BTreeSet::new();
    let mut start = 0;
    loop {
        let end = units[start..]
            .iter()
            .position(|unit| *unit == 0)
            .map(|length| start + length)
            .ok_or("Transports string terminator absent")?;
        if end == start {
            if units[start..].iter().any(|unit| *unit != 0) {
                return Err("Transports has nonzero data after its terminal empty string".into());
            }
            break;
        }
        let service = &units[start..end];
        service_component(service)?;
        services.insert(service.to_vec());
        if services.len() > MAX_KEYS - Root::ALL.len() - 1 {
            return Err("transport root inventory exceeds shared key bound".into());
        }
        start = end + 1;
        if start == units.len() {
            return Err("Transports terminal empty string absent".into());
        }
    }
    Ok(services.into_iter().collect())
}

pub fn transport_services(keys: &[Key]) -> Result<Vec<Vec<u16>>, String> {
    let mut roots = keys
        .iter()
        .filter(|key| key.root == Root::WinsockParameters && key.path.is_empty());
    let root = roots
        .next()
        .ok_or("Winsock Parameters discovery root absent")?;
    if roots.next().is_some() {
        return Err("Winsock Parameters discovery root duplicated".into());
    }
    let expected = "Transports".encode_utf16().collect::<Vec<_>>();
    let mut values = root.values.iter().filter(|value| {
        value.name.len() == expected.len()
            && value.name.iter().zip(&expected).all(|(actual, expected)| {
                u8::try_from(*actual)
                    .ok()
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(&(*expected as u8)))
            })
    });
    let value = values
        .next()
        .ok_or("actual Transports discovery value absent")?;
    if values.next().is_some() {
        return Err("Transports discovery value name is ambiguous".into());
    }
    parse_transports(value)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub version: u32,
    pub view: View,
    pub sha256: [u8; 32],
}
impl Declaration {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err("unsupported Winsock registry dependency version".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueRecord {
    pub name: Vec<u16>,
    pub kind: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub root: Root,
    /// Components relative to this fixed root; its own root is [].
    pub path: Vec<Vec<u16>>,
    pub class: Vec<u16>,
    pub values: Vec<ValueRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub view: View,
    pub migration_providers: TransportPresence,
    pub transports: Vec<TransportRoot>,
    pub keys: Vec<Key>,
}
impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION || self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err("Winsock registry manifest version/key bound differs".into());
        }
        let mut paths = BTreeSet::new();
        let mut total = 0usize;
        let mut values = 0usize;
        let mut charge = |bytes: usize| -> Result<(), String> {
            total = total.checked_add(bytes).ok_or("registry extent overflow")?;
            if total > MAX_TOTAL_BYTES {
                return Err("Winsock registry aggregate input exceeds bound".into());
            }
            Ok(())
        };
        let services = transport_services(&self.keys)?;
        if self.transports.len() != services.len() {
            return Err("transport presence inventory differs from captured Transports".into());
        }
        let mut present = BTreeSet::new();
        let mut inventory = BTreeSet::new();
        charge(6)?; // Fixed optional-root tag, presence and native-status slot.
        let mut absent = match self.migration_providers {
            TransportPresence::Present => 0,
            TransportPresence::Absent { lstatus: 2 } => 1,
            TransportPresence::Absent { .. } => {
                return Err("unsupported migration provider source absence status".into());
            }
        };
        for transport in &self.transports {
            service_component(&transport.service)?;
            if !inventory.insert(transport.service.clone())
                || services.binary_search(&transport.service).is_err()
            {
                return Err("transport presence identity is duplicated or unlisted".into());
            }
            match transport.presence {
                TransportPresence::Present => {
                    present.insert(transport.service.clone());
                }
                TransportPresence::Absent { lstatus: 2 } => {
                    absent += 1;
                }
                TransportPresence::Absent { .. } => {
                    return Err("unsupported transport source absence status".into());
                }
            }
            charge(transport.extent_bytes())?;
        }
        if self
            .keys
            .len()
            .checked_add(absent)
            .is_none_or(|count| count > MAX_KEYS)
        {
            return Err("keys and absent transport roots exceed shared inventory bound".into());
        }
        for key in &self.keys {
            if key.root == Root::WinsockMigrationProviders
                && self.migration_providers != TransportPresence::Present
            {
                return Err("key belongs to absent migration provider root".into());
            }
            if let Root::TransportWinsock { service } = &key.root {
                service_component(service)?;
                if !present.contains(service) {
                    return Err("key belongs to absent or unlisted transport".into());
                }
            }
            if key.path.len() > MAX_DEPTH || !paths.insert((key.root.clone(), key.path.clone())) {
                return Err("Winsock registry key depth/uniqueness differs".into());
            }
            if key.class.len() > 255 || key.class.contains(&0) {
                return Err(
                    "Winsock registry key class is not bounded lossless native UTF16".into(),
                );
            }
            charge(key.root.identity_bytes())?;
            charge(key.class.len() * 2)?;
            for component in &key.path {
                if component.is_empty()
                    || component.len() > 255
                    || component.iter().any(|unit| matches!(*unit, 0 | 0x5c))
                {
                    return Err("Winsock registry key component is not bounded native UTF16".into());
                }
                charge(component.len() * 2)?;
            }
            values = values
                .checked_add(key.values.len())
                .ok_or("registry value count overflow")?;
            if values > MAX_VALUES {
                return Err("Winsock registry value count exceeds bound".into());
            }
            let mut names = BTreeSet::new();
            for value in &key.values {
                // Empty names are the actual default value. Data remains exact
                // bytes even for string-like types: no terminator repair occurs.
                if value.name.len() > 16383
                    || value.name.contains(&0)
                    || !names.insert(value.name.clone())
                    || value.kind > 11
                    || value.bytes.len() > MAX_VALUE_BYTES
                {
                    return Err("Winsock registry value name/type/extent differs".into());
                }
                charge(value.name.len() * 2)?;
                charge(value.bytes.len())?;
            }
        }
        for root in Root::ALL {
            if !paths.contains(&(root, Vec::new())) {
                return Err("Winsock registry required forest root is absent".into());
            }
        }
        if self.migration_providers == TransportPresence::Present
            && !paths.contains(&(Root::WinsockMigrationProviders, Vec::new()))
        {
            return Err("present migration provider root is absent from captured keys".into());
        }
        for service in present {
            if !paths.contains(&(Root::TransportWinsock { service }, Vec::new())) {
                return Err("present transport root is absent from captured keys".into());
            }
        }
        for (root, path) in &paths {
            if !path.is_empty() && !paths.contains(&(root.clone(), path[..path.len() - 1].to_vec()))
            {
                return Err("Winsock registry key lacks its captured parent".into());
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        use sha2::{Digest, Sha256};
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"memcordon.fixture.native-winsock-registry\0");
        hash.update(self.version.to_le_bytes());
        // The only accepted view is the actual native process view.
        hash.update([1]);
        hash.update([4]);
        match self.migration_providers {
            TransportPresence::Present => {
                hash.update([1]);
                hash.update(0u32.to_le_bytes());
            }
            TransportPresence::Absent { lstatus } => {
                hash.update([2]);
                hash.update(lstatus.to_le_bytes());
            }
        }
        let mut transports: Vec<_> = self.transports.iter().collect();
        transports.sort_by(|left, right| left.service.cmp(&right.service));
        hash.update((transports.len() as u32).to_le_bytes());
        for transport in transports {
            hash.update([3]);
            hash.update((transport.service.len() as u32).to_le_bytes());
            for unit in &transport.service {
                hash.update(unit.to_le_bytes());
            }
            match transport.presence {
                TransportPresence::Present => {
                    hash.update([1]);
                    hash.update(0u32.to_le_bytes());
                }
                TransportPresence::Absent { lstatus } => {
                    hash.update([2]);
                    hash.update(lstatus.to_le_bytes());
                }
            }
        }
        let mut keys: Vec<_> = self.keys.iter().collect();
        keys.sort_by(|left, right| {
            left.root
                .tag()
                .cmp(&right.root.tag())
                .then_with(|| left.root.cmp(&right.root))
                .then_with(|| left.path.cmp(&right.path))
        });
        hash.update((keys.len() as u32).to_le_bytes());
        for key in keys {
            hash.update([key.root.tag()]);
            if let Root::TransportWinsock { service } = &key.root {
                hash.update((service.len() as u32).to_le_bytes());
                for unit in service {
                    hash.update(unit.to_le_bytes());
                }
            }
            hash.update((key.path.len() as u32).to_le_bytes());
            for component in &key.path {
                hash.update((component.len() as u32).to_le_bytes());
                for unit in component {
                    hash.update(unit.to_le_bytes());
                }
            }
            hash.update((key.class.len() as u32).to_le_bytes());
            for unit in &key.class {
                hash.update(unit.to_le_bytes());
            }
            let mut values: Vec<_> = key.values.iter().collect();
            values.sort_by(|left, right| left.name.cmp(&right.name));
            hash.update((values.len() as u32).to_le_bytes());
            for value in values {
                hash.update((value.name.len() as u32).to_le_bytes());
                for unit in &value.name {
                    hash.update(unit.to_le_bytes());
                }
                hash.update(value.kind.to_le_bytes());
                hash.update((value.bytes.len() as u32).to_le_bytes());
                hash.update(&value.bytes);
            }
        }
        Ok(hash.finalize().into())
    }

    pub fn declaration(&self) -> Result<Declaration, String> {
        Ok(Declaration {
            version: VERSION,
            view: self.view,
            sha256: self.digest()?,
        })
    }
}
