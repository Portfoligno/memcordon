//! Exact semantic input for the fixture-owned native Winsock registry subtree.
//! A digest describes data; native held-key custody supplies the capability.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const VERSION: u32 = 1;
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
    /// Components relative to the fixed WinSock2 Parameters subtree; root is [].
    pub path: Vec<Vec<u16>>,
    pub class: Vec<u16>,
    pub values: Vec<ValueRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub view: View,
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
        for key in &self.keys {
            if key.path.len() > MAX_DEPTH || !paths.insert(key.path.clone()) {
                return Err("Winsock registry key depth/uniqueness differs".into());
            }
            if key.class.len() > 255 || key.class.contains(&0) {
                return Err(
                    "Winsock registry key class is not bounded lossless native UTF16".into(),
                );
            }
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
        if !paths.contains(&Vec::<Vec<u16>>::new()) {
            return Err("Winsock registry subtree root is absent".into());
        }
        for path in &paths {
            if !path.is_empty() && !paths.contains(&path[..path.len() - 1]) {
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
        let mut keys: Vec<_> = self.keys.iter().collect();
        keys.sort_by(|left, right| left.path.cmp(&right.path));
        hash.update((keys.len() as u32).to_le_bytes());
        for key in keys {
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
