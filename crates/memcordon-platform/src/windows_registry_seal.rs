//! Exact read-only trustee policy for the newly owned fixture registry input.
use std::collections::BTreeSet;

const KEY_READ: u32 = 0x0002_0019;
const OWNER_RIGHTS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const RESTRICTED_CODE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0];
const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

pub fn validate_sid(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
        return Err("registry seal SID header invalid".into());
    }
    let expected = 8 + usize::from(bytes[1]) * 4;
    if bytes.len() != expected {
        return Err(format!(
            "registry seal SID extent differs: actual={}; expected={expected}",
            bytes.len()
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ReadAce {
    pub kind: u8,
    pub flags: u8,
    pub mask: u32,
    pub sid: Vec<u8>,
}

pub fn read_trustees(user: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    validate_sid(user)?;
    Ok([user, &OWNER_RIGHTS, &RESTRICTED_CODE, &SYSTEM]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub fn validate_read_acl(user: &[u8], aces: &[ReadAce]) -> Result<(), String> {
    let trustees = read_trustees(user)?;
    let expected = trustees.iter().map(Vec::as_slice).collect::<BTreeSet<_>>();
    if aces.len() != expected.len() {
        return Err(format!(
            "registry seal trustee count differs: actual={}; expected={}",
            aces.len(),
            expected.len()
        ));
    }
    let mut observed = BTreeSet::new();
    for (index, ace) in aces.iter().enumerate() {
        validate_sid(&ace.sid)?;
        if ace.kind != 0 || ace.flags != 0 || ace.mask != KEY_READ {
            return Err(format!(
                "registry seal ACE differs: index={index}; kind={}; flags={}; mask={:#010x}; expected-mask={KEY_READ:#010x}",
                ace.kind, ace.flags, ace.mask
            ));
        }
        if !expected.contains(ace.sid.as_slice()) || !observed.insert(ace.sid.as_slice()) {
            return Err(format!(
                "registry seal unexpected or duplicate trustee: index={index}"
            ));
        }
    }
    if observed != expected {
        return Err("registry seal required read trustee missing".into());
    }
    Ok(())
}
