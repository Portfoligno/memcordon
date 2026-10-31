//! Pure admission and event rules for fixed native namespace roots.
use crate::{CiError, Result};

pub const RAW_EVENT_LIMIT: usize = 16384;
pub const RELEVANT_EVENT_LIMIT: usize = 4096;
// Linux inotify UAPI values stay fixed when these pure rules run on another host.
pub const INVALIDATION: u32 = 0x400 | 0x800 | 0x2000 | 0x8000;
pub const OVERFLOW: u32 = 0x4000;

#[derive(Clone, Debug)]
pub struct Subscription {
    pub watch: i32,
    pub role: String,
    pub basename: Option<Vec<u8>>,
}

pub fn classify<'a>(
    subscriptions: &'a [Subscription],
    watch: i32,
    mask: u32,
    name: &[u8],
) -> Result<Vec<&'a str>> {
    if mask & (INVALIDATION | OVERFLOW) != 0 {
        return Err(CiError::Message(
            "native namespace watch invalidated or overflowed".into(),
        ));
    }
    let changes = 0x100 | 0x200 | 0x40 | 0x80;
    if mask & changes == 0 || mask & !(changes | 0x40000000) != 0 {
        return Err(CiError::Message(
            "native namespace event mask is unknown".into(),
        ));
    }
    let mut known = false;
    let mut roles = Vec::new();
    for subscription in subscriptions
        .iter()
        .filter(|subscription| subscription.watch == watch)
    {
        known = true;
        let relevant = match &subscription.basename {
            Some(basename) => basename == name,
            None => subscription.role != "root-staging" || name.starts_with(b"private-root-"),
        };
        if relevant {
            roles.push(subscription.role.as_str());
        }
    }
    if !known {
        return Err(CiError::Message(
            "native namespace event belongs to another watch".into(),
        ));
    }
    Ok(roles)
}

pub fn require_same_identity(
    before: Option<(u64, u64, u32, u32)>,
    after: Option<(u64, u64, u32, u32)>,
) -> Result<()> {
    if before != after {
        return Err(CiError::Message(
            "native namespace named identity or presence changed".into(),
        ));
    }
    Ok(())
}

pub fn check_event_bounds(raw: usize, retained: usize) -> Result<()> {
    if raw > RAW_EVENT_LIMIT || retained > RELEVANT_EVENT_LIMIT {
        return Err(CiError::Message(
            "native namespace event inventory exceeds bound".into(),
        ));
    }
    Ok(())
}
