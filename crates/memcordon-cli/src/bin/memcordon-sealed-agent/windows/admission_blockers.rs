//! Bounded filename observations, never admission or retirement authority.
use std::{ffi::OsString, io, time::Instant};

pub const MAX_ENTRIES: usize = 64;

#[derive(Debug, Default)]
pub struct Observation {
    pub launch_names: usize,
    pub reader_names: usize,
    pub writer_names: usize,
    pub unknown_names: usize,
    pub sampled: usize,
    pub truncated: bool,
    pub unavailable: Option<Unavailable>,
}

#[derive(Debug)]
pub enum Unavailable {
    OriginalCutoff,
    UnsafeRoot,
    Io {
        kind: io::ErrorKind,
        native_code: Option<i32>,
    },
}

impl From<io::Error> for Unavailable {
    fn from(error: io::Error) -> Self {
        Self::Io {
            kind: error.kind(),
            native_code: error.raw_os_error(),
        }
    }
}

impl Observation {
    pub fn unavailable(reason: Unavailable) -> Self {
        Self {
            unavailable: Some(reason),
            ..Self::default()
        }
    }

    pub fn detail(&self) -> String {
        let unavailable = match &self.unavailable {
            None => "none".to_owned(),
            Some(Unavailable::OriginalCutoff) => "original-cutoff".to_owned(),
            Some(Unavailable::UnsafeRoot) => "unsafe-root".to_owned(),
            Some(Unavailable::Io { kind, native_code }) => {
                format!("io-kind={kind:?},native-code={native_code:?}")
            }
        };
        format!(
            "filename-shape-only; record-binding=unavailable-before-exclusive-settlement; launch-names={}; reader-names={}; writer-names={}; unknown-names={}; sampled={}; truncated={}; unavailable={unavailable}",
            self.launch_names,
            self.reader_names,
            self.writer_names,
            self.unknown_names,
            self.sampled,
            self.truncated
        )
    }
}

pub fn observe_names(
    entries: impl IntoIterator<Item = io::Result<OsString>>,
    cutoff: Instant,
) -> Observation {
    let mut observed = Observation::default();
    let identity_length = String::from(memcordon_core::hash_bytes(&[])).len();
    let mut entries = entries.into_iter();
    while observed.sampled < MAX_ENTRIES {
        if Instant::now() >= cutoff {
            observed.unavailable = Some(Unavailable::OriginalCutoff);
            return observed;
        }
        let name = match entries.next() {
            None => return observed,
            Some(Ok(name)) => name,
            Some(Err(error)) => {
                observed.unavailable = Some(error.into());
                return observed;
            }
        };
        observed.sampled += 1;
        let classified = name.to_str().and_then(|name| {
            let (identity, kind) = if let Some(identity) = name.strip_suffix(".writer.json") {
                (identity, 2)
            } else if let Some(identity) = name.strip_suffix(".reader.json") {
                (identity, 1)
            } else {
                (name.strip_suffix(".json")?, 0)
            };
            (identity.len() == identity_length
                && identity
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
            .then_some(kind)
        });
        match classified {
            Some(0) => observed.launch_names += 1,
            Some(1) => observed.reader_names += 1,
            Some(2) => observed.writer_names += 1,
            _ => observed.unknown_names += 1,
        }
    }
    // Conservative cap: never enumerate an extra entry just to prove completion.
    observed.truncated = true;
    observed
}
