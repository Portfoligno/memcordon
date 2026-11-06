//! Separate catalog preparation child; never initializes either original workload.
use crate::windows_provider_projection_record::CatalogSnapshot;
#[cfg(windows)]
use memcordon_platform::windows_provider_catalog_protocol::Transfer;
pub use memcordon_platform::windows_provider_catalog_protocol::{Ready, Spec};
use serde::{Deserialize, Serialize};
use std::io;

pub const FRAME_BYTES: usize = memcordon_platform::windows_provider_catalog_protocol::FRAME_BYTES;

#[derive(Debug)]
pub struct HelperFailure {
    pub primary: io::Error,
    pub secondary: io::Error,
}
impl std::fmt::Display for HelperFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; owned helper retirement/publication: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for HelperFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
pub fn preserve<T, U>(primary: io::Result<T>, secondary: io::Result<U>) -> io::Result<(T, U)> {
    match (primary, secondary) {
        (Ok(value), Ok(other)) => Ok((value, other)),
        (Err(primary), Err(secondary)) => Err(io::Error::new(
            primary.kind(),
            HelperFailure { primary, secondary },
        )),
        (Err(primary), Ok(_)) => Err(primary),
        (Ok(_), Err(secondary)) => Err(secondary),
    }
}

pub fn digest(value: &impl Serialize) -> io::Result<String> {
    memcordon_platform::windows_provider_catalog_protocol::digest(value)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u32,
    pid: u32,
    birth: u64,
    spec_sha256: String,
    snapshot: CatalogSnapshot,
}

pub fn frames(bytes: &[u8]) -> io::Result<Vec<serde_json::Value>> {
    if bytes.len() > FRAME_BYTES || bytes.last() != Some(&b'\n') {
        return Err(io::Error::other(
            "catalog protocol is truncated or exceeds finite bound",
        ));
    }
    let mut result = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(io::Error::other("catalog protocol has empty frames"));
        }
        if result.len() == 2 {
            return Err(io::Error::other("catalog protocol has extra frames"));
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(line)
            .map_err(io::Error::other)?;
        result.push(serde_json::from_slice(line).map_err(io::Error::other)?);
    }
    Ok(result)
}

pub fn checked_ready(value: serde_json::Value, spec: &Spec, pid: u32) -> io::Result<Ready> {
    spec.validate()?;
    let ready: Ready = serde_json::from_value(value).map_err(io::Error::other)?;
    if ready.version != 1
        || pid == 0
        || ready.pid != pid
        || ready.birth == 0
        || ready.spec_sha256 != digest(spec)?
    {
        return Err(io::Error::other(
            "catalog readiness differs from owned process or exact input",
        ));
    }
    Ok(ready)
}

pub fn checked_response(
    bytes: &[u8],
    spec: &Spec,
    pid: u32,
    birth: u64,
) -> io::Result<CatalogSnapshot> {
    let observed = frames(bytes)?;
    if observed.len() != 2 {
        return Err(io::Error::other("catalog final protocol is incomplete"));
    }
    let ready = checked_ready(observed[0].clone(), spec, pid)?;
    let response: Response =
        serde_json::from_value(observed[1].clone()).map_err(io::Error::other)?;
    if response.version != 1
        || birth == 0
        || response.pid != pid
        || response.birth != birth
        || ready.birth != birth
        || response.spec_sha256 != digest(spec)?
        || response.snapshot.declaration_sha256 != spec.declaration_sha256
    {
        return Err(io::Error::other(
            "catalog final observation differs from original held helper/capability",
        ));
    }
    crate::windows_provider_projection_record::select(&response.snapshot, &spec.declaration_sha256)
        .map_err(io::Error::other)?;
    Ok(response.snapshot)
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        io::Write,
        path::Path,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    fn live(work: Instant) -> io::Result<()> {
        if Instant::now() >= work {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original catalog work cutoff expired",
            ))
        } else {
            Ok(())
        }
    }
    pub fn child() -> io::Result<()> {
        memcordon_platform::test_support::windows_provider_catalog::child_stdio()
    }

    pub fn collect(
        projection: Arc<Mutex<memcordon_testkit::WindowsWinsockRegistryProjection>>,
        challenge_sha256: String,
        work: Instant,
        cleanup: Instant,
    ) -> io::Result<CatalogSnapshot> {
        live(work)?;
        let declaration = projection
            .lock()
            .map_err(|_| io::Error::other("catalog projection owner poisoned"))?
            .declaration()
            .clone();
        let (cutoff_qpc, frequency) = memcordon_testkit::windows_native_work_cutoff(work)?;
        let spec = Spec {
            version: 1,
            declaration_sha256: digest(&declaration)?,
            declaration,
            challenge_sha256,
            cutoff_qpc,
            frequency,
        };
        spec.validate()?;
        let expected = digest(&spec)?;
        let image = std::env::current_exe()?;
        let mut command = std::process::Command::new(&image);
        command
            .arg("provider-catalog-preparation")
            .stdin(std::process::Stdio::piped());
        let retained = Arc::new(Mutex::new(None::<memcordon_testkit::WindowsImageProcess>));
        let callback_retained = Arc::clone(&retained);
        let callback_projection = Arc::clone(&projection);
        let callback_spec = spec.clone();
        let callback_expected = expected.clone();
        let output = memcordon_testkit::run_until_owned_spawn_with_io_controlled_output_limit(
            command,
            cleanup,
            FRAME_BYTES,
            None,
            |mut command| command.spawn(),
            move |pid, input, snapshot| {
                let mut input =
                    input.ok_or_else(|| io::Error::other("catalog helper stdin absent"))?;
                let mut bytes = serde_json::to_vec(&callback_spec).map_err(io::Error::other)?;
                bytes.push(b'\n');
                input.write_all(&bytes)?;
                let ready = loop {
                    live(work)?;
                    let bytes = snapshot.stdout()?;
                    if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                        let observed = frames(&bytes[..=end])?;
                        let ready = checked_ready(observed[0].clone(), &callback_spec, pid)?;
                        break ready;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                if ready.version != 1 || ready.pid != pid || ready.spec_sha256 != callback_expected
                {
                    return Err(io::Error::other("catalog readiness is foreign"));
                }
                let candidate = memcordon_testkit::windows_fixture_input_candidate_for_image_until(
                    Path::new(&image),
                    pid,
                    work,
                )?;
                let memcordon_testkit::WindowsProcessCandidate::Held(held) = candidate else {
                    return Err(io::Error::other("catalog owned helper unavailable"));
                };
                if held.identity.birth != u128::from(ready.birth) {
                    return Err(io::Error::other("catalog helper birth differs"));
                }
                let mut held_owner = callback_retained
                    .lock()
                    .map_err(|_| io::Error::other("catalog retained helper poisoned"))?;
                *held_owner = Some(held);
                let handle = callback_projection
                    .lock()
                    .map_err(|_| io::Error::other("catalog projection owner poisoned"))?
                    .duplicate_into(held_owner.as_ref().expect("stored original helper"), work)?;
                drop(held_owner);
                let mut bytes = serde_json::to_vec(&Transfer {
                    version: 1,
                    spec_sha256: callback_expected,
                    handle,
                })
                .map_err(io::Error::other)?;
                bytes.push(b'\n');
                input.write_all(&bytes)?;
                drop(input);
                Ok(())
            },
        );
        let output = output.map_err(io::Error::other).and_then(|output| {
            if !output.status.success() || !output.stderr.is_empty() {
                return Err(io::Error::other("catalog preparation helper failed"));
            }
            let observed = frames(&output.stdout)?;
            if observed.len() != 2 {
                return Err(io::Error::other("catalog final protocol incomplete"));
            }
            let _: Ready = serde_json::from_value(observed[0].clone()).map_err(io::Error::other)?;
            let _: Response =
                serde_json::from_value(observed[1].clone()).map_err(io::Error::other)?;
            Ok(output)
        });
        let retirement = (|| -> io::Result<_> {
            let held = retained
                .lock()
                .map_err(|_| io::Error::other("catalog retained helper poisoned"))?;
            let held = held
                .as_ref()
                .ok_or_else(|| io::Error::other("catalog helper original handle absent"))?;
            if !held.has_exited()? {
                return Err(io::Error::other(
                    "catalog helper retirement unproved; sealed input retained",
                ));
            }
            projection
                .lock()
                .map_err(|_| io::Error::other("catalog projection owner poisoned"))?
                .recipients_retired();
            Ok(held.identity)
        })();
        let (output, identity) = preserve(output, retirement)?;
        let response = checked_response(
            &output.stdout,
            &spec,
            identity.pid,
            u64::try_from(identity.birth).map_err(io::Error::other)?,
        )?;
        live(work)?;
        Ok(response)
    }
}

#[cfg(windows)]
pub use native::{child, collect};
