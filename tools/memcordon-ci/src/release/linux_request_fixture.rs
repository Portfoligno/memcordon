//! Caller-side fixture preparation for the request-based installed product.
//! Packing uses the caller's actual OS account; it never installs image policy.
use super::source;
use crate::command::{CommandSpec, require_successful_output};
use crate::{CiError, Result};
use memcordon_core::workload_bundle::SnapshotManifestV1;
use memcordon_core::workload_request::{
    LinuxPrivateProfileV1, PrivateRootLayoutV1, RequirementRequestV1, RevisionOne,
    RuntimeRequestV1, SnapshotSelectionV1, WorkloadRequestFormat, WorkloadRequestV1,
};
use memcordon_core::{BoundedVec, identifiers::LogicalId};
use serde::Serialize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// An ordinary test actor established by the outer installation lifetime.
/// Its supplementary groups come from the existing OS account database.
#[derive(Clone)]
pub struct CallerSession {
    pub uid: u32,
    pub gid: u32,
    pub installed_cli: PathBuf,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PackMember<'a> {
    manifest: &'a Path,
    root: &'a Path,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PackSpec<'a> {
    runtime: PackMember<'a>,
    input: PackMember<'a>,
}

pub struct CallerSnapshot<'a> {
    pub manifest: &'a SnapshotManifestV1,
    pub manifest_path: &'a Path,
    pub source_root: &'a Path,
}

/// These are caller input files, not native attempt ownership or cleanup proof.
pub struct CallerRequestFixture {
    pub request: PathBuf,
    pub bundle: PathBuf,
    pub request_sha256: memcordon_core::DiagnosticSha256,
    #[cfg(target_os = "linux")]
    bundle_file: std::fs::File,
    #[cfg(target_os = "linux")]
    bundle_directory: std::fs::File,
    #[cfg(target_os = "linux")]
    bundle_uid: u32,
}

impl CallerSession {
    pub(super) fn command(&self, directory: &Path, cutoff: Instant) -> Result<CommandSpec> {
        if self.uid == 0 || self.gid == 0 || !self.installed_cli.is_absolute() {
            return Err(CiError::Message(
                "request fixture caller identity/path invalid".into(),
            ));
        }
        // setpriv reads the actor's real supplementary memberships. The fixture
        // does not add the provider socket group to compensate for denied access.
        Ok(
            CommandSpec::new("/usr/bin/setpriv", directory, Duration::from_secs(60))
                .bounded_until(cutoff)
                .cleared_environment()
                .arg("--reuid")
                .arg(self.uid.to_string())
                .arg("--regid")
                .arg(self.gid.to_string())
                .arg("--init-groups")
                .arg("--")
                .arg(&self.installed_cli),
        )
    }
}

impl CallerRequestFixture {
    #[cfg(target_os = "linux")]
    pub(super) fn bundle_identity(&self) -> Result<(u64, u64)> {
        let metadata = self.bundle_file.metadata().map_err(|error| {
            CiError::from(error).context(format!(
                "read held bundle identity {}",
                self.bundle.display()
            ))
        })?;
        Ok((metadata.dev(), metadata.ino()))
    }
    /// Caller-visible directory and sources belong to the outer fixture lease.
    /// The original operation cutoff is shared with subsequent launch/cleanup.
    #[expect(
        clippy::too_many_arguments,
        reason = "Actual caller, two input sources, request behavior and original cutoff stay explicit"
    )]
    pub fn pack(
        caller: &CallerSession,
        directory: &Path,
        runtime: CallerSnapshot<'_>,
        input: CallerSnapshot<'_>,
        entrypoint: LogicalId,
        layout: PrivateRootLayoutV1,
        requirements: BoundedVec<RequirementRequestV1, 64>,
        cutoff: Instant,
    ) -> Result<Self> {
        if Instant::now() >= cutoff || !directory.is_absolute() {
            return Err(CiError::Message(
                "request fixture original cutoff/path invalid".into(),
            ));
        }
        let command = caller.command(directory, cutoff)?;
        let directory_metadata = std::fs::symlink_metadata(directory).map_err(|error| {
            CiError::from(error).context(format!(
                "pack caller directory metadata {}",
                directory.display()
            ))
        })?;
        if !directory_metadata.is_dir() || directory_metadata.uid() != caller.uid {
            return Err(CiError::Message(
                "request fixture directory is not owned by its ordinary caller".into(),
            ));
        }
        let request = WorkloadRequestV1 {
            format: WorkloadRequestFormat::WorkloadRequest,
            revision: RevisionOne,
            runtime: RuntimeRequestV1::LinuxPrivate {
                profile: LinuxPrivateProfileV1::LinuxPrivateWorkload,
                inputs: SnapshotSelectionV1 {
                    runtime_digest: runtime.manifest.digest().map_err(CiError::Message)?,
                    input_digest: input.manifest.digest().map_err(CiError::Message)?,
                    entrypoint,
                },
                layout,
            },
            requirements,
        };
        request
            .validate()
            .map_err(|error| CiError::Message(error.to_string()))?;
        let request_sha256 = request
            .digest()
            .map_err(|error| CiError::Message(error.to_string()))?;
        let request_path = directory.join("workload-request.json");
        let bundle = directory.join("workload-inputs.mci");
        let spec_path = directory.join("workload-pack.json");
        // These contain caller paths only. The installed unprivileged packer
        // opens them after credential selection; the broker receives byte data.
        source::write_diagnostic_json(
            &spec_path,
            &PackSpec {
                runtime: PackMember {
                    manifest: runtime.manifest_path,
                    root: runtime.source_root,
                },
                input: PackMember {
                    manifest: input.manifest_path,
                    root: input.source_root,
                },
            },
        )
        .map_err(|error| {
            error.context(format!("write pack specification {}", spec_path.display()))
        })?;
        source::write_diagnostic_json(&request_path, &request).map_err(|error| {
            error.context(format!("write pack request {}", request_path.display()))
        })?;
        let observed = command
            .arg("workload")
            .arg("pack")
            .arg("--spec")
            .arg(&spec_path)
            .arg("--output")
            .arg(&bundle)
            .output()
            .map_err(|error| {
                error.context(format!(
                    "execute ordinary caller pack spec={} output={}",
                    spec_path.display(),
                    bundle.display()
                ))
            })?;
        require_successful_output("ordinary caller workload pack", &observed).map_err(|error| {
            error.context(format!(
                "ordinary caller pack returned status for {}",
                bundle.display()
            ))
        })?;
        #[cfg(target_os = "linux")]
        let (bundle_file, bundle_directory) = {
            use std::os::unix::fs::OpenOptionsExt;
            let bundle_file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&bundle)
                .map_err(|error| {
                    CiError::from(error).context(format!(
                        "open packed caller bundle nofollow {}",
                        bundle.display()
                    ))
                })?;
            let bundle_directory = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory)
                .map_err(|error| {
                    CiError::from(error).context(format!(
                        "open packed caller directory nofollow {}",
                        directory.display()
                    ))
                })?;
            let metadata = bundle_file.metadata().map_err(|error| {
                CiError::from(error).context(format!(
                    "read packed caller bundle metadata {}",
                    bundle.display()
                ))
            })?;
            if !metadata.is_file() || metadata.uid() != caller.uid || metadata.nlink() != 1 {
                return Err(
                    CiError::Message("packed caller bundle custody invalid".into()).context(
                        format!("validate packed caller bundle {}", bundle.display()),
                    ),
                );
            }
            (bundle_file, bundle_directory)
        };
        Ok(Self {
            request: request_path,
            bundle,
            request_sha256,
            #[cfg(target_os = "linux")]
            bundle_file,
            #[cfg(target_os = "linux")]
            bundle_directory,
            #[cfg(target_os = "linux")]
            bundle_uid: caller.uid,
        })
    }

    /// Only the launch supervisor can call this after its original Child and
    /// capture readers have actually settled.
    #[cfg(target_os = "linux")]
    pub(super) fn retire_bundle_exact(&self) -> Result<()> {
        let held = self.bundle_file.metadata().map_err(|error| {
            CiError::from(error).context(format!(
                "retire held caller bundle metadata {}",
                self.bundle.display()
            ))
        })?;
        let named = std::fs::File::from(
            rustix::fs::openat(
                &self.bundle_directory,
                "workload-inputs.mci",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .map_err(|error| {
                CiError::from(error).context(format!(
                    "retire caller bundle openat nofollow {}",
                    self.bundle.display()
                ))
            })?,
        )
        .metadata()
        .map_err(|error| {
            CiError::from(error).context(format!(
                "retire named caller bundle metadata {}",
                self.bundle.display()
            ))
        })?;
        if !held.is_file()
            || held.uid() != self.bundle_uid
            || held.nlink() != 1
            || named.dev() != held.dev()
            || named.ino() != held.ino()
            || named.uid() != self.bundle_uid
            || named.nlink() != 1
            || !named.is_file()
        {
            return Err(CiError::Message(
                "settled caller bundle identity changed; retaining named entry".into(),
            )
            .context(format!(
                "retire exact caller bundle {}",
                self.bundle.display()
            )));
        }
        rustix::fs::unlinkat(
            &self.bundle_directory,
            "workload-inputs.mci",
            rustix::fs::AtFlags::empty(),
        )
        .map_err(std::io::Error::from)
        .map_err(|error| {
            CiError::from(error).context(format!(
                "retire caller bundle unlinkat {}",
                self.bundle.display()
            ))
        })?;
        self.bundle_directory.sync_all().map_err(|error| {
            CiError::from(error).context(format!(
                "sync caller bundle directory after retirement {}",
                self.bundle.display()
            ))
        })?;
        Ok(())
    }
}
