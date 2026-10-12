//! Original host file canaries for concrete private-root escape probes.
#![cfg(target_os = "linux")]
use crate::{CiError, Result};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub fn host_nonloopback_ipv4() -> Result<std::net::Ipv4Addr> {
    memcordon_platform::test_support::native_nonloopback_ipv4().map_err(Into::into)
}

fn capture_import_source_inventory(
    definition: &memcordon_core::workload_registry_v3::RuntimeImageDefinitionV1,
    source: &Path,
    extra: Option<&str>,
    custody: &mut Vec<File>,
) -> Result<serde_json::Value> {
    use std::io::Read;
    let mut paths = definition
        .entries
        .as_slice()
        .iter()
        .map(|entry| entry.path().as_str())
        .collect::<Vec<_>>();
    if let Some(extra) = extra {
        paths.push(extra);
    }
    let mut members = Vec::new();
    for relative in paths {
        let path = source.join(relative);
        let held = File::from(
            rustix::fs::open(
                &path,
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let native = held.metadata()?;
        let hash = if native.is_file() {
            let mut reader = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let stamp = reader.metadata()?;
            if (stamp.dev(), stamp.ino()) != (native.dev(), native.ino())
                || stamp.len() > 4 * 1024 * 1024
            {
                return Err(CiError::Message(
                    "isolation source inventory original file differs or exceeds bound".into(),
                ));
            }
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut reader)
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            let after = reader.metadata()?;
            if bytes.len() as u64 != stamp.len()
                || (
                    after.dev(),
                    after.ino(),
                    after.len(),
                    after.ctime(),
                    after.ctime_nsec(),
                    after.uid(),
                    after.gid(),
                    after.mode(),
                    after.nlink(),
                ) != (
                    stamp.dev(),
                    stamp.ino(),
                    stamp.len(),
                    stamp.ctime(),
                    stamp.ctime_nsec(),
                    stamp.uid(),
                    stamp.gid(),
                    stamp.mode(),
                    stamp.nlink(),
                )
            {
                return Err(CiError::Message(
                    "isolation input member mutated during native inventory".into(),
                ));
            }
            custody.push(reader);
            Some(super::artifacts::checksum(&bytes))
        } else {
            None
        };
        let named = std::fs::symlink_metadata(&path)?;
        if (named.dev(), named.ino(), named.mode()) != (native.dev(), native.ino(), native.mode()) {
            return Err(CiError::Message(
                "isolation input inventory pathname reassociated".into(),
            ));
        }
        members.push(serde_json::json!({"path":relative,"device":native.dev(),"inode":native.ino(),"uid":native.uid(),"gid":native.gid(),"mode":native.mode(),"nlink":native.nlink(),"length":native.len(),"sha256":hash}));
        custody.push(held);
    }
    let root = std::fs::symlink_metadata(source)?;
    Ok(
        serde_json::json!({"format":"memcordon.linux-isolation-import-inventory","revision":1,"source_root":source,
        "root":{"device":root.dev(),"inode":root.ino(),"uid":root.uid(),"gid":root.gid(),"mode":root.mode()},"members":members}),
    )
}

#[derive(Default)]
pub struct ImportRefusalReport {
    pub files: Vec<File>,
    pub processes: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub artifacts: Vec<PathBuf>,
    source: Option<ImportSourceOwner>,
    closure_complete: bool,
    pub definition: Option<(
        memcordon_core::workload_registry_v3::RuntimeImageDefinitionV1,
        PathBuf,
    )>,
}
struct ImportSourceOwner {
    root: File,
    parent: File,
    name: std::ffi::OsString,
    socket: Option<std::os::unix::net::UnixListener>,
    socket_parent: Option<File>,
    socket_name: Option<std::ffi::OsString>,
    socket_identity: Option<(u64, u64)>,
    original: serde_json::Value,
    directory: PathBuf,
}
impl ImportRefusalReport {
    #[expect(
        clippy::too_many_arguments,
        reason = "Import refusal proof binds installed images, account, policy, original lease, and acquisition independently"
    )]
    pub fn run(
        &mut self,
        input: &super::linux_mixed_installed::InstalledMixedDriverInput<'_>,
        images: &super::linux_mixed_installed::MixedImages,
        account: &crate::consumer_readiness_ledger::ExclusiveAccount,
        policy: &super::linux_mixed_installed::ActivatedMixedPolicy,
        directory: &Path,
        scenario: &str,
        challenge: &str,
    ) -> Result<(
        memcordon_core::workload_registry_v3::RuntimeImageDefinitionV1,
        PathBuf,
    )> {
        use memcordon_core::workload_registry_v3::ImageEntryV1;
        if self.source.is_some()
            || !["input-socket", "imported-socket", "caller-writable-tree"].contains(&scenario)
        {
            return Err(CiError::Message(
                "isolation source import recipe differs/reused".into(),
            ));
        }
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o711))?;
        let source = directory.join("isolation-input-source");
        let protected = input.admin_root.join(format!(
            "isolation-input-{}",
            directory
                .file_name()
                .ok_or_else(|| CiError::Message(
                    "isolation import original recipe basename absent".into()
                ))?
                .to_string_lossy()
        ));
        std::fs::create_dir(&protected)?;
        let mut definition = images.input.clone();
        definition.image_id = memcordon_core::workload_contract::LogicalId::new(format!(
            "isolation-{}-{}",
            scenario,
            directory
                .file_name()
                .expect("validated recipe name")
                .to_string_lossy()
        ))
        .map_err(CiError::Message)?;
        let definition_path = protected.join("definition.json");
        let definition_bytes = serde_json::to_vec(&definition)?;
        super::linux_mixed_installed::retain(&definition_path, &definition_bytes)?;
        self.definition = Some((definition.clone(), definition_path.clone()));
        let probe_bytes =
            hex::decode(challenge).map_err(|error| CiError::Message(error.to_string()))?;
        if probe_bytes.len() != 32 || hex::encode(&probe_bytes) != challenge {
            return Err(CiError::Message(
                "isolation original probe challenge differs".into(),
            ));
        }
        super::linux_mixed_installed::retain(
            &directory.join("isolation-import-challenge.bin"),
            &probe_bytes,
        )?;
        super::linux_mixed_installed::retain(
            &directory.join("isolation-import-intent.json"),
            &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-isolation-import-intent","revision":1,"identity":input.identity,"cell":input.cell,"lease_id":input.lease_id,"scenario":scenario,
            "definition":definition_path,"definition_sha256":super::artifacts::checksum(&definition_bytes),"reference":definition.reference().map_err(CiError::Message)?,"source_root":source,
            "work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis}))?,
        )?;
        std::fs::create_dir(&source)?;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700))?;
        for entry in definition.entries.as_slice() {
            match entry {
                ImageEntryV1::Regular {
                    path,
                    sha256,
                    size,
                    executable,
                } => {
                    let bytes = super::linux_mixed_installed::read_owned_resource(
                        &images.input_source.join(path.as_str()),
                        4 * 1024 * 1024,
                    )?;
                    if bytes.len() as u64 != *size
                        || super::artifacts::checksum(&bytes) != hex::encode(sha256.bytes())
                    {
                        return Err(CiError::Message(
                            "original approved input source differs before isolation mutation"
                                .into(),
                        ));
                    }
                    let destination = source.join(path.as_str());
                    std::fs::create_dir_all(destination.parent().ok_or_else(|| {
                        CiError::Message("isolation approved member parent absent".into())
                    })?)?;
                    super::linux_mixed_installed::retain(&destination, &bytes)?;
                    std::fs::set_permissions(
                        destination,
                        std::fs::Permissions::from_mode(if *executable { 0o555 } else { 0o444 }),
                    )?;
                }
                ImageEntryV1::Symlink { .. } => {
                    return Err(CiError::Message(
                        "owned isolation input fixture unexpectedly contains source symlinks"
                            .into(),
                    ));
                }
            }
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&source)?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory)?;
        let before_inventory =
            capture_import_source_inventory(&definition, &source, None, &mut self.files)?;
        super::linux_mixed_installed::retain(
            &directory.join("isolation-import-original-inventory.json"),
            &serde_json::to_vec(&before_inventory)?,
        )?;
        self.source = Some(ImportSourceOwner {
            root,
            parent,
            name: source.file_name().expect("finite source leaf").to_owned(),
            socket: None,
            socket_parent: None,
            socket_name: None,
            socket_identity: None,
            original: serde_json::Value::Null,
            directory: directory.to_owned(),
        });
        let owner = self
            .source
            .as_mut()
            .expect("retained original source owner");
        let mutation = if ["input-socket", "imported-socket"].contains(&scenario) {
            let selected = if scenario == "input-socket" {
                memcordon_core::workload_contract_v3::RootRelativePath::new(
                    "owned-source/input-socket".into(),
                )
                .map_err(CiError::Message)?
            } else {
                definition
                    .entries
                    .as_slice()
                    .first()
                    .ok_or_else(|| CiError::Message("original input image member absent".into()))?
                    .path()
                    .clone()
            };
            let path = source.join(selected.as_str());
            let baseline = if scenario == "imported-socket" {
                let bytes =
                    super::linux_mixed_installed::read_owned_resource(&path, 4 * 1024 * 1024)?;
                super::linux_mixed_installed::retain(
                    &directory.join("socket-replaced-original.bin"),
                    &bytes,
                )?;
                self.artifacts
                    .push(directory.join("socket-replaced-original.bin"));
                Some(bytes)
            } else {
                None
            };
            let parent_path = path
                .parent()
                .ok_or_else(|| CiError::Message("socket source parent absent".into()))?;
            let parent = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(parent_path)?;
            let name = path
                .file_name()
                .ok_or_else(|| CiError::Message("socket source leaf absent".into()))?
                .to_owned();
            if baseline.is_some() {
                let original = std::fs::symlink_metadata(&path)?;
                if !original.is_file() || original.uid() != 0 || original.nlink() != 1 {
                    return Err(CiError::Message(
                        "socket replacement original regular source invalid".into(),
                    ));
                }
                rustix::fs::unlinkat(&parent, &name, rustix::fs::AtFlags::empty())
                    .map_err(|error| CiError::Message(error.to_string()))?;
            } else {
                match std::fs::symlink_metadata(&path) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                    _ => {
                        return Err(CiError::Message(
                            "extra input socket path already has source authority".into(),
                        ));
                    }
                }
            }
            owner.socket = Some(std::os::unix::net::UnixListener::bind(&path)?);
            let native = std::fs::symlink_metadata(&path)?;
            if native.mode() & libc::S_IFMT != libc::S_IFSOCK
                || native.uid() != 0
                || native.nlink() != 1
            {
                return Err(CiError::Message(
                    "imported socket actual source type differs".into(),
                ));
            }
            owner.socket_identity = Some((native.dev(), native.ino()));
            owner.socket_parent = Some(parent);
            owner.socket_name = Some(name);
            let listener = rustix::fs::fstat(
                owner
                    .socket
                    .as_ref()
                    .expect("original native socket listener"),
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            serde_json::json!({"kind":scenario,"path":selected,"device":native.dev(),"inode":native.ino(),"uid":native.uid(),"gid":native.gid(),"mode":native.mode(),"nlink":native.nlink(),"baseline_sha256":baseline.as_ref().map(|bytes|super::artifacts::checksum(bytes)),
                "listener":{"device":listener.st_dev,"inode":listener.st_ino,"mode":listener.st_mode}})
        } else {
            rustix::fs::fchown(
                &owner.root,
                Some(rustix::process::Uid::from_raw(65534)),
                Some(rustix::process::Gid::from_raw(65534)),
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            owner
                .root
                .set_permissions(std::fs::Permissions::from_mode(0o755))?;
            serde_json::json!({"kind":"caller-writable-tree","caller_uid":65534,"caller_gid":65534})
        };
        let native = owner.root.metadata()?;
        let named = std::fs::symlink_metadata(&source)?;
        if native.dev() != named.dev() || native.ino() != named.ino() {
            return Err(CiError::Message(
                "isolation import source root reassociated before native command".into(),
            ));
        }
        owner.original = serde_json::json!({"format":"memcordon.linux-isolation-import-source","revision":1,"scenario":scenario,"path":source,
            "device":native.dev(),"inode":native.ino(),"uid":native.uid(),"gid":native.gid(),"mode":native.mode(),"mutation":mutation,
            "parent":{"path":directory,"device":owner.parent.metadata()?.dev(),"inode":owner.parent.metadata()?.ino(),"uid":owner.parent.metadata()?.uid(),"mode":owner.parent.metadata()?.mode()}});
        super::linux_mixed_installed::retain(
            &directory.join("isolation-import-source.json"),
            &serde_json::to_vec(&owner.original)?,
        )?;
        let after_inventory = capture_import_source_inventory(
            &definition,
            &source,
            (scenario == "input-socket").then_some("owned-source/input-socket"),
            &mut self.files,
        )?;
        super::linux_mixed_installed::retain(
            &directory.join("isolation-import-inventory.json"),
            &serde_json::to_vec(&after_inventory)?,
        )?;
        let agent = super::linux_mixed_installed::read_owned_resource(
            Path::new("/usr/libexec/memcordon-sealed-agent"),
            512 * 1024 * 1024,
        )?;
        let agent_sha = super::artifacts::checksum(&agent);
        let argv = vec![
            "package".into(),
            "policy".into(),
            "image".into(),
            "install".into(),
            "--definition".into(),
            definition_path.as_os_str().to_owned(),
            "--source-root".into(),
            source.as_os_str().to_owned(),
            "--json".into(),
        ];
        super::linux_mixed_installed::retain(
            &directory.join("invocation.json"),
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-image-import-command","revision":1,
            "identity":input.identity,"cell":input.cell,"lease_id":input.lease_id,"scenario":scenario,"program":"/usr/libexec/memcordon-sealed-agent","executable_sha256":agent_sha,
            "argv":argv.iter().map(|value:&std::ffi::OsString|value.to_string_lossy()).collect::<Vec<_>>(),"cwd":directory,"environment_cleared":true,
            "definition_sha256":super::artifacts::checksum(&definition_bytes),"work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis}),
            )?,
        )?;
        let context = super::linux_readiness_image_cases::ImageCaseContext {
            identity: &input.identity,
            cell: &input.cell,
            lease_id: &input.lease_id,
            activated: policy,
            provider: input.provider,
            images,
            account,
            expected_agent_sha256: &agent_sha,
            output: directory,
            artifact_root: input.artifact_root,
            admin_root: input.admin_root,
            deadline: input.deadline,
            cleanup_deadline: input.cleanup_deadline,
            work_deadline_unix_millis: input.work_deadline_unix_millis,
            cleanup_deadline_unix_millis: input.cleanup_deadline_unix_millis,
        };
        let output = super::linux_readiness_image_cases::capture_import_command(
            &context,
            directory,
            argv,
            &directory.join("native-creation.json"),
            &directory.join("native-process.json"),
            &mut self.files,
            &mut self.processes,
        )?;
        for (name, bytes) in [
            ("stdout.json", &output.stdout),
            ("stderr.bin", &output.stderr),
        ] {
            super::linux_mixed_installed::retain(&directory.join(name), bytes)?;
        }
        super::linux_mixed_installed::retain(
            &directory.join("exit.json"),
            &serde_json::to_vec(
                &serde_json::json!({"native_exit":output.status.code(),"success":output.status.success()}),
            )?,
        )?;
        self.artifacts.extend(
            [
                "isolation-import-intent.json",
                "isolation-import-challenge.bin",
                "isolation-import-source.json",
                "isolation-import-original-inventory.json",
                "isolation-import-inventory.json",
                "invocation.json",
                "native-creation.json",
                "native-process.json",
                "stdout.json",
                "stderr.bin",
                "exit.json",
            ]
            .map(|name| directory.join(name)),
        );
        let retirement = directory.join("definition-retirement");
        std::fs::create_dir(&retirement)?;
        let retirement_argv = vec![
            "package".into(),
            "policy".into(),
            "image".into(),
            "retire".into(),
            "--definition".into(),
            definition_path.as_os_str().to_owned(),
            "--json".into(),
        ];
        super::linux_mixed_installed::retain(
            &retirement.join("invocation.json"),
            &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-isolation-image-retirement-command","revision":1,"identity":input.identity,"cell":input.cell,
            "lease_id":input.lease_id,"scenario":scenario,"program":"/usr/libexec/memcordon-sealed-agent","executable_sha256":agent_sha,
            "argv":retirement_argv.iter().map(|value:&std::ffi::OsString|value.to_string_lossy()).collect::<Vec<_>>(),"cwd":retirement,"environment_cleared":true,
            "definition_sha256":super::artifacts::checksum(&definition_bytes),"work_deadline_unix_millis":input.work_deadline_unix_millis,
            "cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis}))?,
        )?;
        let cleanup_context = super::linux_readiness_image_cases::ImageCaseContext {
            identity: context.identity,
            cell: context.cell,
            lease_id: context.lease_id,
            activated: context.activated,
            provider: context.provider,
            images: context.images,
            account: context.account,
            expected_agent_sha256: context.expected_agent_sha256,
            output: &retirement,
            artifact_root: context.artifact_root,
            admin_root: context.admin_root,
            deadline: context.cleanup_deadline,
            cleanup_deadline: context.cleanup_deadline,
            work_deadline_unix_millis: context.work_deadline_unix_millis,
            cleanup_deadline_unix_millis: context.cleanup_deadline_unix_millis,
        };
        let retired = super::linux_readiness_image_cases::capture_import_command(
            &cleanup_context,
            &retirement,
            retirement_argv,
            &retirement.join("native-creation.json"),
            &retirement.join("native-process.json"),
            &mut self.files,
            &mut self.processes,
        )?;
        for (name, bytes) in [
            ("stdout.json", &retired.stdout),
            ("stderr.bin", &retired.stderr),
        ] {
            super::linux_mixed_installed::retain(&retirement.join(name), bytes)?;
        }
        super::linux_mixed_installed::retain(
            &retirement.join("exit.json"),
            &serde_json::to_vec(
                &serde_json::json!({"native_exit":retired.status.code(),"success":retired.status.success()}),
            )?,
        )?;
        self.artifacts.extend(
            [
                "invocation.json",
                "native-creation.json",
                "native-process.json",
                "stdout.json",
                "stderr.bin",
                "exit.json",
            ]
            .map(|name| retirement.join(name)),
        );
        let retirement_receipt: serde_json::Value = serde_json::from_slice(&retired.stdout)?;
        if !retired.status.success()
            || retirement_receipt["format"] != "memcordon.runtime-image-retirement"
            || retirement_receipt["revision"] != 1
            || retirement_receipt["reference"]
                != serde_json::to_value(definition.reference().map_err(CiError::Message)?)?
            || retirement_receipt["storage_absent"] != true
        {
            return Err(CiError::Message(
                "isolation original input definition retirement differs; owner retained".into(),
            ));
        }
        let probe_nonce = hex::encode(&probe_bytes[..16]);
        let census_path = directory.join("isolation-import-native-census.json");
        super::linux_mixed_installed::persist_policy_refusal_census(
            account,
            input.provider,
            &input.identity,
            &input.cell,
            &input.lease_id,
            scenario,
            &probe_nonce,
            &output.stdout,
            &definition_bytes,
            &census_path,
            input.cleanup_deadline,
        )?;
        let census: serde_json::Value = serde_json::from_slice(
            &super::linux_mixed_installed::read_owned_resource(&census_path, 32 * 1024 * 1024)?,
        )?;
        super::linux_mixed_installed::retain(
            &directory.join("isolation-import-census.json"),
            &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-isolation-import-census","revision":1,"original_probe_nonce":probe_nonce,
            "definition_sha256":super::artifacts::checksum(&definition_bytes),"stdout_sha256":super::artifacts::checksum(&output.stdout),"native_census":census}))?,
        )?;
        self.artifacts
            .extend([census_path, directory.join("isolation-import-census.json")]);
        if output.status.success() {
            return Err(CiError::Message("unsafe actual isolation source unexpectedly imported; native definition intent retained".into()));
        }
        Ok((definition, definition_path))
    }
    pub fn finalize(&mut self, deadline: std::time::Instant) -> Result<()> {
        use std::os::fd::AsFd;
        if let Some(owner) = self.source.as_mut() {
            let root = owner.root.metadata()?;
            let named = rustix::fs::statat(
                &owner.parent,
                &owner.name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            if root.dev() != named.st_dev
                || root.ino() != named.st_ino
                || owner.original["device"] != root.dev()
                || owner.original["inode"] != root.ino()
            {
                return Err(CiError::Message(
                    "isolation source original native root changed before cleanup".into(),
                ));
            }
            if let Some((device, inode)) = owner.socket_identity {
                let parent = owner
                    .socket_parent
                    .as_ref()
                    .ok_or_else(|| CiError::Message("socket original parent absent".into()))?;
                let name = owner
                    .socket_name
                    .as_ref()
                    .ok_or_else(|| CiError::Message("socket original leaf absent".into()))?;
                let named = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|error| CiError::Message(error.to_string()))?;
                if (named.st_dev, named.st_ino) != (device, inode)
                    || named.st_mode & libc::S_IFMT != libc::S_IFSOCK
                {
                    return Err(CiError::Message(
                        "imported source socket native name changed before unlink".into(),
                    ));
                }
                let listener =
                    rustix::fs::fstat(owner.socket.as_ref().expect("held native listener"))
                        .map_err(|error| CiError::Message(error.to_string()))?;
                if owner.original["mutation"]["listener"]["device"] != listener.st_dev
                    || owner.original["mutation"]["listener"]["inode"] != listener.st_ino
                    || owner.original["mutation"]["listener"]["mode"] != listener.st_mode
                {
                    return Err(CiError::Message(
                        "original imported listener descriptor reassociated before close".into(),
                    ));
                }
                rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty())
                    .map_err(|error| CiError::Message(error.to_string()))?;
                memcordon_platform::linux_checked_close(
                    owner.socket.take().expect("held native listener").into(),
                )?;
            }
            rustix::fs::fchown(
                &owner.root,
                Some(rustix::process::Uid::from_raw(0)),
                Some(rustix::process::Gid::from_raw(0)),
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            owner
                .root
                .set_permissions(std::fs::Permissions::from_mode(0o700))?;
            let mut count = 0;
            super::linux_mixed_installed::retire_admin_children(
                &owner.root,
                root.dev(),
                deadline,
                0,
                &mut count,
            )?;
            rustix::fs::unlinkat(
                owner.parent.as_fd(),
                &owner.name,
                rustix::fs::AtFlags::REMOVEDIR,
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            if owner.root.metadata()?.nlink() != 0
                || rustix::fs::statat(
                    &owner.parent,
                    &owner.name,
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .err()
                .map(|error| error.raw_os_error())
                    != Some(libc::ENOENT)
            {
                return Err(CiError::Message(
                    "isolation source original root not retired".into(),
                ));
            }
            let destination = owner.directory.join("isolation-import-source-retired.json");
            super::linux_mixed_installed::retain(
                &destination,
                &serde_json::to_vec(
                    &serde_json::json!({"format":"memcordon.linux-isolation-import-source-retired","revision":1,
                "original":owner.original,"held_nlink":0,"native_errno":libc::ENOENT,"caller_write_revoked_before_cleanup":owner.original["scenario"]=="caller-writable-tree"}),
                )?,
            )?;
            self.artifacts.push(destination);
        }
        for process in &self.processes {
            if !process.exited().map_err(CiError::Message)? {
                return Err(CiError::Message(
                    "isolation native importer owner remains live".into(),
                ));
            }
        }
        if let Some(owner) = self.source.take() {
            let parent = owner.parent.metadata()?;
            let named = std::fs::symlink_metadata(&owner.directory)?;
            if (parent.dev(), parent.ino(), parent.uid(), parent.mode())
                != (named.dev(), named.ino(), named.uid(), named.mode())
                || owner.original["parent"]["device"] != parent.dev()
                || owner.original["parent"]["inode"] != parent.ino()
            {
                return Err(CiError::Message(
                    "original source parent changed before native close".into(),
                ));
            }
            let had_socket_parent = owner.socket_parent.is_some();
            memcordon_platform::linux_checked_close(owner.root.into())?;
            memcordon_platform::linux_checked_close(owner.parent.into())?;
            if let Some(parent) = owner.socket_parent {
                memcordon_platform::linux_checked_close(parent.into())?;
            }
            let file_closes = self.files.len();
            for file in self.files.drain(..) {
                memcordon_platform::linux_checked_close(file.into())?;
            }
            let destination = owner.directory.join("isolation-import-source-closed.json");
            super::linux_mixed_installed::retain(
                &destination,
                &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.linux-isolation-import-source-closed","revision":1,"original":owner.original,
                "parent":{"device":parent.dev(),"inode":parent.ino(),"uid":parent.uid(),"mode":parent.mode()},
                "root_closed":true,"parent_closed":true,"socket_parent_closed":had_socket_parent,"listener_closed":had_socket_parent,
                "native_file_closes":file_closes,"native_errno":serde_json::Value::Null}))?,
            )?;
            self.artifacts.push(destination);
            self.closure_complete = true;
        }
        if !self.closure_complete {
            return Err(CiError::Message(
                "isolation source native close obligation lacks completed original receipt".into(),
            ));
        }
        Ok(())
    }
    pub fn native_owners_settled(&self) -> bool {
        self.closure_complete
            && self.source.is_none()
            && self
                .processes
                .iter()
                .all(|process| process.exited().unwrap_or(false))
    }
}

pub struct HostSocketDescriptor {
    source: Option<File>,
    peer: Option<std::os::unix::net::UnixStream>,
    pub descriptor: i32,
    original: Option<serde_json::Value>,
}
impl HostSocketDescriptor {
    pub fn create(descriptor: i32) -> Result<Self> {
        if ![0, 128].contains(&descriptor) {
            return Err(CiError::Message(
                "host socket finite descriptor differs".into(),
            ));
        }
        let (source, peer) = std::os::unix::net::UnixStream::pair()?;
        // EOF is a byte-stream condition, not closure of the original held
        // host peer. Keep both socket owners through native target retirement.
        peer.shutdown(std::net::Shutdown::Write)?;
        Ok(Self {
            source: Some(File::from(std::os::fd::OwnedFd::from(source))),
            peer: Some(peer),
            descriptor,
            original: None,
        })
    }
    pub fn handoff(&self) -> Result<std::os::fd::OwnedFd> {
        rustix::io::dup(
            self.source.as_ref().ok_or_else(|| {
                CiError::Message("host socket source closed before handoff".into())
            })?,
        )
        .map_err(|error| CiError::Message(error.to_string()))
    }
    pub fn observe_frontend(&mut self, pid: u32, birth: u64, directory: &Path) -> Result<()> {
        let held = crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth)
            .map_err(CiError::Message)?;
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| CiError::Message("host socket source absent".into()))?
            .metadata()?;
        let peer = self
            .peer
            .as_ref()
            .ok_or_else(|| CiError::Message("host socket peer absent".into()))?;
        let peer_stamp =
            File::from(rustix::io::dup(peer).map_err(|error| CiError::Message(error.to_string()))?)
                .metadata()?;
        let path = format!("/proc/{pid}/fd/{}", self.descriptor);
        let named = std::fs::read_link(&path)?;
        if source.mode() & libc::S_IFMT != libc::S_IFSOCK
            || named.as_os_str().as_encoded_bytes()
                != format!("socket:[{}]", source.ino()).as_bytes()
            || held.exited().map_err(CiError::Message)?
        {
            return Err(CiError::Message(
                "original frontend hostile socket handoff not held live".into(),
            ));
        }
        let fdinfo = std::fs::read(format!("/proc/{pid}/fdinfo/{}", self.descriptor))?;
        if fdinfo.len() > 4096 {
            return Err(CiError::Message(
                "host socket native fdinfo unbounded".into(),
            ));
        }
        let network = File::open("/proc/self/ns/net")?.metadata()?;
        let observer = std::process::id();
        let original = serde_json::json!({"format":"memcordon.linux-host-socket-descriptor","revision":1,
            "descriptor":self.descriptor,"frontend":held.live_snapshot().map_err(CiError::Message)?,
            "source":{"device":source.dev(),"inode":source.ino(),"mode":source.mode()},
            "peer":{"device":peer_stamp.dev(),"inode":peer_stamp.ino(),"mode":peer_stamp.mode()},
            "source_link":named.as_os_str().as_encoded_bytes(),"fdinfo":fdinfo,
            "observer":{"pid":observer,"birth":crate::linux_consumer_readiness::process_birth(observer).map_err(CiError::Message)?},
            "host_network":{"device":network.dev(),"inode":network.ino()}});
        super::linux_mixed_installed::retain(
            &directory.join("host-socket-descriptor-live.json"),
            &serde_json::to_vec(&original)?,
        )?;
        self.original = Some(original);
        Ok(())
    }
    pub fn settle(mut self, directory: &Path) -> Result<()> {
        let original = self.original.take().ok_or_else(|| {
            CiError::Message("host socket original frontend custody absent".into())
        })?;
        let source = self
            .source
            .take()
            .ok_or_else(|| CiError::Message("host socket source already closed".into()))?;
        let peer = self
            .peer
            .take()
            .ok_or_else(|| CiError::Message("host socket peer already closed".into()))?;
        let source_meta = source.metadata()?;
        if original["source"]["device"] != source_meta.dev()
            || original["source"]["inode"] != source_meta.ino()
        {
            return Err(CiError::Message(
                "original host socket owner reassociated".into(),
            ));
        }
        let peer_meta =
            rustix::fs::fstat(&peer).map_err(|error| CiError::Message(error.to_string()))?;
        if original["peer"]["device"] != peer_meta.st_dev
            || original["peer"]["inode"] != peer_meta.st_ino
            || original["peer"]["mode"] != peer_meta.st_mode
            || original["source"]["mode"] != source_meta.mode()
        {
            return Err(CiError::Message(
                "original host socket peer identity changed before checked close".into(),
            ));
        }
        memcordon_platform::linux_checked_close(std::os::fd::OwnedFd::from(source))
            .map_err(|errno| CiError::Message(format!("host socket source close errno {errno}")))?;
        memcordon_platform::linux_checked_close(std::os::fd::OwnedFd::from(peer))
            .map_err(|errno| CiError::Message(format!("host socket peer close errno {errno}")))?;
        super::linux_mixed_installed::retain(
            &directory.join("host-socket-descriptor-retired.json"),
            &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-host-socket-descriptor-retired","revision":1,"original":original,"source_closed":true,"peer_closed":true,"native_errno":serde_json::Value::Null}))?,
        )
    }
}

/// Original frontend and external task owners for an account-busy admission
/// probe. The caller stores this report before crossing either spawn boundary.
#[derive(Default)]
pub struct AccountRefusalReport {
    pub external: Option<ExternalAccountTask>,
    pub launches: Vec<super::linux_mixed_installed::InstalledMixedLaunch>,
    pub artifacts: Vec<PathBuf>,
    restore: Option<(
        memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3,
        PathBuf,
        PathBuf,
    )>,
    reservation: Option<StaleReservation>,
}
impl AccountRefusalReport {
    pub fn native_owners_settled(&self) -> bool {
        self.reservation.is_none()
            && self.restore.is_none()
            && self.external.as_ref().is_none_or(|owner| owner.settled)
            && self
                .launches
                .iter()
                .all(|launch| launch.frontend_status.is_some())
    }
    pub fn finalize(&mut self, deadline: std::time::Instant) -> Result<()> {
        let mut failures = Vec::new();
        for launch in &mut self.launches {
            match launch.frontend.try_wait() {
                Ok(None) => {
                    if let Err(error) = launch.frontend.kill() {
                        failures.push(format!("original account probe frontend kill: {error}"));
                    }
                }
                Ok(Some(_)) => {}
                Err(error) => failures.push(format!(
                    "original account probe frontend observation: {error}"
                )),
            }
            if let Err(error) = launch
                .wait_and_capture(deadline.saturating_duration_since(std::time::Instant::now()))
            {
                failures.push(error.to_string());
            }
        }
        if let Some(Err(error)) = self
            .external
            .as_mut()
            .filter(|owner| !owner.settled)
            .map(|owner| owner.settle(deadline))
        {
            failures.push(error.to_string());
        }
        if let Some(reservation) = self.reservation.as_mut() {
            match reservation.settle() {
                Ok(path) => {
                    self.artifacts.push(path);
                    self.reservation = None;
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        if let Some((baseline, directory, privileged)) = &self.restore {
            match super::linux_readiness_policy_cases::apply_policy(
                baseline,
                directory,
                privileged,
                "alias-restoration",
                deadline,
            ) {
                Ok((_, receipt)) => {
                    self.artifacts.push(receipt);
                    self.artifacts.extend(
                        ["policy.json", "invocation.json", "exit.json", "stderr.bin"].map(
                            |extension| {
                                directory
                                    .join("alias-restoration")
                                    .with_extension(extension)
                            },
                        ),
                    );
                    self.restore = None;
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(CiError::Message(failures.join("; ")))
        }
    }
    pub fn run_same_uid(
        &mut self,
        input: &super::linux_mixed_installed::InstalledMixedDriverInput<'_>,
        account: &crate::consumer_readiness_ledger::ExclusiveAccount,
        policy: &super::linux_mixed_installed::ActivatedMixedPolicy,
        directory: &Path,
        challenge: &str,
    ) -> Result<()> {
        if self.external.is_some() || !self.launches.is_empty() {
            return Err(CiError::Message(
                "account refusal report reused across native attempts".into(),
            ));
        }
        self.external = Some(ExternalAccountTask::start(
            directory,
            account.uid,
            account.gid,
            input.deadline,
            input.cleanup_deadline,
        )?);
        self.artifacts.extend(
            [
                "external-account-intent.json",
                "external-account-image.bin",
                "external-account-live.json",
            ]
            .map(|name| directory.join(name)),
        );
        self.run_frontend(
            input,
            account,
            policy,
            directory,
            challenge,
            "same-uid-process",
        )
    }
    pub fn run_alias(
        &mut self,
        input: &super::linux_mixed_installed::InstalledMixedDriverInput<'_>,
        account: &crate::consumer_readiness_ledger::ExclusiveAccount,
        policy: &super::linux_mixed_installed::ActivatedMixedPolicy,
        directory: &Path,
        challenge: &str,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        if self.external.is_some() || !self.launches.is_empty() || self.restore.is_some() {
            return Err(CiError::Message("account alias report reused".into()));
        }
        let mut value = serde_json::to_value(&policy.registry)?;
        let identities = value["execution_identities"]
            .as_array_mut()
            .filter(|rows| rows.len() == 1)
            .ok_or_else(|| {
                CiError::Message("account alias needs sole original exclusive identity".into())
            })?;
        identities[0]["uid"] = 65534.into();
        identities[0]["gid"] = 65534.into();
        let definition: memcordon_core::workload_registry_v3::ExclusiveIdentityDefinitionV3 =
            serde_json::from_value(identities[0].clone())?;
        let reference = definition.reference().map_err(CiError::Message)?;
        let mut contract = policy.contract.clone();
        contract.execution_identity = reference.clone();
        let approved = serde_json::to_vec(&(
            &contract.runtime_image,
            &contract.input_image,
            &contract.root_layout,
            &contract.execution_identity,
            &contract.requirements,
        ))?;
        let digest = memcordon_core::DiagnosticSha256::from_bytes(Sha256::digest(&approved).into());
        value["grants"][0]["execution_identity"] = serde_json::to_value(&reference)?;
        value["grants"][0]["approved_plans"] = serde_json::json!([digest]);
        let mutated: memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3 =
            serde_json::from_value(value)?;
        mutated.validate().map_err(CiError::Message)?;
        let privileged = input.admin_root.join(format!(
            "isolation-alias-{}",
            directory
                .file_name()
                .ok_or_else(|| CiError::Message("alias original case basename absent".into()))?
                .to_string_lossy()
        ));
        std::fs::create_dir(&privileged)?;
        self.restore = Some((
            policy.registry.clone(),
            directory.to_owned(),
            privileged.clone(),
        ));
        let (epoch, activation) = super::linux_readiness_policy_cases::apply_policy(
            &mutated,
            directory,
            &privileged,
            "alias-activation",
            input.deadline,
        )?;
        contract.expected_epoch = epoch;
        contract.workload_plan_digest = digest.clone();
        contract.authorization.approved_plan_digest = digest;
        contract.validate().map_err(CiError::Message)?;
        // The public copied contract remains readable by the actual caller;
        // its protected mutation and native activation receipts are retained.
        let path = directory.join("alias.contract.json");
        super::linux_mixed_installed::retain(&path, &serde_json::to_vec(&contract)?)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        self.artifacts.extend([
            path.clone(),
            activation.clone(),
            directory.join("alias-activation.policy.json"),
        ]);
        self.artifacts.extend(
            ["invocation.json", "exit.json", "stderr.bin"]
                .map(|extension| directory.join("alias-activation").with_extension(extension)),
        );
        let active = super::linux_mixed_installed::ActivatedMixedPolicy {
            registry: mutated,
            contract,
            policy_path: directory.join("alias-activation.policy.json"),
            activation_path: activation,
        };
        self.run_frontend(
            input,
            account,
            &active,
            directory,
            challenge,
            "account-alias",
        )
    }
    pub fn run_stale(
        &mut self,
        input: &super::linux_mixed_installed::InstalledMixedDriverInput<'_>,
        account: &crate::consumer_readiness_ledger::ExclusiveAccount,
        policy: &super::linux_mixed_installed::ActivatedMixedPolicy,
        directory: &Path,
        challenge: &str,
    ) -> Result<()> {
        if self.external.is_some() || !self.launches.is_empty() || self.reservation.is_some() {
            return Err(CiError::Message("stale reservation report reused".into()));
        }
        self.external = Some(ExternalAccountTask::start(
            directory,
            account.uid,
            account.gid,
            input.deadline,
            input.cleanup_deadline,
        )?);
        let original_owner = self
            .external
            .as_ref()
            .expect("actual stale original owner")
            .identity();
        self.external
            .as_mut()
            .expect("retained stale original owner")
            .settle(input.cleanup_deadline)?;
        self.artifacts.extend(
            [
                "external-account-intent.json",
                "external-account-image.bin",
                "external-account-live.json",
                "external-account-retired.json",
            ]
            .map(|name| directory.join(name)),
        );
        self.reservation = Some(StaleReservation::create(
            directory,
            account.uid,
            original_owner,
            challenge,
        )?);
        self.artifacts.extend(
            [
                "stale-reservation-intent.json",
                "stale-reservation-live.json",
            ]
            .map(|name| directory.join(name)),
        );
        self.run_frontend(
            input,
            account,
            policy,
            directory,
            challenge,
            "stale-reservation",
        )
    }
    fn run_frontend(
        &mut self,
        input: &super::linux_mixed_installed::InstalledMixedDriverInput<'_>,
        account: &crate::consumer_readiness_ledger::ExclusiveAccount,
        policy: &super::linux_mixed_installed::ActivatedMixedPolicy,
        directory: &Path,
        challenge: &str,
        scenario: &str,
    ) -> Result<()> {
        let arguments = vec![
            std::ffi::OsString::from("tcp-http"),
            std::ffi::OsString::from(challenge),
        ];
        self.launches
            .push(super::linux_mixed_installed::InstalledMixedLaunch::start(
                super::linux_mixed_installed::InstalledMixedLaunchInput {
                    directory: &directory.join("frontend"),
                    contract: &directory.join(if scenario == "account-alias" {
                        "alias.contract.json"
                    } else {
                        "mixed.contract.json"
                    }),
                    caller_uid: 65534,
                    caller_gid: 65534,
                    target_arguments: &arguments,
                    memory: std::ffi::OsStr::new("+256M"),
                    deadline: std::ffi::OsStr::new("+30000ms"),
                },
            )?);
        let launch = self
            .launches
            .last_mut()
            .expect("retained original account probe frontend");
        launch.frontend.stdin.take();
        let status = launch.wait_and_capture(
            std::time::Duration::from_secs(30).min(
                input
                    .deadline
                    .saturating_duration_since(std::time::Instant::now()),
            ),
        )?;
        // Keep the measured live account occupation through the genuine
        // refusal. A native setup success is retained as a verifier failure.
        if let Some(occupation) = self.external.as_ref().filter(|owner| !owner.settled) {
            if occupation.held.exited().map_err(CiError::Message)? {
                return Err(CiError::Message(
                    "external account task retired before actual admission response".into(),
                ));
            }
            super::linux_mixed_installed::retain(
                &directory.join("external-account-at-refusal.json"),
                &serde_json::to_vec(&occupation.held.live_snapshot().map_err(CiError::Message)?)?,
            )?;
            self.artifacts
                .push(directory.join("external-account-at-refusal.json"));
        }
        let result = super::linux_mixed_installed::read_policy_observation_file(
            &launch.result,
            4 * 1024 * 1024,
        )?;
        let parsed =
            memcordon_core::result_v2::ResultV2::parse(&result).map_err(CiError::Message)?;
        if status.code() != Some(125) || parsed.wrapper_status != 125 {
            return Err(CiError::Message(
                "account-busy probe did not produce actual frontend setup refusal".into(),
            ));
        }
        let request_paths = std::fs::read_dir(&launch.observation_directory)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.as_encoded_bytes().ends_with(b".provider-request.bin"))
            })
            .collect::<Vec<_>>();
        if request_paths.len() != 1 {
            return Err(CiError::Message(
                "account probe original native request ambiguous".into(),
            ));
        }
        let request = super::linux_mixed_installed::read_policy_observation_file(
            &request_paths[0],
            4 * 1024 * 1024,
        )?;
        let attempt = request_paths[0]
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".provider-request.bin"))
            .filter(|name| {
                name.len() == 32
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| {
                CiError::Message("account refusal original native attempt basename absent".into())
            })?;
        if let Some(external) = self.external.as_mut().filter(|owner| !owner.settled) {
            external.settle(input.cleanup_deadline)?;
            self.artifacts
                .push(directory.join("external-account-retired.json"));
        }
        if let Some(reservation) = self.reservation.as_mut() {
            self.artifacts.push(reservation.settle()?);
            self.reservation = None;
        }
        super::linux_mixed_installed::persist_policy_refusal_census(
            account,
            input.provider,
            &input.identity,
            &input.cell,
            &input.lease_id,
            scenario,
            attempt,
            &result,
            &request,
            &directory.join("refusal-census.json"),
            input.cleanup_deadline,
        )?;
        self.artifacts.extend([
            directory.join("refusal-census.json"),
            request_paths[0].clone(),
            launch.result.clone(),
            launch.stdout.clone(),
            launch.stderr.clone(),
        ]);
        super::linux_mixed_installed::retain(
            &directory.join("original-activation.json"),
            &super::linux_mixed_installed::read_owned_resource(
                &policy.activation_path,
                4 * 1024 * 1024,
            )?,
        )?;
        self.artifacts
            .push(directory.join("original-activation.json"));
        Ok(())
    }
}

struct StaleReservation {
    parents: Vec<File>,
    file: Option<File>,
    name: std::ffi::OsString,
    path: PathBuf,
    directory: PathBuf,
    original: serde_json::Value,
}
impl StaleReservation {
    fn create(directory: &Path, uid: u32, owner: (u32, u64), challenge: &str) -> Result<Self> {
        use std::os::fd::AsFd;
        if challenge.len() != 64
            || !challenge
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || owner.0 == 0
            || owner.1 == 0
        {
            return Err(CiError::Message(
                "stale native reservation original identity differs".into(),
            ));
        }
        let parents = super::linux_native_component::protected_directory(Path::new(
            "/var/lib/memcordon/sealed",
        ))?;
        let namespace = File::open("/proc/self/ns/user")?.metadata()?;
        let name = std::ffi::OsString::from(format!(
            "account-{}-{}-{uid}.reservation",
            namespace.dev(),
            namespace.ino()
        ));
        let path = Path::new("/var/lib/memcordon/sealed").join(&name);
        let attempt =
            hex::decode(&challenge[..32]).map_err(|error| CiError::Message(error.to_string()))?;
        if attempt.iter().all(|byte| *byte == 0) {
            return Err(CiError::Message(
                "stale reservation original random attempt is zero".into(),
            ));
        }
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        let payload = serde_json::json!({"format":"memcordon.account-reservation","revision":1,
            "user_namespace_device":namespace.dev(),"user_namespace_inode":namespace.ino(),"uid":uid,"attempt":attempt,
            "owner_pid":owner.0,"owner_birth":owner.1,"boot_identity":boot});
        let bytes = serde_json::to_vec(&payload)?;
        let parent = parents
            .last()
            .ok_or_else(|| CiError::Message("stale reservation held parent absent".into()))?;
        let stamp = parent.metadata()?;
        super::linux_mixed_installed::retain(
            &directory.join("stale-reservation-intent.json"),
            &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-stale-reservation-intent","revision":1,"path":path,"payload":payload,"payload_sha256":super::artifacts::checksum(&bytes),
            "parent":{"device":stamp.dev(),"inode":stamp.ino(),"uid":stamp.uid(),"mode":stamp.mode()}}))?,
        )?;
        let fd = rustix::fs::openat(
            parent.as_fd(),
            &name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let mut file = File::from(fd);
        file.write_all(&bytes)?;
        file.sync_all()?;
        parent.sync_all()?;
        let metadata = file.metadata()?;
        let named = rustix::fs::statat(parent, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || named.st_dev != metadata.dev()
            || named.st_ino != metadata.ino()
        {
            return Err(CiError::Message(
                "stale reservation original native custody differs".into(),
            ));
        }
        let mut parent_graph = Vec::new();
        for (held, path) in parents.iter().zip([
            "/",
            "/var",
            "/var/lib",
            "/var/lib/memcordon",
            "/var/lib/memcordon/sealed",
        ]) {
            let held = held.metadata()?;
            let named = std::fs::symlink_metadata(path)?;
            if held.dev() != named.dev()
                || held.ino() != named.ino()
                || held.uid() != 0
                || held.mode() & 0o022 != 0
                || !named.is_dir()
                || named.file_type().is_symlink()
            {
                return Err(CiError::Message(
                    "stale reservation held protected ancestry changed during allocation".into(),
                ));
            }
            parent_graph.push(serde_json::json!({"path":path,"device":held.dev(),"inode":held.ino(),"uid":held.uid(),"mode":held.mode(),"nlink":held.nlink()}));
        }
        if parent_graph.len() != 5 {
            return Err(CiError::Message(
                "stale reservation original protected ancestry cardinality differs".into(),
            ));
        }
        let original = serde_json::json!({"format":"memcordon.linux-stale-reservation-live","revision":1,"path":path,"payload":payload,
            "device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode(),"nlink":metadata.nlink(),
            "payload_sha256":super::artifacts::checksum(&bytes),"parent":{"device":stamp.dev(),"inode":stamp.ino(),"uid":stamp.uid(),"mode":stamp.mode()},"parents":parent_graph});
        super::linux_mixed_installed::retain(
            &directory.join("stale-reservation-live.json"),
            &serde_json::to_vec(&original)?,
        )?;
        Ok(Self {
            parents,
            file: Some(file),
            name,
            path,
            directory: directory.to_owned(),
            original,
        })
    }
    fn settle(&mut self) -> Result<PathBuf> {
        for (index, (held, path)) in self
            .parents
            .iter()
            .zip([
                "/",
                "/var",
                "/var/lib",
                "/var/lib/memcordon",
                "/var/lib/memcordon/sealed",
            ])
            .enumerate()
        {
            let metadata = held.metadata()?;
            let named = std::fs::symlink_metadata(path)?;
            let original = &self.original["parents"][index];
            if metadata.dev() != named.dev()
                || metadata.ino() != named.ino()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || original["device"] != metadata.dev()
                || original["inode"] != metadata.ino()
                || original["mode"] != metadata.mode()
                || !named.is_dir()
                || named.file_type().is_symlink()
            {
                return Err(CiError::Message(
                    "stale reservation original held ancestry changed before retirement".into(),
                ));
            }
        }
        let parent = self
            .parents
            .last()
            .ok_or_else(|| CiError::Message("stale reservation cleanup parent absent".into()))?;
        let file = self.file.as_ref().ok_or_else(|| {
            CiError::Message("stale reservation original owner already closed".into())
        })?;
        let stamp = file.metadata()?;
        let named = rustix::fs::statat(parent, &self.name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if self.original["device"] != stamp.dev()
            || self.original["inode"] != stamp.ino()
            || named.st_dev != stamp.dev()
            || named.st_ino != stamp.ino()
            || stamp.uid() != 0
            || stamp.nlink() != 1
            || stamp.mode() & 0o7777 != 0o600
        {
            return Err(CiError::Message(
                "stale reservation original native name changed; owner retained".into(),
            ));
        }
        rustix::fs::unlinkat(parent, &self.name, rustix::fs::AtFlags::empty())
            .map_err(|error| CiError::Message(error.to_string()))?;
        parent.sync_all()?;
        let after = file.metadata()?;
        let errno = rustix::fs::statat(parent, &self.name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .err()
            .map(|error| error.raw_os_error());
        if after.nlink() != 0 || errno != Some(libc::ENOENT) {
            return Err(CiError::Message(
                "stale reservation original inode not retired".into(),
            ));
        }
        memcordon_platform::linux_checked_close(
            self.file
                .take()
                .expect("original held reservation owner")
                .into(),
        )?;
        let mut closure = Vec::new();
        for (index, (held, path)) in self
            .parents
            .drain(..)
            .zip([
                "/",
                "/var",
                "/var/lib",
                "/var/lib/memcordon",
                "/var/lib/memcordon/sealed",
            ])
            .enumerate()
        {
            let metadata = held.metadata()?;
            let named = std::fs::symlink_metadata(path)?;
            if named.dev() != metadata.dev()
                || named.ino() != metadata.ino()
                || named.uid() != metadata.uid()
                || named.mode() != metadata.mode()
                || named.file_type().is_symlink()
            {
                return Err(CiError::Message(
                    "stale reservation protected ancestry changed after original inode retirement"
                        .into(),
                ));
            }
            memcordon_platform::linux_checked_close(held.into())?;
            closure.push(serde_json::json!({"index":index,"path":path,"device":metadata.dev(),"inode":metadata.ino(),"named_device":named.dev(),"named_inode":named.ino(),"uid":metadata.uid(),"mode":metadata.mode(),"closed":true,"native_errno":serde_json::Value::Null}));
        }
        let destination = self.directory.join("stale-reservation-retired.json");
        super::linux_mixed_installed::retain(
            &destination,
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-stale-reservation-retired","revision":1,
            "original":self.original,"path":self.path,"native_errno":errno,"held_nlink":after.nlink(),"closed":true,"parents":closure}),
            )?,
        )?;
        Ok(destination)
    }
}

/// An actual external host task using the administrator's selected exclusive
/// account. Its PIDFD and kernel image stay held through the admission probe.
pub struct ExternalAccountTask {
    child: std::process::Child,
    held: crate::linux_consumer_readiness::HeldLinuxProcess,
    pub original: serde_json::Value,
    pub directory: PathBuf,
    settled: bool,
}
impl ExternalAccountTask {
    pub fn start(
        directory: &Path,
        uid: u32,
        gid: u32,
        deadline: std::time::Instant,
        cleanup_deadline: std::time::Instant,
    ) -> Result<Self> {
        use std::io::Read;
        if uid == 0
            || gid == 0
            || deadline >= cleanup_deadline
            || std::time::Instant::now() >= deadline
        {
            return Err(CiError::Message(
                "external account task ownership/cutoff invalid".into(),
            ));
        }
        let program = Path::new("/usr/bin/setpriv");
        let executable = Path::new("/usr/bin/sleep");
        let image =
            super::linux_mixed_installed::read_owned_resource(executable, 64 * 1024 * 1024)?;
        let argv = vec![
            "--reuid".to_owned(),
            uid.to_string(),
            "--regid".to_owned(),
            gid.to_string(),
            "--clear-groups".to_owned(),
            "--".to_owned(),
            executable.to_string_lossy().into_owned(),
            "300".to_owned(),
        ];
        let intent = serde_json::json!({"format":"memcordon.linux-external-account-task-intent","revision":1,
            "program":program.as_os_str().as_encoded_bytes(),"arguments":argv.iter().map(|value|value.as_bytes()).collect::<Vec<_>>(),"environment_cleared":true,
            "uid":uid,"gid":gid,"selected_executable_sha256":super::artifacts::checksum(&image)});
        super::linux_mixed_installed::retain(
            &directory.join("external-account-intent.json"),
            &serde_json::to_vec(&intent)?,
        )?;
        super::linux_mixed_installed::retain(
            &directory.join("external-account-image.bin"),
            &image,
        )?;
        let mut command = std::process::Command::new(program);
        command
            .args(&argv)
            .env_clear()
            .current_dir(directory)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = command.spawn()?;
        let pid = child.id();
        let birth = match crate::linux_consumer_readiness::process_birth(pid) {
            Ok(value) => value,
            Err(error) => {
                abort_unobserved_child(&mut child, cleanup_deadline)?;
                return Err(CiError::Message(error));
            }
        };
        let held = match crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth) {
            Ok(value) => value,
            Err(error) => {
                abort_unobserved_child(&mut child, cleanup_deadline)?;
                return Err(CiError::Message(error));
            }
        };
        let mut owner = Self {
            child,
            held,
            original: serde_json::Value::Null,
            directory: directory.to_owned(),
            settled: false,
        };
        let transition =
            deadline.min(std::time::Instant::now() + std::time::Duration::from_secs(3));
        let transition_result = (|| -> Result<()> {
            loop {
                if std::time::Instant::now() >= transition {
                    return Err(CiError::Message(
                        "external account native exec/credential transition deadline exhausted"
                            .into(),
                    ));
                }
                if owner.held.exited().map_err(CiError::Message)? {
                    return Err(CiError::Message(
                        "external account task exited before actual UID observation".into(),
                    ));
                }
                let mut status = Vec::new();
                File::open(format!("/proc/{pid}/status"))?
                    .take(131073)
                    .read_to_end(&mut status)?;
                if status.len() > 131072 {
                    return Err(CiError::Message(
                        "external account native credentials unbounded".into(),
                    ));
                }
                let text = std::str::from_utf8(&status)
                    .map_err(|error| CiError::Message(error.to_string()))?;
                let ids = |prefix: &str| -> Result<Vec<u32>> {
                    text.lines()
                        .find_map(|line| line.strip_prefix(prefix))
                        .ok_or_else(|| {
                            CiError::Message(
                                "external account native credential tuple absent".into(),
                            )
                        })?
                        .split_whitespace()
                        .map(|value| {
                            value
                                .parse::<u32>()
                                .map_err(|error| CiError::Message(error.to_string()))
                        })
                        .collect()
                };
                if ids("Uid:")? != vec![uid; 4]
                    || ids("Gid:")? != vec![gid; 4]
                    || !ids("Groups:")?.is_empty()
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                let kernel_image = owner
                    .held
                    .hold_executable_image(transition)
                    .map_err(CiError::Message)?;
                if kernel_image["sha256"] != super::artifacts::checksum(&image) {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                let snapshot = owner.held.live_snapshot().map_err(CiError::Message)?;
                let creator = std::process::id();
                owner.original = serde_json::json!({"format":"memcordon.linux-external-account-task","revision":1,
                "intent_sha256":super::artifacts::checksum(&serde_json::to_vec(&intent)?),"held":snapshot,"kernel_image":kernel_image,
                "native_status":status,"uid":uid,"gid":gid,"creator":{"pid":creator,"birth":crate::linux_consumer_readiness::process_birth(creator).map_err(CiError::Message)?}});
                super::linux_mixed_installed::retain(
                    &directory.join("external-account-live.json"),
                    &serde_json::to_vec(&owner.original)?,
                )?;
                return Ok(());
            }
        })();
        if let Err(error) = transition_result {
            owner.settle(cleanup_deadline).map_err(|cleanup|CiError::Message(format!("external account transition failed: {error}; original native cleanup: {cleanup}")))?;
            return Err(error);
        }
        Ok(owner)
    }
    pub fn identity(&self) -> (u32, u64) {
        (self.held.process_id, self.held.birth)
    }
    pub fn settle(&mut self, deadline: std::time::Instant) -> Result<serde_json::Value> {
        use std::os::unix::process::ExitStatusExt;
        if self.settled {
            return Err(CiError::Message(
                "external account task settlement duplicated".into(),
            ));
        }
        let signal = if self.held.exited().map_err(CiError::Message)? {
            None
        } else {
            Some(
                self.held
                    .signal_kill()
                    .map_err(CiError::Message)?
                    .map_err(|errno| {
                        CiError::Message(format!(
                            "external account original PIDFD kill errno {errno}"
                        ))
                    })?,
            )
        };
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                return Err(CiError::Message(
                    "external account original Child retirement exceeds cleanup cutoff".into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        let held = self.held.retirement_identity().map_err(CiError::Message)?;
        if !held.retirement_observed {
            return Err(CiError::Message(
                "external account task Child wait lacks original PIDFD retirement".into(),
            ));
        }
        let receipt = serde_json::json!({"format":"memcordon.linux-external-account-retired","revision":1,
            "original_sha256":super::artifacts::checksum(&serde_json::to_vec(&self.original)?),"held":held,
            "signal_sent":signal.is_some(),"raw_wait_status":status.into_raw(),"native_exit":status.code(),"signal":status.signal()});
        super::linux_mixed_installed::retain(
            &self.directory.join("external-account-retired.json"),
            &serde_json::to_vec(&receipt)?,
        )?;
        self.settled = true;
        Ok(receipt)
    }
}
impl Drop for ExternalAccountTask {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self.held.signal_kill();
            let _ = self.child.try_wait();
        }
    }
}

/// Before PIDFD acquisition the original Child remains the only native owner.
/// Never turn a failed birth observation into an unbounded blocking wait.
fn abort_unobserved_child(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    child.kill()?;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(CiError::Message(
                "external account unobserved Child cleanup exceeded original cutoff".into(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Holds the original host peer and its protected parent until native denial
/// and explicit cleanup have both been measured.
pub struct HostPathSocket {
    listener: Option<std::os::unix::net::UnixListener>,
    parent: Option<File>,
    parent_path: PathBuf,
    pub path: PathBuf,
    original: serde_json::Value,
    cleanup_identity: Option<(u64, u64)>,
    active: bool,
}
impl HostPathSocket {
    pub fn prepare(
        directory: &Path,
        kind: &str,
        challenge: &str,
        deadline: std::time::Instant,
    ) -> Result<Self> {
        use std::io::Read;
        use std::os::unix::fs::FileTypeExt;
        let parent_path = match kind {
            "host-run-socket" => PathBuf::from("/run"),
            "host-temp-socket" => PathBuf::from("/tmp"),
            _ => {
                return Err(CiError::Message(
                    "unknown original host pathname socket scenario".into(),
                ));
            }
        };
        if challenge.len() != 64 || !challenge.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CiError::Message("host socket challenge malformed".into()));
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&parent_path)?;
        let stamp = parent.metadata()?;
        if stamp.uid() != 0
            || (stamp.mode() & 0o022 != 0
                && !(kind == "host-temp-socket" && stamp.mode() & 0o1000 != 0))
        {
            return Err(CiError::Message(
                "host socket original parent lacks native protection".into(),
            ));
        }
        let path = parent_path.join(format!("memcordon-readiness-{challenge}.sock"));
        super::linux_mixed_installed::retain(
            &directory.join("host-path-socket-intent.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.linux-host-path-socket-intent","revision":1,"kind":kind,"path":path,"challenge":challenge,
                "parent":{"path":parent_path,"device":stamp.dev(),"inode":stamp.ino(),"uid":stamp.uid(),"mode":stamp.mode()}
            }))?,
        )?;
        if std::time::Instant::now() >= deadline {
            return Err(CiError::Message(
                "host socket allocation crossed original work cutoff".into(),
            ));
        }
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        let mut owner = Self {
            listener: Some(listener),
            parent: Some(parent),
            parent_path,
            path,
            original: serde_json::Value::Null,
            cleanup_identity: None,
            active: true,
        };
        let allocated = std::fs::symlink_metadata(&owner.path)?;
        owner.cleanup_identity = Some((allocated.dev(), allocated.ino()));
        std::fs::set_permissions(&owner.path, std::fs::Permissions::from_mode(0o666))?;
        super::linux_mixed_installed::retain(
            &directory.join("host-path-socket-allocation.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.linux-host-path-socket-allocation","revision":1,"path":owner.path,"device":allocated.dev(),"inode":allocated.ino(),
                "uid":allocated.uid(),"gid":allocated.gid(),"nlink":allocated.nlink(),
                "intent_sha256":super::artifacts::checksum(&super::linux_mixed_installed::read_owned_resource(&directory.join("host-path-socket-intent.json"),64*1024)?)
            }))?,
        )?;
        owner
            .listener
            .as_ref()
            .expect("original listener owner")
            .set_nonblocking(true)?;
        let client_fd = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let address = rustix::net::SocketAddrUnix::new(&owner.path)
            .map_err(|error| CiError::Message(error.to_string()))?;
        // A fresh local listener accepts synchronously; backlog interference is
        // an explicit failed positive, never a blocking connect or a denial.
        rustix::net::connect(&client_fd, &address)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let mut client = std::os::unix::net::UnixStream::from(client_fd);
        client.set_nonblocking(false)?;
        let (mut accepted, _) = loop {
            if std::time::Instant::now() >= deadline {
                return Err(CiError::Message(
                    "host socket positive accept crossed original work cutoff".into(),
                ));
            }
            match owner
                .listener
                .as_ref()
                .expect("original listener owner")
                .accept()
            {
                Ok(peer) => break peer,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2))
                }
                Err(error) => return Err(error.into()),
            }
        };
        let remaining = deadline
            .saturating_duration_since(std::time::Instant::now())
            .min(std::time::Duration::from_secs(2));
        if remaining.is_zero() {
            return Err(CiError::Message(
                "host socket positive IO crossed original work cutoff".into(),
            ));
        }
        client.set_write_timeout(Some(remaining))?;
        accepted.set_read_timeout(Some(remaining))?;
        let peer = rustix::net::sockopt::socket_peercred(&accepted)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if peer.pid.as_raw_nonzero().get() as u32 != std::process::id()
            || peer.uid.as_raw() != 0
            || peer.gid.as_raw() != 0
        {
            return Err(CiError::Message(
                "host socket accepted unrelated native peer".into(),
            ));
        }
        client.write_all(challenge.as_bytes())?;
        let mut bytes = vec![0; challenge.len()];
        accepted.read_exact(&mut bytes)?;
        if bytes != challenge.as_bytes() {
            return Err(CiError::Message(
                "original host socket positive changed bytes".into(),
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(CiError::Message(
                "host socket positive crossed original work cutoff".into(),
            ));
        }
        let socket = rustix::fs::fstat(owner.listener.as_ref().expect("original listener owner"))
            .map_err(|error| CiError::Message(error.to_string()))?;
        let named = std::fs::symlink_metadata(&owner.path)?;
        if !named.file_type().is_socket() || named.uid() != 0 || named.nlink() != 1 {
            return Err(CiError::Message(
                "host socket original named custody differs".into(),
            ));
        }
        owner.original = serde_json::json!({"path":owner.path,"device":named.dev(),"inode":named.ino(),"uid":named.uid(),"gid":named.gid(),"mode":named.mode(),"nlink":named.nlink(),
            "listener_device":socket.st_dev,"listener_inode":socket.st_ino,"bytes":bytes,"kind":kind,
            "peer":{"pid":peer.pid.as_raw_nonzero().get(),"birth":crate::linux_consumer_readiness::process_birth(std::process::id()).map_err(CiError::Message)?,"uid":peer.uid.as_raw(),"gid":peer.gid.as_raw()},
            "network_namespace_inode":std::fs::metadata("/proc/self/ns/net")?.ino()});
        Ok(owner)
    }
    pub fn settle(mut self, directory: &Path) -> Result<()> {
        let named = std::fs::symlink_metadata(&self.path)?;
        if named.dev() != self.original["device"].as_u64().unwrap_or(0)
            || named.ino() != self.original["inode"].as_u64().unwrap_or(0)
            || named.mode() != self.original["mode"].as_u64().unwrap_or(0) as u32
            || named.nlink() != 1
            || named.uid() != self.original["uid"].as_u64().unwrap_or(u64::MAX) as u32
            || named.gid() != self.original["gid"].as_u64().unwrap_or(u64::MAX) as u32
        {
            return Err(CiError::Message(
                "original host socket pathname was rebound".into(),
            ));
        }
        let held = self
            .parent
            .as_ref()
            .expect("original parent owner")
            .metadata()?;
        let parent = std::fs::symlink_metadata(&self.parent_path)?;
        if held.dev() != parent.dev() || held.ino() != parent.ino() {
            return Err(CiError::Message(
                "original host socket parent was rebound".into(),
            ));
        }
        std::fs::remove_file(&self.path)?;
        self.active = false;
        let absent = match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => libc::ENOENT,
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(CiError::Message(
                    "host socket remains named after native unlink".into(),
                ));
            }
        };
        memcordon_platform::linux_checked_close(
            self.listener
                .take()
                .expect("original listener owner")
                .into(),
        )?;
        memcordon_platform::linux_checked_close(
            self.parent.take().expect("original parent owner").into(),
        )?;
        super::linux_mixed_installed::retain(
            &directory.join("host-path-socket-canary.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.linux-host-path-socket-canary","revision":1,"original":self.original,
                "parent":{"path":self.parent_path,"device":held.dev(),"inode":held.ino(),"uid":held.uid(),"mode":held.mode()},
                "named_absence_errno":absent,"listener_closed":true,"parent_closed":true
            }))?,
        )?;
        Ok(())
    }
}
impl Drop for HostPathSocket {
    fn drop(&mut self) {
        if self.active
            && self.cleanup_identity.is_some_and(|identity| {
                std::fs::symlink_metadata(&self.path)
                    .is_ok_and(|named| (named.dev(), named.ino()) == identity)
            })
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Recovery enumerates only the bounded producer recipe slots. A bind interrupted
/// before native inode custody was retained stays unresolved rather than granting
/// authority to unlink a replacement at an intent's pathname.
pub(super) fn recover_host_path_sockets(mixed: &Path, deadline: std::time::Instant) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    for ordinal in 0..256 {
        if std::time::Instant::now() >= deadline {
            return Err(CiError::Message(
                "host socket recovery crossed original cleanup cutoff".into(),
            ));
        }
        let directory = mixed.join(format!("recipe-{ordinal}"));
        let intent_path = directory.join("host-path-socket-intent.json");
        match std::fs::symlink_metadata(&intent_path) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let intent_bytes =
            super::linux_mixed_installed::read_owned_resource(&intent_path, 64 * 1024)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&intent_bytes)
            .map_err(CiError::Message)?;
        let intent: serde_json::Value = serde_json::from_slice(&intent_bytes)?;
        let closed = |value: &serde_json::Value, fields: &[&str]| {
            value.as_object().is_some_and(|object| {
                object.len() == fields.len()
                    && object.keys().all(|key| fields.contains(&key.as_str()))
            })
        };
        if !closed(
            &intent,
            &["format", "revision", "kind", "path", "challenge", "parent"],
        ) || !closed(
            &intent["parent"],
            &["path", "device", "inode", "uid", "mode"],
        ) {
            return Err(CiError::Message(
                "retained host socket intent authority schema differs".into(),
            ));
        }
        let challenge = intent["challenge"]
            .as_str()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| CiError::Message("retained host socket challenge malformed".into()))?;
        let parent_path = match intent["kind"].as_str() {
            Some("host-run-socket") => Path::new("/run"),
            Some("host-temp-socket") => Path::new("/tmp"),
            _ => {
                return Err(CiError::Message(
                    "retained host socket scenario unknown".into(),
                ));
            }
        };
        let leaf = format!("memcordon-readiness-{challenge}.sock");
        let path = parent_path.join(&leaf);
        if intent["format"] != "memcordon.linux-host-path-socket-intent"
            || intent["revision"] != 1
            || intent["path"] != serde_json::to_value(&path)?
            || intent["parent"]["path"] != serde_json::to_value(parent_path)?
        {
            return Err(CiError::Message(
                "host socket recovery crossed original finite pathname scope".into(),
            ));
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent_path)?;
        let stamp = parent.metadata()?;
        if intent["parent"]["device"].as_u64() != Some(stamp.dev())
            || intent["parent"]["inode"].as_u64() != Some(stamp.ino())
            || stamp.uid() != 0
            || intent["parent"]["uid"] != 0
            || intent["parent"]["mode"].as_u64() != Some(u64::from(stamp.mode()))
            || (stamp.mode() & 0o022 != 0
                && !(parent_path == Path::new("/tmp") && stamp.mode() & 0o1000 != 0))
        {
            return Err(CiError::Message(
                "host socket original recovery parent was rebound".into(),
            ));
        }
        let present = match std::fs::symlink_metadata(&path) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
            Err(error) => return Err(error.into()),
            Ok(metadata) => Some(metadata),
        };
        if let Some(named) = present {
            let allocation_bytes = super::linux_mixed_installed::read_owned_resource(
                &directory.join("host-path-socket-allocation.json"),
                64 * 1024,
            )?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&allocation_bytes)
                .map_err(CiError::Message)?;
            let allocation: serde_json::Value = serde_json::from_slice(&allocation_bytes)?;
            if !closed(
                &allocation,
                &[
                    "format",
                    "revision",
                    "path",
                    "device",
                    "inode",
                    "uid",
                    "gid",
                    "nlink",
                    "intent_sha256",
                ],
            ) || allocation["format"] != "memcordon.linux-host-path-socket-allocation"
                || allocation["revision"] != 1
                || allocation["path"] != intent["path"]
                || allocation["intent_sha256"] != super::artifacts::checksum(&intent_bytes)
                || allocation["device"].as_u64() != Some(named.dev())
                || allocation["inode"].as_u64() != Some(named.ino())
                || allocation["uid"] != 0
                || allocation["gid"] != 0
                || allocation["nlink"] != 1
                || !named.file_type().is_socket()
                || named.uid() != 0
                || named.gid() != 0
                || named.nlink() != 1
            {
                return Err(CiError::Message(
                    "host socket recovery lacks exact original allocated native inode".into(),
                ));
            }
            rustix::fs::unlinkat(&parent, &leaf, rustix::fs::AtFlags::empty())
                .map_err(|error| CiError::Message(error.to_string()))?;
        }
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(CiError::Message(
                    "original host socket recovery did not retire its pathname".into(),
                ));
            }
        }
        let named_parent = std::fs::symlink_metadata(parent_path)?;
        if named_parent.dev() != stamp.dev()
            || named_parent.ino() != stamp.ino()
            || named_parent.uid() != stamp.uid()
            || named_parent.mode() != stamp.mode()
        {
            return Err(CiError::Message(
                "host socket parent changed during native recovery".into(),
            ));
        }
        memcordon_platform::linux_checked_close(parent.into())?;
    }
    Ok(())
}

pub struct HostOutsideFile {
    owner: File,
    parents: Vec<(PathBuf, File)>,
    mount: Option<MountedAlias>,
    leaked_path: Option<File>,
    leaked_frontend: Option<serde_json::Value>,
    pub probe: PathBuf,
    kind: String,
    original: serde_json::Value,
    bytes: Vec<u8>,
}
struct MountedAlias {
    path: std::ffi::CString,
    active: bool,
}
impl Drop for MountedAlias {
    fn drop(&mut self) {
        if self.active {
            let _ = memcordon_platform::test_support::native_test_unmount(&self.path, true);
        }
    }
}
impl HostOutsideFile {
    pub fn prepare(directory: &Path, kind: &str, challenge: &str) -> Result<Self> {
        if ![
            "symlink",
            "dotdot",
            "proc-root",
            "proc-cwd",
            "proc-fd",
            "hardlink",
            "opath",
            "mount-alias",
        ]
        .contains(&kind)
        {
            return Err(CiError::Message(
                "unknown concrete outside file canary".into(),
            ));
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(directory)?;
        let metadata = parent.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "outside canary original output parent lacks protected ownership".into(),
            ));
        }
        let root = directory.join("host-outside-canary");
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o711))?;
        let held_root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&root)?;
        let parents = vec![(directory.to_owned(), parent), (root.clone(), held_root)];
        let path = root.join("original.bin");
        let bytes = challenge.as_bytes().to_vec();
        let mut owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o444)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        owner.write_all(&bytes)?;
        owner.sync_all()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))?;
        let mut mount = None;
        let probe = match kind {
            "mount-alias" => {
                let alias = root.join("outside-mount");
                let destination = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o444)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&alias)?;
                memcordon_platform::linux_checked_close(destination.into())?;
                let source = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                    .map_err(|error| CiError::Message(error.to_string()))?;
                let destination = std::ffi::CString::new(alias.as_os_str().as_encoded_bytes())
                    .map_err(|error| CiError::Message(error.to_string()))?;
                memcordon_platform::test_support::native_test_bind_mount(&source, &destination)?;
                mount = Some(MountedAlias {
                    path: destination,
                    active: true,
                });
                alias
            }
            "opath" => path.clone(),
            "symlink" => {
                let alias = root.join("outside-symlink");
                std::os::unix::fs::symlink(&path, &alias)?;
                alias
            }
            "hardlink" => {
                let alias = root.join("outside-hardlink");
                std::fs::hard_link(&path, &alias)?;
                alias
            }
            "dotdot" => {
                let child = root.join("child");
                std::fs::create_dir(&child)?;
                child.join("../original.bin")
            }
            "proc-root" => PathBuf::from(format!("/proc/{}/root", std::process::id())).join(
                path.strip_prefix("/")
                    .map_err(|error| CiError::Message(error.to_string()))?,
            ),
            "proc-fd" => PathBuf::from(format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                owner.as_raw_fd()
            )),
            "proc-cwd" => {
                let cwd = std::env::current_dir()?;
                let mut alias = PathBuf::from(format!("/proc/{}/cwd", std::process::id()));
                for component in cwd.components() {
                    if matches!(component, std::path::Component::Normal(_)) {
                        alias.push("..");
                    }
                }
                alias.join(
                    path.strip_prefix("/")
                        .map_err(|error| CiError::Message(error.to_string()))?,
                )
            }
            _ => unreachable!(),
        };
        let actual = File::open(&probe)?;
        let metadata = owner.metadata()?;
        let resolved = actual.metadata()?;
        let alias = std::fs::symlink_metadata(&probe)?;
        let symlink_target = if alias.file_type().is_symlink() {
            Some(
                std::fs::read_link(&probe)?
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            )
        } else {
            None
        };
        let mut observed = vec![0u8; metadata.len() as usize];
        actual.read_exact_at(&mut observed, 0)?;
        if observed != bytes
            || (metadata.dev(), metadata.ino()) != (resolved.dev(), resolved.ino())
            || !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(CiError::Message(
                "host outside alias did not resolve original readable canary".into(),
            ));
        }
        memcordon_platform::linux_checked_close(actual.into())?;
        let original = serde_json::json!({"path":path.as_os_str().as_encoded_bytes(),"probe":probe.as_os_str().as_encoded_bytes(),"kind":kind,
            "device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode(),"nlink":metadata.nlink(),"length":metadata.len(),"sha256":super::artifacts::checksum(&observed),
            "controller_pid":std::process::id(),"controller_birth":crate::linux_consumer_readiness::process_birth(std::process::id()).map_err(CiError::Message)?,
            "source_descriptor":owner.as_raw_fd(),"resolved_device":resolved.dev(),"resolved_inode":resolved.ino(),"positive_bytes":observed,
            "original_cwd":std::env::current_dir()?.as_os_str().as_encoded_bytes()});
        let mut original = original;
        original["alias_native"] = serde_json::json!({"device":alias.dev(),"inode":alias.ino(),"mode":alias.mode(),"nlink":alias.nlink(),"symlink_target":symlink_target});
        let leaked_path = if kind == "opath" {
            Some(File::from(
                rustix::fs::open(
                    &path,
                    rustix::fs::OFlags::PATH
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|error| CiError::Message(error.to_string()))?,
            ))
        } else {
            None
        };
        Ok(Self {
            owner,
            parents,
            mount,
            leaked_path,
            leaked_frontend: None,
            probe,
            kind: kind.into(),
            original,
            bytes,
        })
    }
    pub fn leaked_descriptor(&self) -> Option<(i32, i32)> {
        self.leaked_path
            .as_ref()
            .map(|file| (file.as_raw_fd(), 128))
    }
    pub fn clone_leaked_descriptor(&self) -> Result<Option<(std::os::fd::OwnedFd, i32)>> {
        self.leaked_path
            .as_ref()
            .map(|file| file.try_clone().map(|file| (file.into(), 128)))
            .transpose()
            .map_err(Into::into)
    }
    pub fn observe_frontend(&mut self, pid: u32, birth: u64) -> Result<()> {
        let Some(file) = &self.leaked_path else {
            return Ok(());
        };
        let held = crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth)
            .map_err(CiError::Message)?;
        let name = format!("/proc/{pid}/fd/128");
        let original = file.metadata()?;
        let path = std::fs::read_link(&name)?;
        let actual = File::open(&name)?;
        let metadata = actual.metadata()?;
        use std::io::Read;
        let mut fdinfo = Vec::new();
        File::open(format!("/proc/{pid}/fdinfo/128"))?
            .take(4097)
            .read_to_end(&mut fdinfo)?;
        if fdinfo.len() > 4096 {
            return Err(CiError::Message(
                "actual frontend O_PATH fdinfo exceeds finite bound".into(),
            ));
        }
        if held.exited().map_err(CiError::Message)?
            || crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?
                != birth
            || (metadata.dev(), metadata.ino()) != (original.dev(), original.ino())
            || path.as_os_str().as_encoded_bytes()
                != serde_json::from_value::<Vec<u8>>(self.original["path"].clone())?
        {
            return Err(CiError::Message(
                "actual frontend did not inherit original hostile O_PATH descriptor".into(),
            ));
        }
        memcordon_platform::linux_checked_close(actual.into())?;
        self.leaked_frontend = Some(
            serde_json::json!({"frontend_pid":pid,"frontend_birth":birth,"descriptor":128,"parent_source_descriptor":file.as_raw_fd(),"path":path.as_os_str().as_encoded_bytes(),"device":metadata.dev(),"inode":metadata.ino(),"fdinfo":fdinfo}),
        );
        Ok(())
    }
    pub fn settle(self, directory: &Path) -> Result<()> {
        let metadata = self.owner.metadata()?;
        let mut bytes = vec![0u8; metadata.len() as usize];
        self.owner.read_exact_at(&mut bytes, 0)?;
        let named = File::open(&self.probe)?;
        let alias = named.metadata()?;
        let link = std::fs::symlink_metadata(&self.probe)?;
        let target = if link.file_type().is_symlink() {
            Some(
                std::fs::read_link(&self.probe)?
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            )
        } else {
            None
        };
        if self.original["alias_native"]
            != serde_json::json!({"device":link.dev(),"inode":link.ino(),"mode":link.mode(),"nlink":link.nlink(),"symlink_target":target})
        {
            return Err(CiError::Message(
                "original outside alias name was rebound".into(),
            ));
        }
        if bytes != self.bytes
            || metadata.dev() != self.original["device"].as_u64().unwrap_or(0)
            || metadata.ino() != self.original["inode"].as_u64().unwrap_or(0)
            || (alias.dev(), alias.ino()) != (metadata.dev(), metadata.ino())
            || metadata.len() != self.bytes.len() as u64
            || metadata.nlink() != self.original["nlink"].as_u64().unwrap_or(0)
        {
            return Err(CiError::Message(
                "original outside host canary changed during isolated attempt".into(),
            ));
        }
        let resolved_close = memcordon_platform::linux_checked_close(named.into());
        let owner_close = memcordon_platform::linux_checked_close(self.owner.into());
        let leaked_descriptor = if let Some(file) = self.leaked_path {
            let original = self.leaked_frontend.ok_or_else(|| {
                CiError::Message("original frontend hostile O_PATH association absent".into())
            })?;
            let closed = memcordon_platform::linux_checked_close(file.into());
            let receipt = serde_json::json!({"original":original,"closed":closed.is_ok(),"close_native_errno":closed.as_ref().err().and_then(std::io::Error::raw_os_error)});
            closed?;
            Some(receipt)
        } else {
            None
        };
        let mount = if let Some(mut mount) = self.mount {
            let outcome = memcordon_platform::test_support::native_test_unmount(&mount.path, false);
            let result = if outcome.is_ok() { 0 } else { -1 };
            let error = outcome.err();
            if error.is_none() {
                mount.active = false;
            }
            let receipt = serde_json::json!({"source":self.original["path"],"destination":self.original["probe"],"mount_flags":libc::MS_BIND,"mount_result":0,"unmount_flags":0,"unmount_result":result,"unmount_native_errno":error.as_ref().and_then(std::io::Error::raw_os_error)});
            if let Some(error) = error {
                return Err(error.into());
            }
            Some(receipt)
        } else {
            None
        };
        let mut parents = Vec::new();
        for (path, file) in self.parents {
            let held = file.metadata()?;
            let named = std::fs::symlink_metadata(&path)?;
            if !named.is_dir()
                || (held.dev(), held.ino()) != (named.dev(), named.ino())
                || held.uid() != 0
                || held.mode() & 0o022 != 0
                || held.nlink() == 0
            {
                return Err(CiError::Message(
                    "original outside canary parent was rebound".into(),
                ));
            }
            let closed = memcordon_platform::linux_checked_close(file.into());
            parents.push(serde_json::json!({"path":path.as_os_str().as_encoded_bytes(),"device":held.dev(),"inode":held.ino(),"named_device":named.dev(),"named_inode":named.ino(),"uid":held.uid(),"mode":held.mode(),"nlink":held.nlink(),"closed":closed.is_ok(),"close_native_errno":closed.as_ref().err().and_then(std::io::Error::raw_os_error)}));
            closed?;
        }
        let receipt = serde_json::json!({"format":"memcordon.linux-outside-file-canary","revision":1,"kind":self.kind,"before":self.original,
            "after":{"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode(),"nlink":metadata.nlink(),"length":metadata.len(),"bytes":bytes},
            "parents":parents,"mount":mount,"leaked_descriptor":leaked_descriptor,"resolved_close_errno":resolved_close.as_ref().err().and_then(std::io::Error::raw_os_error),"owner_close_errno":owner_close.as_ref().err().and_then(std::io::Error::raw_os_error)});
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("outside-file-canary.json"))?;
        file.write_all(&serde_json::to_vec(&receipt)?)?;
        file.sync_all()?;
        resolved_close?;
        owner_close?;
        Ok(())
    }
}
