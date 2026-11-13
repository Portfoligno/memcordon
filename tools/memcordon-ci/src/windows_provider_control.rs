//! Controller-owned root-only provider control; never peer/full-Joint authority.
#[cfg(windows)]
pub(crate) mod native {
    use crate::windows_consumer_readiness::descriptor::{self, controller_start as start};
    use crate::windows_private_custody::PrivateFixtureCustody;
    use crate::{CiError, Result};
    use memcordon_platform::test_support::{ProcessIdentity, WindowsImageProcess};
    use std::{
        fs::OpenOptions,
        io::{self, Read, Seek, SeekFrom, Write},
        os::windows::fs::OpenOptionsExt,
        sync::{Arc, Mutex},
        time::Instant,
    };

    fn live(work: Instant) -> io::Result<()> {
        if Instant::now() >= work {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "provider original work cutoff exhausted",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) struct SharedInputs {
        files: Vec<(
            std::path::PathBuf,
            Arc<crate::windows_native_files::HeldWindowsArtifact>,
            [u8; 32],
        )>,
        local: Option<(std::path::PathBuf, Arc<std::fs::File>, (u32, u64), [u8; 32])>,
    }
    #[allow(unsafe_code)] // Query-only bounded SD; relative bounds precede native validity and length accessors.
    fn security(file: &std::fs::File, work: Instant) -> io::Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        use std::os::windows::io::AsRawHandle;
        live(work)?;
        let mut words = vec![0_u64; 8192];
        let mut required = 0;
        let okay = unsafe {
            windows_sys::Win32::Security::GetKernelObjectSecurity(
                file.as_raw_handle(),
                7,
                words.as_mut_ptr().cast(),
                65536,
                &mut required,
            )
        };
        let failure = (okay == 0).then(io::Error::last_os_error);
        if let Some(error) = failure {
            return Err(error);
        }
        live(work)?;
        if required > 65536 {
            return Err(io::Error::other(
                "provider immutable security extent invalid",
            ));
        }
        // A successful zero requirement is not an extent. Reuse the native
        // length-aware relative validation order used by stream capture, then
        // measure the actual descriptor in this same initialized allocation.
        let bound = if required == 0 { 65536 } else { required };
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        let module_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
        let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
        if module.is_null() {
            return Err(io::Error::other(
                "provider relative SD validator unavailable",
            ));
        }
        live(work)?;
        let address = unsafe {
            GetProcAddress(
                module,
                c"RtlValidRelativeSecurityDescriptor".as_ptr().cast(),
            )
        }
        .ok_or_else(|| io::Error::other("provider relative SD validator unavailable"))?;
        type Validate = unsafe extern "system" fn(*mut std::ffi::c_void, u32, u32) -> u8;
        let validate: Validate = unsafe { std::mem::transmute(address) };
        let pointer = words.as_mut_ptr().cast();
        live(work)?;
        if unsafe { validate(pointer, bound, 0) } == 0 {
            return Err(io::Error::other("provider relative SD structure invalid"));
        }
        live(work)?;
        if unsafe { windows_sys::Win32::Security::IsValidSecurityDescriptor(pointer) } == 0 {
            return Err(io::Error::other("provider native SD validation failed"));
        }
        live(work)?;
        let extent = unsafe { windows_sys::Win32::Security::GetSecurityDescriptorLength(pointer) };
        live(work)?;
        if extent == 0 || extent > bound {
            return Err(io::Error::other("provider actual native SD extent invalid"));
        }
        let bytes: Vec<_> = words
            .into_iter()
            .flat_map(u64::to_ne_bytes)
            .take(extent as usize)
            .collect();
        Ok(Sha256::digest(&bytes).into())
    }
    impl SharedInputs {
        pub(crate) fn capture(
            deployment: &crate::windows_provider_projection::native::Deployment,
            work: Instant,
        ) -> Result<Self> {
            let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(work)
                .map_err(io::Error::other)?;
            let primary = Self::capture_inner(deployment, work);
            let settled = timer
                .finish()
                .map_err(io::Error::other)
                .map_err(CiError::from);
            match (primary, settled) {
                (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(error)) => Err(error),
                (Ok(inputs), Ok(())) => {
                    live(work)?;
                    Ok(inputs)
                }
            }
        }
        fn capture_inner(
            deployment: &crate::windows_provider_projection::native::Deployment,
            work: Instant,
        ) -> Result<Self> {
            let mut files = Vec::new();
            for (path, held) in deployment.shared_input_files() {
                crate::windows_native_files::verify_named_artifact(&held, &path)?;
                let hash = security(held.private_file(), work)?;
                files.push((path, held, hash));
            }
            let local = if let Some((path, held)) = deployment.shared_local_directory() {
                let id = crate::windows_native_files::native_file_identity(&held, true, &path)?;
                let hash = security(&held, work)?;
                Some((path, held, id, hash))
            } else {
                None
            };
            live(work)?;
            Ok(Self { files, local })
        }
        pub(crate) fn verify(&self, work: Instant) -> Result<()> {
            for (path, held, hash) in &self.files {
                live(work)?;
                crate::windows_native_files::verify_named_artifact(held, path)?;
                if security(held.private_file(), work)? != *hash {
                    return Err(CiError::Message(
                        "provider prelude changed original shared file security".into(),
                    ));
                }
            }
            if let Some((path, held, id, hash)) = &self.local {
                let named = OpenOptions::new()
                    .read(true)
                    .share_mode(7)
                    .custom_flags(0x0220_0000)
                    .open(path)?;
                if crate::windows_native_files::native_file_identity(&named, true, path)? != *id
                    || crate::windows_native_files::native_file_identity(held, true, path)? != *id
                    || security(held, work)? != *hash
                {
                    return Err(CiError::Message("provider prelude changed original shared local directory identity/security".into()));
                }
            }
            live(work)?;
            Ok(())
        }
    }

    pub(crate) struct DirectRoot {
        pub process: WindowsImageProcess,
        pub ready: start::ProviderDirectReady,
        core_token_sha256: [u8; 32],
        restricted: bool,
        pub descriptor: descriptor::Descriptor,
        sender: start::Sender,
        binding: start::Binding,
        pair: start::ProviderPairBinding,
    }

    pub(crate) struct RootPair {
        pub direct_custody: Arc<PrivateFixtureCustody>,
        pub shared: SharedInputs,
        pub broker: Mutex<Option<WindowsImageProcess>>,
        pub direct: Mutex<Option<DirectRoot>>,
        pub installed: Mutex<Option<(WindowsImageProcess, [u8; 32])>>,
        pub probes: Mutex<[Option<serde_json::Value>; 2]>,
    }
    impl RootPair {
        pub(crate) fn new(
            direct_custody: Arc<PrivateFixtureCustody>,
            shared: SharedInputs,
        ) -> Self {
            Self {
                direct_custody,
                shared,
                broker: Mutex::new(None),
                direct: Mutex::new(None),
                installed: Mutex::new(None),
                probes: Mutex::new([None, None]),
            }
        }
    }

    impl RootPair {
        pub(crate) fn assess(
            &self,
            comparison: &descriptor::matched::Comparison,
            providers: &[crate::windows_provider_projection_record::PrivateInput],
            readbacks: [&crate::windows_consumer_readiness::matched_control_input_record::Readback;
                2],
            installed_descriptor: &descriptor::Descriptor,
            cleanup: Instant,
        ) -> Result<RootCapture> {
            let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(cleanup)
                .map_err(io::Error::other)?;
            let primary = self.assess_inner(
                comparison,
                providers,
                readbacks,
                installed_descriptor,
                cleanup,
            );
            let settled = timer
                .finish()
                .map_err(io::Error::other)
                .map_err(CiError::from);
            match (primary, settled) {
                (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(error)) => Err(error),
                (Ok(capture), Ok(())) => {
                    live(cleanup)?;
                    Ok(capture)
                }
            }
        }
        fn assess_inner(
            &self,
            comparison: &descriptor::matched::Comparison,
            providers: &[crate::windows_provider_projection_record::PrivateInput],
            readbacks: [&crate::windows_consumer_readiness::matched_control_input_record::Readback;
                2],
            installed_descriptor: &descriptor::Descriptor,
            cleanup: Instant,
        ) -> Result<RootCapture> {
            use crate::windows_provider_projection_record::{
                BindingExpectation, observe_original_selection,
            };
            use crate::windows_readiness_policy::{
                RootPairClosure, RootPairEvidence, assess_root_pair,
            };
            let direct = self.direct.lock().map_err(|_| {
                CiError::Message("provider direct assessment ownership poisoned".into())
            })?;
            let direct = direct.as_ref().ok_or_else(|| {
                CiError::Message("provider direct assessment owner absent".into())
            })?;
            let installed = self.installed.lock().map_err(|_| {
                CiError::Message("provider installed assessment ownership poisoned".into())
            })?;
            let (installed, installed_token_sha256) = installed.as_ref().ok_or_else(|| {
                CiError::Message("provider installed assessment owner absent".into())
            })?;
            if (readbacks[0].pid, u128::from(readbacks[0].birth))
                != (direct.process.identity.pid, direct.process.identity.birth)
                || (readbacks[1].pid, u128::from(readbacks[1].birth))
                    != (installed.identity.pid, installed.identity.birth)
                || readbacks[0].descriptor_sha256 != direct.binding.descriptor_sha256
                || readbacks[1].descriptor_sha256 != direct.pair.installed_descriptor_sha256
                || readbacks[0].token_sha256 != direct.core_token_sha256
                || readbacks[1].token_sha256 != *installed_token_sha256
            {
                return Err(CiError::Message("provider bound readbacks differ from independent native root/Core observations".into()));
            }
            if !direct.process.has_exited()? || !installed.has_exited()? {
                return Err(CiError::Message(
                    "provider assessment requires actual two-lane native retirement".into(),
                ));
            }
            self.direct_custody.prove_retired(cleanup)?;
            let probes = self
                .probes
                .lock()
                .map_err(|_| CiError::Message("provider prelude witnesses poisoned".into()))?;
            if probes.iter().any(Option::is_none) {
                return Err(CiError::Message(
                    "provider root requires both validated original prelude witnesses".into(),
                ));
            }
            let observe = |descriptor: &descriptor::Descriptor,
                           expected: BindingExpectation|
             -> Result<_> {
                let path = descriptor.output_root.join("listener-call-trace.json");
                let mut bytes = Vec::new();
                OpenOptions::new()
                    .read(true)
                    .share_mode(7)
                    .custom_flags(0x0020_0000)
                    .open(path)?
                    .take(65537)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 65536 {
                    return Err(CiError::Message(
                        "provider original listener trace exceeds retained bound".into(),
                    ));
                }
                memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                    .map_err(CiError::Message)?;
                observe_original_selection(&serde_json::from_slice(&bytes)?, &expected, providers)
                    .map_err(CiError::Message)
            };
            let (direct_selection, installed_selection) =
                if comparison.outcome == descriptor::matched::ComparisonOutcome::ScopeSuccess {
                    let challenge_sha256 = start::descriptor_digest(&direct.binding.challenge);
                    (
                        Some(observe(
                            &direct.descriptor,
                            BindingExpectation {
                                pid: direct.process.identity.pid,
                                birth: u64::try_from(direct.process.identity.birth)
                                    .map_err(io::Error::other)?,
                                descriptor_sha256: direct.binding.descriptor_sha256,
                                challenge_sha256,
                                token_sha256: readbacks[0].partial_token_sha256,
                                peer: false,
                            },
                        )?),
                        Some(observe(
                            installed_descriptor,
                            BindingExpectation {
                                pid: installed.identity.pid,
                                birth: u64::try_from(installed.identity.birth)
                                    .map_err(io::Error::other)?,
                                descriptor_sha256: direct.pair.installed_descriptor_sha256,
                                challenge_sha256,
                                token_sha256: readbacks[1].partial_token_sha256,
                                peer: false,
                            },
                        )?),
                    )
                } else {
                    (None, None)
                };
            let assessment = assess_root_pair(RootPairEvidence {
                listener: comparison,
                direct_selection: direct_selection.as_ref(),
                installed_selection: installed_selection.as_ref(),
                closure: RootPairClosure::Settled,
            });
            let report = serde_json::json!({"format":"memcordon.windows-provider-root-selection","revision":1,"scope":"provider-listener-selection","assessment":assessment.as_ref().ok(),"contract_validation_error":assessment.as_ref().err(),"comparison":comparison,"configured_provider_inputs":providers,"provider_coverage":"observed-original-returns-only; uninvoked inputs unmeasured","host_file_identity":"not established by mapped-path text","direct_selection":direct_selection,"installed_selection":installed_selection});
            let mut report = report;
            let fields = report.as_object_mut().expect("closed root observation");
            fields.insert(
                "selected_direct_core_sha256".into(),
                serde_json::to_value(direct.ready.selected_token_sha256)?,
            );
            fields.insert(
                "selected_hash_domain".into(),
                "windows-caller-token-envelope-v1".into(),
            );
            fields.insert(
                "original_call_hash_domain".into(),
                "consumer-readiness-token-observation-json-v1".into(),
            );
            fields.insert("original_call_hash_source".into(), "actual process readback bound to original native PID/birth/descriptor; independent full Core hash verified".into());
            fields.insert(
                "direct_original_call_token_sha256".into(),
                serde_json::to_value(readbacks[0].partial_token_sha256)?,
            );
            fields.insert(
                "installed_original_call_token_sha256".into(),
                serde_json::to_value(readbacks[1].partial_token_sha256)?,
            );
            fields.insert(
                "direct_prelude_witness".into(),
                probes[0].clone().expect("validated direct witness"),
            );
            fields.insert(
                "installed_prelude_witness".into(),
                probes[1].clone().expect("validated installed witness"),
            );
            if serde_json::to_vec(&report)?.len() > 256 * 1024 {
                return Err(CiError::Message(
                    "provider paired root report exceeds 256 KiB without truncation".into(),
                ));
            }
            Ok(RootCapture {
                report,
                validation: assessment.map(|_| ()).map_err(CiError::Message),
            })
        }
    }

    pub(crate) struct RootCapture {
        pub report: serde_json::Value,
        pub validation: Result<()>,
    }

    pub(crate) struct Admission<'a> {
        pub plan: &'a descriptor::matched_plan::Plan,
        pub broker: &'a WindowsImageProcess,
        pub installed: &'a WindowsImageProcess,
        pub installed_binding: &'a start::Binding,
        pub direct_custody: &'a Arc<PrivateFixtureCustody>,
        pub registry: &'a Arc<Mutex<memcordon_testkit::WindowsWinsockRegistryProjection>>,
        pub work: Instant,
    }

    impl DirectRoot {
        pub(crate) fn wait_prelude(
            &self,
            descriptor: &descriptor::Descriptor,
            shared: &SharedInputs,
            work: Instant,
        ) -> Result<serde_json::Value> {
            wait_prelude(
                descriptor,
                &self.process,
                &self.binding,
                shared,
                self.restricted,
                work,
            )
        }
        pub(crate) fn admit(input: Admission<'_>) -> Result<Self> {
            let work = input.work;
            let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(work)
                .map_err(io::Error::other)?;
            let primary = Self::admit_inner(input);
            let settled = timer
                .finish()
                .map_err(io::Error::other)
                .map_err(CiError::from);
            match (primary, settled) {
                (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(secondary)) => Err(secondary),
                (Ok(root), Ok(())) => {
                    live(work)?;
                    Ok(root)
                }
            }
        }
        fn admit_inner(input: Admission<'_>) -> Result<Self> {
            live(input.work)?;
            let broker = start::BrokerIdentity {
                pid: input.broker.identity.pid,
                birth: u64::try_from(input.broker.identity.birth).map_err(io::Error::other)?,
            };
            let mut direct_bytes = Vec::new();
            OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x0020_0000)
                .open(&input.plan.direct_descriptor)?
                .take((descriptor::MAX_DESCRIPTOR_BYTES + 1) as u64)
                .read_to_end(&mut direct_bytes)?;
            if direct_bytes.len() > descriptor::MAX_DESCRIPTOR_BYTES {
                return Err(CiError::Message(
                    "provider direct descriptor exceeds bound".into(),
                ));
            }
            let direct_descriptor =
                descriptor::Descriptor::parse(&direct_bytes).map_err(CiError::Message)?;
            let expected = start::ProviderReadyBinding {
                broker,
                pair_sha256: input.plan.pair_sha256,
                input_sha256: input.plan.input_sha256,
                direct_descriptor_sha256: start::descriptor_digest(&direct_bytes),
                qpc_frequency: input.plan.work_clock.qpc_frequency,
                cutoff_qpc: input.plan.work_clock.work_cutoff_qpc,
            };
            let mut file = loop {
                live(input.work)?;
                if input.broker.has_exited()? {
                    return Err(CiError::Message(
                        "provider original broker retired before Ready publication".into(),
                    ));
                }
                match OpenOptions::new()
                    .read(true)
                    .share_mode(3)
                    .custom_flags(0x0020_0000)
                    .open(input.plan.record.with_extension("direct-recipient.bin"))
                {
                    Ok(file) => break file,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        std::thread::sleep(std::time::Duration::from_millis(1))
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let ready = loop {
                live(input.work)?;
                if input.broker.has_exited()? {
                    return Err(CiError::Message(
                        "provider broker retired before complete Ready publication".into(),
                    ));
                }
                let metadata = memcordon_testkit::windows_held_file_metadata(&file)?;
                if metadata.length > (start::MAX_PROVIDER_READY_BYTES + 44) as u64
                    || metadata.attributes & (0x400 | 0x10) != 0
                    || metadata.links != 1
                {
                    return Err(CiError::Message(
                        "provider private Ready object is not a bounded original file".into(),
                    ));
                }
                file.seek(SeekFrom::Start(0))?;
                let mut bytes = Vec::new();
                (&mut file)
                    .take((start::MAX_PROVIDER_READY_BYTES + 45) as u64)
                    .read_to_end(&mut bytes)?;
                if let Some(ready) = start::ProviderDirectReady::from_committed_prefix(&bytes)? {
                    break ready;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            };
            ready.validate(&expected)?;
            let process = input.direct_custody.admit_direct_root(
                input.broker,
                ready.original_process_reference,
                ProcessIdentity {
                    pid: ready.direct.pid,
                    birth: u128::from(ready.direct.birth),
                },
                &ready.selected_token_sha256,
                input.work,
            )?;
            let core_token_sha256 = start::descriptor_digest(&serde_json::to_vec(
                &process.original_token_envelope(input.work)?,
            )?);
            if core_token_sha256 != ready.selected_token_sha256 {
                return Err(CiError::Message(
                    "provider direct native Core token changed after admission".into(),
                ));
            }
            // The descriptor scalar identified only an entry in the original
            // held broker's table; the admitted native process is the authority.
            let mut registry = input.registry.lock().map_err(|_| {
                CiError::Message("provider original registry ownership poisoned".into())
            })?;
            let capability = start::Capability {
                version: 1,
                handle: registry.duplicate_into(&process, input.work)?,
                manifest_sha256: registry.declaration().sha256,
            };
            drop(registry);
            let sender = start::Sender::with_registry(capability, false)
                .with_directories(
                    input.direct_custody.duplicate_into(&process, input.work)?,
                    input
                        .direct_custody
                        .binding()
                        .directory_expectation()
                        .map_err(CiError::Message)?,
                )?
                .provider_root()?;
            let binding = start::Binding {
                challenge: input.installed_binding.challenge.clone(),
                descriptor_sha256: expected.direct_descriptor_sha256,
                pid: process.identity.pid,
                birth: u64::try_from(process.identity.birth).map_err(io::Error::other)?,
            };
            let pair = start::ProviderPairBinding {
                broker,
                direct: ready.direct,
                installed: start::BrokerIdentity {
                    pid: input.installed.identity.pid,
                    birth: u64::try_from(input.installed.identity.birth)
                        .map_err(io::Error::other)?,
                },
                pair_sha256: input.plan.pair_sha256,
                input_sha256: input.plan.input_sha256,
                direct_descriptor_sha256: binding.descriptor_sha256,
                installed_descriptor_sha256: input.installed_binding.descriptor_sha256,
                qpc_frequency: expected.qpc_frequency,
                cutoff_qpc: expected.cutoff_qpc,
            };
            live(input.work)?;
            Ok(Self {
                process,
                ready,
                core_token_sha256,
                restricted: input.plan.restricted,
                descriptor: direct_descriptor,
                sender,
                binding,
                pair,
            })
        }

        pub(crate) fn start_direct(
            &mut self,
            writer: &mut impl Write,
            work: Instant,
        ) -> io::Result<()> {
            let mut direct_frame = Vec::new();
            self.sender.send(
                &mut direct_frame,
                &self.binding,
                start::Phase::Start,
                || live(work),
            )?;
            self.write(
                writer,
                start::ProviderLanePhase::DirectAdmitted,
                direct_frame,
                Vec::new(),
                work,
            )
        }
        pub(crate) fn start_installed(
            &self,
            writer: &mut impl Write,
            sender: &mut start::Sender,
            binding: &start::Binding,
            work: Instant,
        ) -> io::Result<()> {
            let mut installed_frame = Vec::new();
            sender.send(&mut installed_frame, binding, start::Phase::Start, || {
                live(work)
            })?;
            self.write(
                writer,
                start::ProviderLanePhase::StartInstalled,
                Vec::new(),
                installed_frame,
                work,
            )
        }
        pub(crate) fn release_originals(
            &mut self,
            writer: &mut impl Write,
            sender: &mut start::Sender,
            binding: &start::Binding,
            work: Instant,
        ) -> io::Result<()> {
            let mut direct_frame = Vec::new();
            let mut installed_frame = Vec::new();
            self.sender.send(
                &mut direct_frame,
                &self.binding,
                start::Phase::ProviderPreludeRelease,
                || live(work),
            )?;
            sender.send(
                &mut installed_frame,
                binding,
                start::Phase::ProviderPreludeRelease,
                || live(work),
            )?;
            self.write(
                writer,
                start::ProviderLanePhase::ReleaseOriginal,
                direct_frame,
                installed_frame,
                work,
            )
        }
        fn write(
            &self,
            writer: &mut impl Write,
            phase: start::ProviderLanePhase,
            direct_frame: Vec<u8>,
            installed_frame: Vec<u8>,
            work: Instant,
        ) -> io::Result<()> {
            start::ProviderLaneFrame {
                revision: 1,
                scope: start::ProviderControlScope::ListenerSelection,
                binding: self.pair.clone(),
                phase,
                direct_frame,
                installed_frame,
            }
            .write(writer, || live(work))
        }
    }

    pub(crate) fn wait_prelude(
        descriptor: &descriptor::Descriptor,
        process: &WindowsImageProcess,
        binding: &start::Binding,
        shared: &SharedInputs,
        restricted: bool,
        work: Instant,
    ) -> Result<serde_json::Value> {
        loop {
            live(work)?;
            if process.identity.pid != binding.pid
                || process.identity.birth != u128::from(binding.birth)
                || process.has_exited()?
            {
                return Err(CiError::Message(
                    "provider original lane retired before prelude barrier".into(),
                ));
            }
            match OpenOptions::new()
                .read(true)
                .share_mode(7)
                .custom_flags(0x0020_0000)
                .open(&descriptor.transcript)
            {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
                    if bytes.len() > 1024 * 1024 {
                        return Err(CiError::Message(
                            "provider live transcript exceeds bound".into(),
                        ));
                    }
                    if crate::windows_consumer_readiness::provider_prelude_complete(
                        &bytes, binding,
                    )? {
                        use std::os::windows::ffi::OsStrExt;
                        let mut probes = Vec::new();
                        OpenOptions::new()
                            .read(true)
                            .share_mode(7)
                            .custom_flags(0x0020_0000)
                            .open(descriptor.output_root.join("provider-input-probes.json"))?
                            .take(16385)
                            .read_to_end(&mut probes)?;
                        if probes.len() > 16384 {
                            return Err(CiError::Message(
                                "provider original prelude record exceeds 16 KiB".into(),
                            ));
                        }
                        memcordon_core::canonical_json::reject_duplicate_json_keys(&probes)
                            .map_err(CiError::Message)?;
                        let paths: Vec<_> = descriptor
                            .provider_input_paths
                            .iter()
                            .map(|path| {
                                crate::windows_causal_acceptance::sha256(
                                    &path
                                        .as_os_str()
                                        .encode_wide()
                                        .flat_map(u16::to_le_bytes)
                                        .collect::<Vec<_>>(),
                                )
                            })
                            .collect();
                        let file_layout = descriptor
                            .provider_input_binding
                            .as_ref()
                            .ok_or_else(|| {
                                CiError::Message("provider original layout binding absent".into())
                            })?
                            .file_layout();
                        let witness: serde_json::Value = serde_json::from_slice(&probes)?;
                        crate::windows_provider_projection_record::mutation_witness_for_layout(
                            &witness,
                            binding.pid,
                            false,
                            restricted,
                            &paths,
                            file_layout,
                        )
                        .map_err(CiError::Message)?;
                        shared.verify(work)?;
                        if process.has_exited()? {
                            return Err(CiError::Message(
                                "provider original lane retired during shared-input verification"
                                    .into(),
                            ));
                        }
                        live(work)?;
                        return Ok(witness);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
