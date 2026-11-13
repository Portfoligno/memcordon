//! Test-only native observations, never a verdict or product-stage receipt.
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub pid: u32,
    pub birth: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sample {
    pub identity: Identity,
    pub status: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixtureSample {
    pub process: Sample,
    pub parent_pid: u32,
    pub image_matches: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    Deadline,
    CliExited,
    Ambiguous,
    IdentityMismatch,
    QueryUnavailable {
        operation: &'static str,
        native_code: Option<i32>,
    },
    #[cfg(windows)]
    ObserverBusy,
    #[cfg(windows)]
    ObserverPending,
    #[cfg(windows)]
    ObservationCaptured,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverState {
    NotStarted,
    Pending,
    QueryReferencesClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Unknown,
    ObservedFixtureLiveWhileCliLive,
    ObservedFixtureExitedWhileCliLive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub cli: Option<Identity>,
    pub cli_status: Option<u32>,
    pub fixture: Option<Identity>,
    pub fixture_status: Option<u32>,
    pub phase: Phase,
    pub observed_at_ms: Option<u128>,
    pub discovery_passes: u8,
    pub stop: Option<Stop>,
    #[cfg(windows)]
    pub observer_state: ObserverState,
    #[cfg(windows)]
    pub setup_micros: u128,
    #[cfg(windows)]
    pub duplication_micros: Option<u64>,
}
impl Default for Observation {
    fn default() -> Self {
        Self {
            cli: None,
            cli_status: None,
            fixture: None,
            fixture_status: None,
            phase: Phase::Unknown,
            observed_at_ms: None,
            discovery_passes: 0,
            stop: None,
            #[cfg(windows)]
            observer_state: ObserverState::NotStarted,
            #[cfg(windows)]
            setup_micros: 0,
            #[cfg(windows)]
            duplication_micros: None,
        }
    }
}

/// A late result cannot mint evidence, including when the operation started in
/// time. Native owners returned late are dropped rather than retained as facts.
pub fn guarded_query<T>(
    cutoff: Instant,
    query: impl FnOnce() -> Result<T, Stop>,
) -> Result<T, Stop> {
    if Instant::now() >= cutoff {
        return Err(Stop::Deadline);
    }
    let result = query();
    if Instant::now() >= cutoff {
        return Err(Stop::Deadline);
    }
    result
}

pub fn validate_held(expected: Identity, actual: Sample) -> Result<Sample, Stop> {
    if expected.pid == 0 || expected.birth == 0 || actual.identity != expected {
        return Err(Stop::IdentityMismatch);
    }
    Ok(actual)
}

/// Both liveness and fixture status must be observed before the same cutoff.
/// A miss is not prelaunch proof; an exited fixture proves neither cleanup nor
/// report delivery nor successful execution of its application body.
pub fn record_fixture(
    observation: &mut Observation,
    cli: Identity,
    fixture: FixtureSample,
    cli_after: Sample,
    at_ms: u128,
) -> Result<(), Stop> {
    let cli_after = validate_held(cli, cli_after)?;
    if cli_after.status.is_some() {
        return Err(Stop::CliExited);
    }
    if !fixture.image_matches
        || fixture.parent_pid != cli.pid
        || fixture.process.identity.pid == cli.pid
        || fixture.process.identity.pid == 0
        || fixture.process.identity.birth < cli.birth
    {
        return Err(Stop::IdentityMismatch);
    }
    if observation
        .fixture
        .is_some_and(|held| held != fixture.process.identity)
    {
        return Err(Stop::Ambiguous);
    }
    observation.cli = Some(cli);
    observation.fixture = Some(fixture.process.identity);
    observation.fixture_status = fixture.process.status;
    observation.phase = if fixture.process.status.is_some() {
        Phase::ObservedFixtureExitedWhileCliLive
    } else {
        Phase::ObservedFixtureLiveWhileCliLive
    };
    observation.observed_at_ms = Some(at_ms);
    Ok(())
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        io,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::Path,
        process::{Child, Command},
        sync::{
            Arc, Mutex, OnceLock,
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc,
        },
        time::Duration,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Globalization::{CSTR_EQUAL, CompareStringOrdinal},
        System::{Diagnostics::ToolHelp::*, Threading::*},
    };

    // These references cannot terminate, duplicate into, or modify a process.
    struct Held {
        identity: Identity,
        handle: OwnedHandle,
    }
    fn unavailable(operation: &'static str) -> Stop {
        Stop::QueryUnavailable {
            operation,
            native_code: io::Error::last_os_error().raw_os_error(),
        }
    }

    fn identity(handle: HANDLE, cutoff: Instant) -> Result<Identity, Stop> {
        let pid = guarded_query(cutoff, || {
            // SAFETY: every caller retains the queryable process reference.
            let pid = unsafe { GetProcessId(handle) };
            if pid == 0 {
                Err(unavailable("GetProcessId"))
            } else {
                Ok(pid)
            }
        })?;
        guarded_query(cutoff, || {
            let (mut creation, mut exit, mut kernel, mut user) = (
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
            );
            // SAFETY: same retained reference and initialized output structures.
            if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }
                == 0
            {
                return Err(unavailable("GetProcessTimes"));
            }
            let birth =
                (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
            if birth == 0 {
                return Err(Stop::IdentityMismatch);
            }
            Ok(Identity { pid, birth })
        })
    }
    fn exit_status(held: &Held, cutoff: Instant) -> Result<Option<u32>, Stop> {
        let status = guarded_query(cutoff, || {
            // SAFETY: zero wait polls only this original synchronization reference.
            match unsafe { WaitForSingleObject(held.handle.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => Ok(false),
                WAIT_OBJECT_0 => Ok(true),
                _ => Err(unavailable("WaitForSingleObject")),
            }
        })?;
        Ok(if status {
            Some(guarded_query(cutoff, || {
                let mut code = 0;
                // SAFETY: initialized output and this same retained process.
                if unsafe { GetExitCodeProcess(held.handle.as_raw_handle(), &mut code) } == 0 {
                    Err(unavailable("GetExitCodeProcess"))
                } else {
                    Ok(code)
                }
            })?)
        } else {
            None
        })
    }
    fn sample(held: &Held, cutoff: Instant) -> Result<Sample, Stop> {
        let actual = identity(held.handle.as_raw_handle(), cutoff)?;
        let status = exit_status(held, cutoff)?;
        validate_held(
            held.identity,
            Sample {
                identity: actual,
                status,
            },
        )
    }
    struct OriginalReference {
        pid: u32,
        handle: OwnedHandle,
    }
    fn original_cli(child: &Child, cutoff: Instant) -> Result<OriginalReference, Stop> {
        let handle = guarded_query(cutoff, || {
            let mut duplicate = std::ptr::null_mut();
            // SAFETY: borrow the returned Child, reducing access on a local,
            // non-inheritable duplicate. No PID is reopened.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    child.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut duplicate,
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    0,
                )
            } == 0
            {
                return Err(unavailable("DuplicateHandle(original CLI)"));
            }
            // SAFETY: successful duplication transfers this one reference.
            Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
        })?;
        Ok(OriginalReference {
            pid: child.id(),
            handle,
        })
    }
    fn bind_original(reference: OriginalReference, cutoff: Instant) -> Result<Held, Stop> {
        let identity = identity(reference.handle.as_raw_handle(), cutoff)?;
        if identity.pid != reference.pid {
            return Err(Stop::IdentityMismatch);
        }
        Ok(Held {
            identity,
            handle: reference.handle,
        })
    }
    fn parent(held: &Held, cutoff: Instant) -> Result<u32, Stop> {
        #[repr(C)]
        struct Basic {
            reserved1: usize,
            peb: usize,
            reserved2: [usize; 2],
            pid: usize,
            parent: usize,
        }
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationProcess(
                process: HANDLE,
                class: u32,
                data: *mut std::ffi::c_void,
                bytes: u32,
                returned: *mut u32,
            ) -> i32;
        }
        guarded_query(cutoff, || {
            let mut data = Basic {
                reserved1: 0,
                peb: 0,
                reserved2: [0; 2],
                pid: 0,
                parent: 0,
            };
            let mut returned = 0;
            // SAFETY: class0 writes the complete initialized native-width layout.
            let code = unsafe {
                NtQueryInformationProcess(
                    held.handle.as_raw_handle(),
                    0,
                    (&mut data as *mut Basic).cast(),
                    std::mem::size_of::<Basic>() as u32,
                    &mut returned,
                )
            };
            if code < 0 {
                return Err(Stop::QueryUnavailable {
                    operation: "NtQueryInformationProcess(parent)",
                    native_code: Some(code),
                });
            }
            if returned as usize != std::mem::size_of::<Basic>()
                || data.pid != held.identity.pid as usize
            {
                return Err(Stop::IdentityMismatch);
            }
            u32::try_from(data.parent).map_err(|_| Stop::IdentityMismatch)
        })
    }
    fn same_path(left: &[u16], right: &[u16], cutoff: Instant) -> Result<bool, Stop> {
        guarded_query(cutoff, || {
            let l = i32::try_from(left.len()).map_err(|_| Stop::IdentityMismatch)?;
            let r = i32::try_from(right.len()).map_err(|_| Stop::IdentityMismatch)?;
            // SAFETY: both exact UTF-16 slices remain borrowed; no normalization.
            let result = unsafe { CompareStringOrdinal(left.as_ptr(), l, right.as_ptr(), r, 1) };
            if result == 0 {
                Err(unavailable("CompareStringOrdinal(image)"))
            } else {
                Ok(result == CSTR_EQUAL)
            }
        })
    }
    fn image(held: &Held, expected: &[u16], cutoff: Instant) -> Result<bool, Stop> {
        let units = guarded_query(cutoff, || {
            let mut units = vec![0u16; 32768];
            let mut length = units.len() as u32;
            // SAFETY: same held queryable process and bounded writable output.
            if unsafe {
                QueryFullProcessImageNameW(
                    held.handle.as_raw_handle(),
                    0,
                    units.as_mut_ptr(),
                    &mut length,
                )
            } == 0
            {
                return Err(unavailable("QueryFullProcessImageNameW(fixture)"));
            }
            units.truncate(length as usize);
            Ok(units)
        })?;
        same_path(&units, expected, cutoff)
    }
    fn discover(
        cli: &Held,
        fixture: &Path,
        cutoff: Instant,
        observation: &mut Observation,
    ) -> Result<Option<Held>, Stop> {
        let expected: Vec<_> = fixture.as_os_str().encode_wide().collect();
        let name: Vec<_> = fixture
            .file_name()
            .ok_or(Stop::IdentityMismatch)?
            .encode_wide()
            .collect();
        let snapshot = guarded_query(cutoff, || {
            // SAFETY: read-only process snapshot, transferred to a local owner.
            let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
            if raw == INVALID_HANDLE_VALUE {
                Err(unavailable("CreateToolhelp32Snapshot"))
            } else {
                Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
            }
        })?;
        // SAFETY: the documented enumeration output accepts a zeroed layout
        // with its native byte size set before the first call.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut first = true;
        let mut selected = None;
        loop {
            if let Some(status) = exit_status(cli, cutoff)? {
                observation.cli_status = Some(status);
                return Err(Stop::CliExited);
            }
            let found = guarded_query(cutoff, || {
                // SAFETY: same snapshot and initialized exact-sized output.
                let found = unsafe {
                    if first {
                        Process32FirstW(snapshot.as_raw_handle(), &mut entry)
                    } else {
                        Process32NextW(snapshot.as_raw_handle(), &mut entry)
                    }
                };
                if found != 0 {
                    Ok(true)
                } else if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                    Ok(false)
                } else {
                    Err(unavailable("Process32First/NextW"))
                }
            })?;
            first = false;
            if !found {
                break;
            }
            let end = entry
                .szExeFile
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(entry.szExeFile.len());
            if entry.th32ParentProcessID != cli.identity.pid
                || !same_path(&entry.szExeFile[..end], &name, cutoff)?
            {
                continue;
            }
            let handle = guarded_query(cutoff, || {
                // SAFETY: query-only reference; native image/birth/parent follow.
                let raw = unsafe {
                    OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                        0,
                        entry.th32ProcessID,
                    )
                };
                if raw.is_null() {
                    Err(unavailable("OpenProcess(fixture candidate)"))
                } else {
                    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
                }
            })?;
            let identity = identity(handle.as_raw_handle(), cutoff)?;
            let held = Held { identity, handle };
            if held.identity.pid != entry.th32ProcessID
                || held.identity.birth < cli.identity.birth
                || parent(&held, cutoff)? != cli.identity.pid
                || !image(&held, &expected, cutoff)?
            {
                return Err(Stop::IdentityMismatch);
            }
            if selected.is_some() {
                return Err(Stop::Ambiguous);
            }
            selected = Some(held);
        }
        Ok(selected)
    }
    fn observe(
        cli: Held,
        fixture: &Path,
        cutoff: Instant,
        started: Instant,
        observation: &mut Observation,
        publisher: &Samples,
    ) -> Result<(), Stop> {
        observation.cli = Some(cli.identity);
        let mut target = None;
        loop {
            if let Some(status) = sample(&cli, cutoff)?.status {
                observation.cli_status = Some(status);
                return Err(Stop::CliExited);
            }
            if target.is_none() && observation.discovery_passes < 8 {
                observation.discovery_passes += 1;
                target = discover(&cli, fixture, cutoff, observation)?;
            }
            if let Some(target) = &target {
                let process = sample(target, cutoff)?;
                let after = sample(&cli, cutoff)?;
                if let Some(status) = after.status {
                    observation.cli_status = Some(status);
                    return Err(Stop::CliExited);
                }
                let mut recorded = observation.clone();
                guarded_query(cutoff, || {
                    record_fixture(
                        &mut recorded,
                        cli.identity,
                        FixtureSample {
                            process,
                            parent_pid: cli.identity.pid,
                            image_matches: true,
                        },
                        after,
                        started.elapsed().as_millis(),
                    )
                })?;
                *observation = recorded;
                publisher.publish(observation, cutoff);
                if observation.fixture_status.is_some() {
                    return Ok(());
                }
            }
            guarded_query(cutoff, || {
                let remaining = cutoff
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(10));
                // SAFETY: bounded wait only on the original CLI, waking on exit.
                match unsafe {
                    WaitForSingleObject(cli.handle.as_raw_handle(), remaining.as_millis() as u32)
                } {
                    // The next guarded same-owner sample records its native
                    // status without any further wait or discovery.
                    WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(()),
                    _ => Err(unavailable("WaitForSingleObject(CLI observation)")),
                }
            })?;
        }
    }

    #[derive(Default)]
    struct Published {
        value: OnceLock<Observation>,
        valid: AtomicBool,
    }
    impl Published {
        fn publish(&self, value: &Observation, cutoff: Instant) {
            if Instant::now() >= cutoff || self.value.get().is_some() {
                return;
            }
            // Only this one worker writes each cell. Readers never initialize,
            // wait on, or lock a cell. A late store remains ineligible.
            if self.value.set(value.clone()).is_ok() && Instant::now() < cutoff {
                self.valid.store(true, Ordering::Release);
            }
        }
        fn get(&self) -> Option<&Observation> {
            self.valid
                .load(Ordering::Acquire)
                .then(|| self.value.get())
                .flatten()
        }
    }
    #[derive(Default)]
    struct Samples {
        identity: Published,
        live: Published,
        exited: Published,
        stopped: Published,
        references_closed: AtomicBool,
        duplication_micros: AtomicU64,
    }
    impl Samples {
        fn publish(&self, value: &Observation, cutoff: Instant) {
            let cell = if value.stop.is_some() {
                &self.stopped
            } else {
                match value.phase {
                    Phase::Unknown => &self.identity,
                    Phase::ObservedFixtureLiveWhileCliLive => &self.live,
                    Phase::ObservedFixtureExitedWhileCliLive => &self.exited,
                }
            };
            cell.publish(value, cutoff);
        }
    }
    // This guard is declared before all query references and the receive
    // closure. Publication therefore follows their destruction, including on
    // unwind; it does not assert that a product process retired.
    struct QueryReferencesClosed(Arc<Samples>);
    impl Drop for QueryReferencesClosed {
        fn drop(&mut self) {
            self.0.references_closed.store(true, Ordering::Release);
        }
    }
    struct Pending {
        worker: std::thread::JoinHandle<()>,
        samples: Arc<Samples>,
    }

    /// One pending diagnostic worker, independent of the command's ownership.
    /// The mutex is try-locked only during setup. No result/capture/cleanup
    /// path waits for a worker or takes this lock.
    #[derive(Default)]
    pub struct Observer {
        pending: Mutex<Option<Pending>>,
    }
    pub struct Monitor {
        samples: Option<Arc<Samples>>,
        unavailable: Option<Stop>,
        cutoff: Instant,
        setup_micros: u128,
    }
    impl Monitor {
        /// Scalar reads only: an in-flight diagnostic cannot gate a verdict.
        pub fn snapshot(&self) -> Observation {
            let Some(samples) = &self.samples else {
                return Observation {
                    stop: self.unavailable,
                    setup_micros: self.setup_micros,
                    ..Observation::default()
                };
            };
            let mut value = samples
                .exited
                .get()
                .or_else(|| samples.live.get())
                .or_else(|| samples.stopped.get())
                .or_else(|| samples.identity.get())
                .cloned()
                .unwrap_or_default();
            if let Some(stopped) = samples.stopped.get() {
                value.stop = stopped.stop;
                value.cli_status = stopped.cli_status;
            }
            let closed = samples.references_closed.load(Ordering::Acquire);
            value.observer_state = if closed {
                ObserverState::QueryReferencesClosed
            } else {
                ObserverState::Pending
            };
            if value.stop.is_none() {
                value.stop = Some(if Instant::now() >= self.cutoff {
                    Stop::Deadline
                } else if closed {
                    Stop::QueryUnavailable {
                        operation: "observer ended without final sample",
                        native_code: None,
                    }
                } else {
                    Stop::ObserverPending
                });
            }
            value.setup_micros = self.setup_micros;
            let duplication = samples.duplication_micros.load(Ordering::Acquire);
            value.duplication_micros = (duplication != u64::MAX).then_some(duplication);
            value
        }
    }
    impl Observer {
        // Owning parameters and locals are destroyed before this call returns
        // (also on unwind), so its caller may then publish reference closure.
        fn query_worker(
            receiver: mpsc::Receiver<Result<OriginalReference, Stop>>,
            after_bind: impl FnOnce(),
            samples: &Samples,
            fixture: &Path,
            cutoff: Instant,
            started: Instant,
        ) {
            let mut value = Observation::default();
            let work = (|| -> Result<(), Stop> {
                let input = receiver
                    .recv_timeout(cutoff.saturating_duration_since(Instant::now()))
                    .map_err(|_| Stop::Deadline)??;
                let cli = bind_original(input, cutoff)?;
                value.cli = Some(cli.identity);
                samples.publish(&value, cutoff);
                guarded_query(cutoff, || {
                    after_bind();
                    Ok(())
                })?;
                observe(cli, fixture, cutoff, started, &mut value, samples)
            })();
            value.stop = Some(work.err().unwrap_or(Stop::ObservationCaptured));
            samples.publish(&value, cutoff);
            drop(receiver);
        }

        pub fn global() -> &'static Self {
            static OBSERVER: OnceLock<Observer> = OnceLock::new();
            OBSERVER.get_or_init(Self::default)
        }

        /// `after_bind` is trusted test diagnostic work, not a process factory.
        /// Tests may keep it in flight to prove verdict independence. It never
        /// owns the original Child, its pipes, or its Job.
        pub fn run(
            &self,
            command: Command,
            fixture: &Path,
            cutoff: Instant,
            after_bind: impl FnOnce() + Send + 'static,
        ) -> (
            Result<memcordon_testkit::ObservedOutput, memcordon_testkit::ProcessTestError>,
            Monitor,
        ) {
            let started = Instant::now();
            let samples = Arc::new(Samples {
                duplication_micros: AtomicU64::new(u64::MAX),
                ..Samples::default()
            });
            let (sender, receiver) = mpsc::sync_channel(1);
            let fixture = fixture.to_owned();
            let worker_samples = Arc::clone(&samples);
            let start_worker = (|| -> Result<(), Stop> {
                if Instant::now() >= cutoff {
                    return Err(Stop::Deadline);
                }
                let mut slot = self.pending.try_lock().map_err(|_| Stop::ObserverBusy)?;
                if let Some(previous) = slot.as_ref() {
                    // This is a nonblocking retirement check of OUR observer
                    // thread, never another CLI/fixture query after its cutoff.
                    // The slot is not reusable until the OS thread terminated.
                    let ended = unsafe { WaitForSingleObject(previous.worker.as_raw_handle(), 0) };
                    if ended != WAIT_OBJECT_0
                        || !previous.samples.references_closed.load(Ordering::Acquire)
                    {
                        return Err(Stop::ObserverBusy);
                    }
                    // Drop closes its thread reference; it never joins.
                    drop(slot.take());
                }
                let worker = std::thread::Builder::new()
                    .spawn(move || {
                        let _closed = QueryReferencesClosed(Arc::clone(&worker_samples));
                        Self::query_worker(
                            receiver,
                            after_bind,
                            &worker_samples,
                            &fixture,
                            cutoff,
                            started,
                        );
                    })
                    .map_err(|error| Stop::QueryUnavailable {
                        operation: "spawn diagnostic worker",
                        native_code: error.raw_os_error(),
                    })?;
                *slot = Some(Pending {
                    worker,
                    samples: Arc::clone(&samples),
                });
                Ok(())
            })();
            let unavailable = start_worker.err();
            let monitor = Monitor {
                samples: unavailable.is_none().then(|| Arc::clone(&samples)),
                unavailable,
                cutoff,
                setup_micros: started.elapsed().as_micros(),
            };
            let result = memcordon_testkit::run_until_owned_spawn_after_output_limit(
                command,
                cutoff,
                usize::MAX,
                move |mut command| {
                    let child = command.spawn()?;
                    if unavailable.is_none() {
                        let began = Instant::now();
                        let reference = original_cli(&child, cutoff);
                        samples.duplication_micros.store(
                            began.elapsed().as_micros().min(u128::from(u64::MAX - 1)) as u64,
                            Ordering::Release,
                        );
                        // Bounded channel, never a wait; a failed/late send drops
                        // only our query duplicate. Always return the SAME Child.
                        let _ = sender.try_send(reference);
                    }
                    Ok(child)
                },
                |_| Ok(()),
            );
            (result, monitor)
        }
    }
}
#[cfg(windows)]
pub use native::Observer;
