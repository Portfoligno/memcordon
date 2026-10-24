//! Read-only diagnostic probes; none of these results qualify workload startup.
use super::*;
use std::mem::{offset_of, size_of, size_of_val};

const TOKEN_BYTES: usize = 64 * 1024;
const SID_ENTRIES: usize = 512;
const DESKTOP_ACCESS: u32 = 0x000f_01ff;
// Native ABI values, matching the existing production token attributes and
// noninteractive USER-object mappings; these are observations, not new grants.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
const WINSTA_ENUMDESKTOPS: u32 = 0x0000_0001;
const WINSTA_READATTRIBUTES: u32 = 0x0000_0002;
const WINSTA_ACCESSCLIPBOARD: u32 = 0x0000_0004;
const WINSTA_CREATEDESKTOP: u32 = 0x0000_0008;
const WINSTA_ACCESSGLOBALATOMS: u32 = 0x0000_0020;
const WINSTA_EXITWINDOWS: u32 = 0x0000_0040;
const WINSTA_ENUMERATE: u32 = 0x0000_0100;

fn info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<(Vec<usize>, usize), String> {
    let mut needed = 0;
    let sized = unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed) };
    let status = unsafe { GetLastError() };
    if sized != 0
        || status != ERROR_INSUFFICIENT_BUFFER
        || needed == 0
        || needed as usize > TOKEN_BYTES
    {
        return Err(format!(
            "token information sizing class={class} bytes={needed} native_code={status}; complete=false"
        ));
    }
    let mut words = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    let capacity = needed;
    if unsafe {
        GetTokenInformation(
            token,
            class,
            words.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    } == 0
    {
        return Err(error("GetTokenInformation startup probe"));
    }
    if needed == 0 || needed > capacity {
        return Err("token information extent changed; complete=false".into());
    }
    Ok((words, needed as usize))
}

fn sid(words: &[usize], extent: usize, raw: PSID) -> Result<String, String> {
    let start = words.as_ptr() as usize;
    let address = raw as usize;
    let offset = address
        .checked_sub(start)
        .ok_or("SID precedes retained token buffer")?;
    if raw.is_null() || offset.checked_add(8).is_none_or(|end| end > extent) {
        return Err("SID header escapes retained token buffer".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), extent) };
    let count = usize::from(bytes[offset + 1]);
    let length = count
        .checked_mul(size_of::<u32>())
        .and_then(|tail| tail.checked_add(8))
        .ok_or("SID extent overflow")?;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= extent)
        .ok_or("SID escapes retained token buffer")?;
    if unsafe { IsValidSid(raw) } == 0 {
        return Err("native token SID is invalid".into());
    }
    let bytes = &bytes[offset..end];
    let authority = bytes[2..8]
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut text = format!("S-{}-{authority}", bytes[0]);
    for subauthority in bytes[8..].chunks_exact(size_of::<u32>()) {
        use std::fmt::Write;
        write!(
            &mut text,
            "-{}",
            u32::from_le_bytes(
                subauthority
                    .try_into()
                    .expect("native SID subauthority width")
            )
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(text)
}

fn principal(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Value, String> {
    let (words, extent) = info(token, class)?;
    if extent < size_of::<PSID>() {
        return Err("token principal header is truncated".into());
    }
    if class == TokenUser || class == TokenIntegrityLevel {
        if extent < size_of::<SID_AND_ATTRIBUTES>() {
            return Err("token SID attributes are truncated".into());
        }
        let entry = unsafe { words.as_ptr().cast::<SID_AND_ATTRIBUTES>().read_unaligned() };
        Ok(json!({"sid":sid(&words, extent, entry.Sid)?,"attributes":entry.Attributes}))
    } else {
        let raw = unsafe { words.as_ptr().cast::<PSID>().read_unaligned() };
        Ok(json!({"sid":sid(&words, extent, raw)?}))
    }
}

fn groups(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Value, String> {
    let (words, extent) = info(token, class)?;
    if extent < size_of::<u32>() {
        return Err("token group header truncated".into());
    }
    let count = unsafe { words.as_ptr().cast::<u32>().read_unaligned() } as usize;
    let offset = offset_of!(TOKEN_GROUPS, Groups);
    if count > SID_ENTRIES
        || count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|size| offset.checked_add(size))
            .is_none_or(|end| end > extent)
    {
        return Err(format!(
            "token group inventory exceeds complete bounded extent; entries={count}; complete=false"
        ));
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let entry = unsafe {
            words
                .as_ptr()
                .cast::<u8>()
                .add(offset + index * size_of::<SID_AND_ATTRIBUTES>())
                .cast::<SID_AND_ATTRIBUTES>()
                .read_unaligned()
        };
        entries.push(json!({"sid":sid(&words, extent, entry.Sid)?,"attributes":entry.Attributes,
            "enabled":entry.Attributes & SE_GROUP_ENABLED != 0,"deny_only":entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0}));
    }
    Ok(json!({"complete":true,"entries":entries}))
}

fn captured(result: Result<Value, String>) -> Value {
    match result {
        Ok(facts) => json!({"captured":true,"facts":facts}),
        Err(error) => json!({"captured":false,"complete":false,"error":error}),
    }
}

pub(super) fn validate_probe_capability(probe: HANDLE, primary: HANDLE) -> Result<(), String> {
    #[repr(C)]
    struct Basic {
        attributes: u32,
        access: u32,
        handles: u32,
        pointers: u32,
        reserved: [u32; 10],
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryObject(
            handle: HANDLE,
            class: u32,
            buffer: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut basic = Basic {
        attributes: 0,
        access: 0,
        handles: 0,
        pointers: 0,
        reserved: [0; 10],
    };
    let mut returned = 0;
    let mut flags = 0;
    if unsafe { GetHandleInformation(probe, &mut flags) } == 0
        || flags & HANDLE_FLAG_INHERIT != 0
        || unsafe {
            NtQueryObject(
                probe,
                0,
                (&mut basic as *mut Basic).cast(),
                size_of::<Basic>() as u32,
                &mut returned,
            )
        } < 0
        || basic.access != (TOKEN_QUERY | TOKEN_IMPERSONATE)
    {
        return Err("startup probe capability rights/inheritance differ".into());
    }
    let original = memcordon_windows_launch_core::query_token_envelope(primary)?;
    let duplicate = memcordon_windows_launch_core::query_token_envelope(probe)?;
    memcordon_windows_loader_lab::startup_probe_contract::validate_token_pair(&original, &duplicate)
}

fn object_name(handle: HANDLE) -> Result<String, String> {
    let mut needed = 0;
    unsafe {
        GetUserObjectInformationW(handle, UOI_NAME, ptr::null_mut(), 0, &mut needed);
    }
    if needed < size_of::<u16>() as u32
        || needed as usize > 8192
        || needed as usize % size_of::<u16>() != 0
    {
        return Err("native USER name extent outside bound".into());
    }
    let mut words = vec![0_u16; (needed as usize).div_ceil(size_of::<u16>())];
    let capacity = needed;
    if unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            words.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    } == 0
        || needed > capacity
    {
        return Err(error("GetUserObjectInformationW startup probe"));
    }
    let end = words
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("native USER name unterminated")?;
    String::from_utf16(&words[..end]).map_err(|error| error.to_string())
}

fn object_access(
    handle: HANDLE,
    token: HANDLE,
    station: bool,
    expected: &selected_policy::Snapshot,
) -> Result<Value, String> {
    let selection = 0x17;
    let mut needed = 0;
    unsafe {
        GetUserObjectSecurity(handle, &selection, ptr::null_mut(), 0, &mut needed);
    }
    if !(20..=64 * 1024).contains(&needed) {
        return Err("native USER descriptor size outside bound".into());
    }
    let mut words = vec![0_u32; (needed as usize).div_ceil(size_of::<u32>())];
    let capacity = needed;
    if unsafe {
        GetUserObjectSecurity(
            handle,
            &selection,
            words.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    } == 0
        || needed > capacity
        || needed < 20
    {
        return Err(error("GetUserObjectSecurity startup probe"));
    }
    let bounded =
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), needed as usize) };
    selected_policy::capture_selected(bounded, selection)?;
    if unsafe { IsValidSecurityDescriptor(words.as_ptr().cast_mut().cast()) } == 0 {
        return Err("native USER descriptor invalid".into());
    }
    let actual = unsafe { GetSecurityDescriptorLength(words.as_ptr().cast_mut().cast()) };
    if !(20..=needed).contains(&actual) {
        return Err("native USER descriptor actual extent differs".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), actual as usize) };
    let observed = selected_policy::capture_selected(bytes, selection)?;
    if observed.raw_sha256 != expected.raw_sha256 {
        return Err("held USER descriptor changed before startup AccessCheck".into());
    }
    let requested = if station {
        memcordon_windows_loader_lab::holder_creation::STATION_ACCESS
    } else {
        DESKTOP_ACCESS
    };
    // Same finite object-specific mappings as production security.rs. The
    // requested masks are already concrete; no broader retry is performed.
    let mut mapping = if station {
        GENERIC_MAPPING {
            GenericRead: 0x0002_0000
                | WINSTA_ENUMDESKTOPS
                | WINSTA_ENUMERATE
                | WINSTA_READATTRIBUTES,
            GenericWrite: 0x0002_0000 | WINSTA_ACCESSCLIPBOARD | WINSTA_CREATEDESKTOP,
            GenericExecute: 0x0002_0000 | WINSTA_ACCESSGLOBALATOMS | WINSTA_EXITWINDOWS,
            GenericAll: requested,
        }
    } else {
        GENERIC_MAPPING {
            GenericRead: 0x0002_0000 | DESKTOP_ENUMERATE | DESKTOP_READOBJECTS,
            GenericWrite: 0x0002_0000
                | DESKTOP_CREATEMENU
                | DESKTOP_CREATEWINDOW
                | DESKTOP_HOOKCONTROL
                | DESKTOP_JOURNALPLAYBACK
                | DESKTOP_JOURNALRECORD
                | DESKTOP_WRITEOBJECTS,
            GenericExecute: 0x0002_0000 | DESKTOP_SWITCHDESKTOP,
            GenericAll: requested,
        }
    };
    let mut privilege_words = [0_usize; 64];
    let mut privilege_bytes = size_of_val(&privilege_words) as u32;
    let mut granted = 0;
    let mut allowed = 0;
    let called = unsafe {
        AccessCheck(
            words.as_mut_ptr().cast(),
            token,
            requested,
            &mut mapping,
            privilege_words.as_mut_ptr().cast(),
            &mut privilege_bytes,
            &mut granted,
            &mut allowed,
        )
    };
    let native_code = if called == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let policy = selected_policy::verify_and_fingerprint(
        if station {
            Domain::Station
        } else {
            Domain::Desktop
        },
        expected,
        &observed,
    )?;
    Ok(
        json!({"name":object_name(handle)?,"descriptor_sha256":observed.raw_sha256,"descriptor_length":observed.length,"selected_descriptor_sha256":expected.raw_sha256,"policy":policy,
        "requested":requested,"granted":if called != 0 {Some(granted)} else {None},"api_succeeded":called != 0,
        "access_status":if called != 0 {Some(allowed != 0)} else {None},"native_code":native_code,"privilege_bytes":privilege_bytes}),
    )
}

struct Impersonation {
    active: bool,
}
impl Impersonation {
    fn enter(token: HANDLE) -> Result<Self, String> {
        let mut existing = ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut existing) } != 0 {
            drop(Handle::new(existing)?);
            return Err("isolated startup probe thread already impersonates".into());
        }
        if unsafe { GetLastError() } != ERROR_NO_TOKEN {
            return Err(error("startup probe impersonation preflight"));
        }
        if unsafe { SetThreadToken(ptr::null(), token) } == 0 {
            return Err(error("SetThreadToken exact target startup probe"));
        }
        Ok(Self { active: true })
    }
    fn restore(&mut self) -> Result<(), String> {
        if self.active && unsafe { RevertToSelf() } == 0 {
            return Err(error("restore startup probe impersonation"));
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for Impersonation {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                RevertToSelf();
            }
        }
    }
}

struct OpenedUser {
    raw: HANDLE,
    station: bool,
}
impl OpenedUser {
    fn close(mut self) -> Result<(), String> {
        let closed = unsafe {
            if self.station {
                CloseWindowStation(self.raw)
            } else {
                CloseDesktop(self.raw)
            }
        };
        if closed == 0 {
            Err(error("close startup probe USER object"))
        } else {
            self.raw = ptr::null_mut();
            Ok(())
        }
    }
}
impl Drop for OpenedUser {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                if self.station {
                    CloseWindowStation(self.raw);
                } else {
                    CloseDesktop(self.raw);
                }
            }
        }
    }
}

fn namespace_open(name: &str, expected_sha256: &str, station: bool, work: Instant) -> Value {
    let operation = (|| -> Result<Value, String> {
        live(work)?;
        let name_wide = wide(name);
        let requested = if station {
            memcordon_windows_loader_lab::holder_creation::STATION_ACCESS
        } else {
            DESKTOP_ACCESS
        };
        let raw = unsafe {
            if station {
                OpenWindowStationW(name_wide.as_ptr(), 0, requested)
            } else {
                OpenDesktopW(name_wide.as_ptr(), 0, 0, requested)
            }
        };
        if raw.is_null() {
            return Ok(
                json!({"opened":false,"requested":requested,"native_code":unsafe { GetLastError() }}),
            );
        }
        let owner = OpenedUser { raw, station };
        let facts = (|| -> Result<Value, String> {
            live(work)?;
            let observed_name = object_name(owner.raw)?;
            let policy = unsafe { selected_policy_native::read_user(owner.raw) }?;
            if observed_name != name || policy.raw_sha256 != expected_sha256 {
                return Err("opened USER object differs from original held name/descriptor".into());
            }
            let fingerprint = selected_policy::verify_and_fingerprint(
                if station {
                    Domain::Station
                } else {
                    Domain::Desktop
                },
                &policy,
                &policy,
            )?;
            Ok(
                json!({"name":observed_name,"descriptor_sha256":policy.raw_sha256,"policy":fingerprint}),
            )
        })();
        let cleanup = owner.close();
        Ok(
            json!({"opened":true,"requested":requested,"native_code":null,"identity":captured(facts),
            "new_handle_closed":cleanup.is_ok(),"cleanup_error":cleanup.err()}),
        )
    })();
    captured(operation)
}

fn namespace_thread(
    token: Handle,
    names: (String, String),
    digests: (String, String),
    expected_token_sha256: String,
    work: Instant,
) -> Value {
    let mut guard = match Impersonation::enter(token.0) {
        Ok(guard) => guard,
        Err(error) => return json!({"impersonated":false,"inconclusive":true,"error":error}),
    };
    let operation = (|| -> Result<Value, String> {
        live(work)?;
        let mut thread_raw = ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_raw) } == 0 {
            return Err(error("query active startup probe thread token"));
        }
        let thread_token = Handle::new(thread_raw)?;
        let active = memcordon_windows_launch_core::query_token_envelope(thread_token.0)?;
        let selected = memcordon_windows_launch_core::query_token_envelope(token.0)?;
        if active != selected {
            return Err(
                "active startup probe thread token differs from retained exact duplicate".into(),
            );
        }
        let active_sha256 = memcordon_windows_launch_core::token_envelope_sha256(&active)?;
        if active_sha256 != expected_token_sha256 {
            return Err(
                "startup probe token changed after original primary association capture".into(),
            );
        }
        let current = unsafe { GetProcessWindowStation() };
        if current.is_null() || object_name(current)? != names.0 {
            return Err(
                "startup probe process station is not the original held target-session station"
                    .into(),
            );
        }
        Ok(
            json!({"thread_id":unsafe { GetCurrentThreadId() },"active_thread_token_envelope_sha256":active_sha256,"process_station":names.0,"station":namespace_open(&names.0, &digests.0, true, work),
            "desktop":namespace_open(&names.1, &digests.1, false, work)}),
        )
    })();
    let restoration = guard.restore();
    json!({"impersonated":true,"scoped_to_isolated_thread":true,"facts":captured(operation),
        "restored":restoration.is_ok(),"restoration_error":restoration.err(),"inconclusive":true})
}

pub(super) fn collect(
    primary: HANDLE,
    probe: Handle,
    objects: (HANDLE, HANDLE),
    names: (&str, &str),
    station: &selected_policy::Snapshot,
    desktop: &selected_policy::Snapshot,
    deadlines: (Instant, Instant),
) -> Result<Value, String> {
    let (work, cleanup) = deadlines;
    live(work)?;
    let envelope = memcordon_windows_launch_core::query_token_envelope(primary)?;
    let probe_envelope = memcordon_windows_launch_core::query_token_envelope(probe.0)?;
    memcordon_windows_loader_lab::startup_probe_contract::validate_token_pair(
        &envelope,
        &probe_envelope,
    )?;
    let mut facts = json!({"envelope":envelope,"envelope_sha256":memcordon_windows_launch_core::token_envelope_sha256(&envelope)?,
        "probe_envelope":probe_envelope,"probe_envelope_sha256":memcordon_windows_launch_core::token_envelope_sha256(&probe_envelope)?,
        "token_source":"same retained primary token used to create the suspended diagnostic target","omissions":[]});
    for (name, class) in [
        ("user", TokenUser),
        ("owner", TokenOwner),
        ("primary_group", TokenPrimaryGroup),
        ("integrity", TokenIntegrityLevel),
    ] {
        live(work)?;
        facts[name] = captured(principal(primary, class));
    }
    live(work)?;
    facts["groups"] = captured(groups(primary, TokenGroups));
    live(work)?;
    facts["restricting_sids"] = captured(groups(primary, TokenRestrictedSids));
    let omissions: Vec<_> = [
        "user",
        "owner",
        "primary_group",
        "integrity",
        "groups",
        "restricting_sids",
    ]
    .into_iter()
    .filter(|name| facts[*name]["captured"] != true)
    .collect();
    facts["complete"] = json!(omissions.is_empty());
    facts["omissions"] = json!(omissions);
    live(work)?;
    let station_access = captured(object_access(objects.0, probe.0, true, station));
    live(work)?;
    let desktop_access = captured(object_access(objects.1, probe.0, false, desktop));
    let after = memcordon_windows_launch_core::query_token_envelope(primary)?;
    if after != envelope {
        return Err("target token changed while capturing startup facts; inconclusive".into());
    }
    let raw = probe.0 as usize;
    let names = (names.0.to_owned(), names.1.to_owned());
    let digests = (station.raw_sha256.clone(), desktop.raw_sha256.clone());
    let expected_token_sha256 =
        memcordon_windows_launch_core::token_envelope_sha256(&probe_envelope)?;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("startup-access-probe".into())
        .spawn(move || {
            let owned = Handle(raw as HANDLE);
            let result = namespace_thread(owned, names, digests, expected_token_sha256, work);
            let _ = send.send(result);
        })
        .map_err(|error| error.to_string())?;
    // The successfully created isolated thread now owns this exact inherited
    // capability. Spawn failure above leaves ordinary RAII cleanup unchanged.
    std::mem::forget(probe);
    let namespace = receive.recv_timeout(work.saturating_duration_since(Instant::now()));
    // After the work cutoff, only settle restoration and the original holder's
    // owned thread. Never detach a live impersonation carrier or restore the
    // process station while that carrier can still use its native context.
    while !worker.is_finished() {
        if Instant::now() >= cleanup {
            eprintln!(
                "startup namespace probe thread unresolved at original cleanup cutoff; holder exits inconclusively"
            );
            // This is the existing disposable holder, owned by its parent's
            // original Job. Request retirement without extending either
            // deadline; this call does not prove bounded synchronous cleanup.
            // The parent's held-process/Job checks remain the final proof.
            unsafe {
                ExitProcess(FAILURE);
            }
        }
        std::thread::yield_now();
    }
    worker
        .join()
        .map_err(|_| "startup namespace probe thread panicked; inconclusive")?;
    let namespace = namespace.map_err(|error| format!("startup namespace probe exceeded original work cutoff; restoration settled; inconclusive: {error}"))?;
    live(work)?;
    if memcordon_windows_launch_core::query_token_envelope(primary)? != envelope {
        return Err(
            "original primary token changed through namespace startup probe; inconclusive".into(),
        );
    }
    Ok(
        json!({"token_facts":facts,"station_access_check":station_access,"desktop_access_check":desktop_access,
        "namespace_opens":namespace,"diagnostic_only":true,"inconclusive":true}),
    )
}
