//! Controller-only, read-only observation of the already executed directory calls.
use super::super::{authz_diagnostic, protocol};
use super::{
    directory_policy as policy,
    helper_evidence::{Input, Operands, Output},
};
use memcordon_windows_launch_core::TokenObservationV1;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{
        CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER,
        ERROR_NO_TOKEN, HANDLE, SetLastError,
    },
    Security::{GetKernelObjectSecurity, TOKEN_QUERY},
    System::Threading::{GetCurrentProcess, OpenProcessToken, OpenThreadToken},
};

const POLICY_BYTES: usize = super::helper_evidence::DIRECTORY_POLICY_BYTES;
const SD_BYTES: usize = 1024;
#[derive(Clone, Copy)]
pub struct Target {
    pub process: HANDLE,
    pub thread: HANDLE,
}
type Sample = (
    Value,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<(String, TokenObservationV1)>,
);
#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: HANDLE,
    name: *mut Unicode,
    flags: u32,
    sd: *mut c_void,
    qos: *mut c_void,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenDirectoryObject(handle: *mut HANDLE, access: u32, attributes: *mut Attributes) -> i32;
    fn NtQueryObject(
        handle: HANDLE,
        class: i32,
        buffer: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
#[derive(Debug)]
struct NtFailure {
    status: i32,
    operation: &'static str,
    access: Option<u32>,
}
impl std::fmt::Display for NtFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} status {:#x}", self.operation, self.status)
    }
}
impl std::error::Error for NtFailure {}
fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}
fn error(error: &io::Error) -> Value {
    let nt = error
        .get_ref()
        .and_then(|value| value.downcast_ref::<NtFailure>());
    json!({"unavailable":error.to_string(),"native_error":error.raw_os_error(),"nt_status":nt.map(|value|value.status),"operation":nt.map(|value|value.operation),"observer_access":nt.and_then(|value|value.access)})
}
fn open(
    root: HANDLE,
    name: &[u16],
    flags: u32,
    access: u32,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<OwnedHandle> {
    check()?;
    let length = u16::try_from(
        name.len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| io::Error::other("directory name overflow"))?,
    )
    .map_err(io::Error::other)?;
    let mut text = name.to_vec();
    let mut string = Unicode {
        length,
        maximum: length,
        buffer: text.as_mut_ptr(),
    };
    let mut attributes = Attributes {
        length: size_of::<Attributes>() as u32,
        root,
        name: &mut string,
        flags,
        sd: ptr::null_mut(),
        qos: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let status = unsafe { NtOpenDirectoryObject(&mut handle, access, &mut attributes) };
    let handle = if handle.is_null() {
        None
    } else {
        Some(owned(handle)?)
    };
    check()?;
    if status < 0 {
        return Err(io::Error::other(NtFailure {
            status,
            operation: "observer NtOpenDirectoryObject",
            access: Some(access),
        }));
    }
    handle.ok_or_else(|| io::Error::other("observer directory returned no handle"))
}
fn object_text(
    handle: HANDLE,
    class: i32,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Vec<u16>> {
    check()?;
    let mut buffer = vec![0usize; 1024usize.div_ceil(size_of::<usize>())];
    let mut needed = 0;
    let status =
        unsafe { NtQueryObject(handle, class, buffer.as_mut_ptr().cast(), 1024, &mut needed) };
    check()?;
    if status < 0 {
        return Err(io::Error::other(NtFailure {
            status,
            operation: "observer NtQueryObject",
            access: None,
        }));
    }
    if needed as usize > 1024 || (needed as usize) < size_of::<Unicode>() {
        return Err(io::Error::other(format!(
            "bounded Directory name/type query status {status:#x}, length {needed}"
        )));
    }
    let value = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<Unicode>()) };
    let start = buffer.as_ptr() as usize;
    let at = (value.buffer as usize)
        .checked_sub(start)
        .ok_or_else(|| io::Error::other("Directory name pointer"))?;
    if value.length % 2 != 0
        || value.maximum % 2 != 0
        || value.length > value.maximum
        || at
            .checked_add(usize::from(value.length))
            .is_none_or(|end| end > needed as usize)
    {
        return Err(io::Error::other("Directory name/type extent"));
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(at),
            usize::from(value.length),
        )
    };
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}
fn identity(handle: HANDLE, check: &impl Fn() -> io::Result<()>) -> io::Result<Value> {
    let kind = object_text(handle, 2, check)?;
    if kind != "Directory".encode_utf16().collect::<Vec<_>>() {
        return Err(io::Error::other("observer object is not Directory"));
    }
    let name = object_text(handle, 1, check)?;
    Ok(json!({"type_utf16":kind,"name_utf16":name}))
}
fn descriptor(
    handle: HANDLE,
    info: u32,
    remaining: usize,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    check()?;
    let mut needed = 0;
    let sized = unsafe { GetKernelObjectSecurity(handle, info, ptr::null_mut(), 0, &mut needed) };
    let native = io::Error::last_os_error();
    let bound = (if info == 16 { 256 } else { SD_BYTES }).min(remaining);
    if sized != 0
        || native.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || needed == 0
        || needed as usize > bound
    {
        return Err(io::Error::other(format!(
            "directory SD sizing native {:?}, bytes {needed}, bound {bound}",
            native.raw_os_error()
        )));
    }
    check()?;
    let capacity = needed;
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            info,
            buffer.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    check()?;
    if needed > capacity {
        return Err(io::Error::other("directory SD grew beyond sized capacity"));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), needed as usize) }
            .to_vec();
    policy::decode_descriptor(&bytes)
        .map_err(|value| io::Error::other(format!("directory descriptor {value:?}")))?;
    Ok(bytes)
}
fn duplicate(
    process: HANDLE,
    remote: u64,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<OwnedHandle> {
    check()?;
    let mut local = ptr::null_mut();
    let ok = unsafe {
        DuplicateHandle(
            process,
            remote as usize as HANDLE,
            GetCurrentProcess(),
            &mut local,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    let native = io::Error::last_os_error();
    let local = if local.is_null() {
        None
    } else {
        Some(owned(local)?)
    };
    check()?;
    if ok == 0 {
        return Err(native);
    }
    local.ok_or_else(|| io::Error::other("live root duplication returned no handle"))
}
fn compare(
    first: HANDLE,
    second: HANDLE,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(bool, Option<i32>)> {
    check()?;
    unsafe {
        SetLastError(0);
    }
    let same = unsafe { CompareObjectHandles(first, second) } != 0;
    let native = (!same)
        .then(|| io::Error::last_os_error().raw_os_error())
        .flatten()
        .filter(|value| *value != 0);
    check()?;
    Ok((same, native))
}
fn effective(
    process: HANDLE,
    thread: HANDLE,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(OwnedHandle, &'static str, TokenObservationV1)> {
    check()?;
    let mut token = ptr::null_mut();
    let thread_ok = unsafe { OpenThreadToken(thread, TOKEN_QUERY, 1, &mut token) } != 0;
    let native = io::Error::last_os_error();
    let source = if thread_ok {
        "thread"
    } else if native.raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
        check()?;
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        "process-after-ERROR_NO_TOKEN"
    } else {
        return Err(native);
    };
    let token = owned(token)?;
    check()?;
    let (_, observation) =
        memcordon_windows_launch_core::query_token_envelope_with_observation(token.as_raw_handle())
            .map_err(io::Error::other)?;
    let observation = observation.map_err(io::Error::other)?;
    check()?;
    Ok((token, source, observation))
}
struct Held {
    handle: OwnedHandle,
    name: Vec<u16>,
    before_sd: Option<Vec<u8>>,
    before_label: Option<Vec<u8>>,
    token_before: Option<(String, TokenObservationV1)>,
}
pub struct Observation {
    pub record: Value,
    parent: Option<OwnedHandle>,
    root: Option<OwnedHandle>,
    remote_root: Option<u64>,
    child: Option<Held>,
}
impl Default for Observation {
    fn default() -> Self {
        Self {
            record: json!({"diagnostic_only":true,"acceptance_authority":false,"sampling":"non-atomic bracketed held-root+relative-name; denied lookup returned no identity handle","blobs":{},"tokens":{},"samples":[],"selected":false,"handles_released":false}),
            parent: None,
            root: None,
            remote_root: None,
            child: None,
        }
    }
}
impl Observation {
    fn store_bytes(&mut self, bytes: &[u8]) -> io::Result<String> {
        let digest = hash(bytes);
        if self.record["blobs"].get(&digest).is_none() {
            let value = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            if serde_json::to_vec(&self.record)
                .map_err(io::Error::other)?
                .len()
                + value.len()
                + digest.len()
                + 256
                > POLICY_BYTES
            {
                return Err(io::Error::other("directory policy byte budget"));
            }
            self.record["blobs"][&digest] = json!(value);
        }
        Ok(digest)
    }
    fn store_token(&mut self, token: &TokenObservationV1) -> io::Result<String> {
        let bytes = serde_json::to_vec(token).map_err(io::Error::other)?;
        let digest = hash(&bytes);
        if self.record["tokens"].get(&digest).is_none() {
            if bytes.len() > 4096
                || serde_json::to_vec(&self.record)
                    .map_err(io::Error::other)?
                    .len()
                    + bytes.len()
                    + digest.len()
                    + 512
                    > POLICY_BYTES
            {
                return Err(io::Error::other("directory token observation budget"));
            }
            self.record["tokens"][&digest] =
                serde_json::to_value(token).map_err(io::Error::other)?;
        }
        Ok(digest)
    }
    fn sample(
        &mut self,
        handle: HANDLE,
        label: &str,
        target: Target,
        request: &protocol::Request,
        deadline: Instant,
        check: &impl Fn() -> io::Result<()>,
    ) -> Sample {
        let Target { process, thread } = target;
        let object = match identity(handle, check) {
            Ok(value) => value,
            Err(value) => {
                return (
                    json!({"stage":label,"object":error(&value)}),
                    None,
                    None,
                    None,
                );
            }
        };
        let mut sample_qpc = 0;
        let clock = unsafe {
            windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut sample_qpc)
        } != 0;
        let mut record = json!({"stage":label,"object":object,"sample_qpc":clock.then_some(sample_qpc),"sampling":"sequential-non-atomic"});
        let remaining = POLICY_BYTES.saturating_sub(
            serde_json::to_vec(&self.record).map_or(POLICY_BYTES, |bytes| bytes.len()) + 2048,
        ) / 2;
        let sd = match descriptor(handle, 7, remaining, check) {
            Ok(bytes) => match self.store_bytes(&bytes) {
                Ok(digest) => {
                    record["sd_ref"] = json!(digest);
                    Some(bytes)
                }
                Err(value) => {
                    record["sd"] = error(&value);
                    None
                }
            },
            Err(value) => {
                record["sd"] = error(&value);
                None
            }
        };
        let remaining = POLICY_BYTES.saturating_sub(
            serde_json::to_vec(&self.record).map_or(POLICY_BYTES, |bytes| bytes.len()) + 2048,
        ) / 2;
        let label_bytes = match descriptor(handle, 16, remaining, check) {
            Ok(bytes) => match self.store_bytes(&bytes) {
                Ok(digest) => {
                    record["label_ref"] = json!(digest);
                    Some(bytes)
                }
                Err(value) => {
                    record["label"] = error(&value);
                    None
                }
            },
            Err(value) => {
                record["label"] = error(&value);
                None
            }
        };
        let token = match effective(process, thread, check) {
            Ok((token, source, observation)) => {
                let matches = observation.envelope == request.expected_token;
                let token_recorded = match self.store_token(&observation) {
                    Ok(digest) => {
                        record["token"] = json!({"source":source,"ref":digest,"requested_envelope_matches":matches});
                        true
                    }
                    Err(value) => {
                        record["token"] = error(&value);
                        false
                    }
                };
                if let Some(bytes) = &sd {
                    if let Ok(decoded) = policy::decode_descriptor(bytes) {
                        record["descriptor_summary"] = json!({"owner":decoded.owner,"group":decoded.group,"control":decoded.control});
                        let subject = policy::Subject {
                            user: policy::SidEntry {
                                sid: observation.envelope.user_sid.clone(),
                                attributes: observation.user_attributes,
                            },
                            groups: observation
                                .normal_groups
                                .iter()
                                .map(|value| policy::SidEntry {
                                    sid: value.sid.clone(),
                                    attributes: value.attributes,
                                })
                                .collect(),
                            restricted: observation
                                .restricted_sids
                                .iter()
                                .map(|value| policy::SidEntry {
                                    sid: value.sid.clone(),
                                    attributes: value.attributes,
                                })
                                .collect(),
                        };
                        if matches && token_recorded {
                            record["dacl_projection"] =
                                json!(policy::explain(&decoded, &subject, 0xf));
                            let generic = match &decoded.dacl {
                                policy::Acl::Present { aces, .. } => aces
                                    .iter()
                                    .any(|ace| ace.mask.is_none_or(|mask| mask & 0xf0000000 != 0)),
                                _ => false,
                            };
                            record["combined_authz"] = if generic {
                                json!({"unavailable":"unsupported Directory ACE layout or unverified generic mapping"})
                            } else {
                                authz_diagnostic::observe_directory(
                                    &token,
                                    bytes,
                                    &observation,
                                    deadline,
                                )
                            };
                        } else {
                            record["dacl_projection"] = json!({"unavailable":"effective token differs from requested envelope"});
                        }
                        let decoded_label = label_bytes
                            .as_ref()
                            .and_then(|bytes| policy::decode_descriptor(bytes).ok());
                        let label = policy::mandatory_label(decoded_label.as_ref());
                        record["mic"] = json!(policy::mic_facts(
                            &label,
                            &observation.envelope.integrity_level,
                            observation.envelope.mandatory_policy
                        ));
                    }
                }
                Some((source.to_owned(), observation))
            }
            Err(value) => {
                record["token"] = error(&value);
                None
            }
        };
        if let Err(value) = check() {
            record["late_or_deadline"] = error(&value);
        }
        (record, sd, label_bytes, token)
    }
    pub fn observe(
        &mut self,
        operands: &Operands,
        event: usize,
        target: Target,
        request: &protocol::Request,
        deadline: Instant,
        check: &impl Fn() -> io::Result<()>,
    ) {
        let result = (|| -> io::Result<()> {
            match operands {
                Operands::Before(input) if input.call == 0x867cf => {
                    self.parent_before(input, event, target, request, deadline, check)?
                }
                Operands::After(output) if output.call == 0x8687a => {
                    self.root_return(output, event, target.process, check)?
                }
                Operands::Before(input) if input.call == 0x86b2d => {
                    self.child_before(input, event, target, request, deadline, check)?
                }
                Operands::After(output) if output.call == 0x86b2d => {
                    self.child_after(output, event, target, request, deadline, check)?
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(value) = result {
            self.record["unavailable"] = json!({"event":event,"detail":error(&value)});
        }
    }
    fn parent_before(
        &mut self,
        input: &Input,
        event: usize,
        target: Target,
        request: &protocol::Request,
        deadline: Instant,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let attributes = input
            .object_attributes
            .as_ref()
            .ok_or_else(|| io::Error::other("parent OA missing"))?;
        if attributes.root_handle != 0
            || attributes.attributes != 0x40
            || input.args[1] as u32 != 0xf
        {
            return Err(io::Error::other("parent call binding unsupported"));
        }
        let name = decode_name(input)?;
        let handle = open(ptr::null_mut(), &name, 0x40, 0x20002, check)?;
        let (sample, _, _, _) = self.sample(
            handle.as_raw_handle(),
            "parent-before",
            target,
            request,
            deadline,
            check,
        );
        self.record["samples"].as_array_mut().unwrap().push(json!({"event":event,"call":input.call,"requested_access":0xf,"observer_access":0x20002,"sample":sample}));
        self.parent = Some(handle);
        Ok(())
    }
    fn root_return(
        &mut self,
        output: &Output,
        event: usize,
        process: HANDLE,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let remote = output
            .successful_output_handle
            .ok_or_else(|| io::Error::other("fallback has no successful output handle"))?;
        let root = duplicate(process, remote, check)?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| io::Error::other("controller parent unavailable"))?;
        let (same, native) = compare(root.as_raw_handle(), parent.as_raw_handle(), check)?;
        self.record["root_binding"] = json!({"event":event,"call":output.call,"remote":remote,"duplicate_same_access":true,"noninheriting":true,"compared":true,"same_kernel_object":same,"false_last_error":native});
        if !same {
            return Err(io::Error::other(
                "live fallback root differs from observer parent",
            ));
        }
        self.root = Some(root);
        self.remote_root = Some(remote);
        Ok(())
    }
    fn child_before(
        &mut self,
        input: &Input,
        event: usize,
        target: Target,
        request: &protocol::Request,
        deadline: Instant,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let attributes = input
            .object_attributes
            .as_ref()
            .ok_or_else(|| io::Error::other("child OA missing"))?;
        if Some(attributes.root_handle) != self.remote_root
            || attributes.attributes != 0x40
            || input.args[1] as u32 != 0xf
            || attributes.security_descriptor_pointer != 0
            || attributes.security_qos_pointer != 0
        {
            return Err(io::Error::other("child call/root binding mismatch"));
        }
        let name = decode_name(input)?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| io::Error::other("verified live root unavailable"))?;
        let handle = open(root.as_raw_handle(), &name, 0x40, 0x20000, check)?;
        let (sample, sd, label, token) = self.sample(
            handle.as_raw_handle(),
            "child-before",
            target,
            request,
            deadline,
            check,
        );
        self.record["samples"].as_array_mut().unwrap().push(json!({"event":event,"call":input.call,"requested_access":0xf,"observer_access":0x20000,"sample":sample}));
        self.child = Some(Held {
            handle,
            name,
            before_sd: sd,
            before_label: label,
            token_before: token,
        });
        Ok(())
    }
    fn child_after(
        &mut self,
        output: &Output,
        event: usize,
        target: Target,
        request: &protocol::Request,
        deadline: Instant,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("paired child candidate unavailable"))?;
        let (mut sample, sd, label, token) = self.sample(
            child.handle.as_raw_handle(),
            "child-after",
            target,
            request,
            deadline,
            check,
        );
        if child.before_sd.is_some()
            && child.before_sd == sd
            && child.before_label == label
            && child.token_before.is_some()
            && child.token_before == token
        {
            for key in ["dacl_projection", "mic"] {
                if sample.get(key).is_some() {
                    sample[key] = json!({"same_inputs_and_result_as":"child-before","sampling":"separate non-atomic snapshot"});
                }
            }
        }
        let reopened = match self.root.as_ref() {
            Some(root) => {
                open(root.as_raw_handle(), &child.name, 0x40, 0x20000, check).and_then(|reopened| {
                    compare(
                        reopened.as_raw_handle(),
                        child.handle.as_raw_handle(),
                        check,
                    )
                })
            }
            None => Err(io::Error::other("retained root unavailable")),
        };
        self.record["samples"]
            .as_array_mut()
            .unwrap()
            .push(json!({"event":event,"call":output.call,"status":output.status,"sample":sample}));
        self.record["bracket"] = json!({"descriptor_equal":match(&child.before_sd,&sd){(Some(a),Some(b))=>Some(a==b),_=>None},"label_equal":match(&child.before_label,&label){(Some(a),Some(b))=>Some(a==b),_=>None},"effective_token_equal":match(&child.token_before,&token){(Some(a),Some(b))=>Some(a==b),_=>None},"same_relative_name_object":reopened.as_ref().ok().map(|value|value.0),"comparison_false_last_error":reopened.as_ref().ok().and_then(|value|value.1),"reopen_error":reopened.err().map(|value|error(&value)),"atomic":false,"denied_lookup_object_identity":"unproved; no returned handle"});
        self.child = Some(child);
        Ok(())
    }
    pub fn finish(
        &mut self,
        selected: Option<super::profile::helper_profile::Selected>,
        outer_verified: bool,
        aggregate_verified: bool,
    ) {
        let candidate = selected.is_some_and(|value| {
            matches!(
                value.source,
                super::profile::helper_profile::Source::Call {
                    call: 0x86b2d,
                    returned: 0x86b34
                }
            )
        });
        self.record["candidate_selected_checkpoint"] = json!(selected);
        self.record["outer_eax_verified"] = json!(outer_verified);
        self.record["aggregate_r14_verified"] = json!(aggregate_verified);
        self.record["selected"] = json!(candidate && outer_verified && aggregate_verified);
        self.record["selected_status"] = json!(selected.map(|value| value.status));
        let binding = policy::BindingFacts {
            root_same: self.record["root_binding"]["same_kernel_object"].as_bool(),
            child_same: self.record["bracket"]["same_relative_name_object"].as_bool(),
            sd_equal: self.record["bracket"]["descriptor_equal"].as_bool(),
            label_equal: self.record["bracket"]["label_equal"].as_bool(),
            token_equal: self.record["bracket"]["effective_token_equal"].as_bool(),
            requested_token_matches: self.record["samples"].as_array().is_some_and(|samples| {
                samples.len() == 3
                    && samples.iter().all(|sample| {
                        sample["sample"]["token"]["requested_envelope_matches"] == true
                    })
            }),
        };
        let stable = policy::stable_binding(&binding);
        self.record["binding_facts"] = json!(binding);
        self.record["binding_stable"] = json!(stable);
        self.record["complete"] = json!(
            candidate
                && stable
                && outer_verified
                && aggregate_verified
                && self.record.get("unavailable").is_none()
                && self.record["samples"]
                    .as_array()
                    .is_some_and(|samples| samples.len() == 3
                        && samples
                            .iter()
                            .all(|sample| sample["sample"].get("sd_ref").is_some()
                                && sample["sample"].get("label_ref").is_some()
                                && sample["sample"]["token"].get("ref").is_some()
                                && sample["sample"]["combined_authz"]["context_matches"] == true
                                && sample["sample"]["combined_authz"]["source_unchanged"] == true
                                && sample["sample"]["combined_authz"]["checks"]
                                    .as_array()
                                    .is_some_and(|checks| checks.len() == 5
                                        && checks
                                            .iter()
                                            .all(|check| check["api_success"] == true))))
        );
        self.child = None;
        self.root = None;
        self.parent = None;
        self.record["handles_released"] = json!(true);
        if serde_json::to_vec(&self.record).map_or(true, |value| value.len() > POLICY_BYTES) {
            let digest = serde_json::to_vec(&self.record)
                .ok()
                .map(|bytes| hash(&bytes));
            self.record = json!({"diagnostic_only":true,"acceptance_authority":false,"complete":false,"unavailable":"directory-policy-byte-budget","candidate_sha256":digest,"handles_released":true});
        }
    }
}
fn decode_name(input: &Input) -> io::Result<Vec<u16>> {
    let name = input
        .object_attributes
        .as_ref()
        .and_then(|value| value.name.as_ref())
        .ok_or_else(|| io::Error::other("counted directory name unavailable"))?;
    let bytes = name
        .utf16_le_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(io::Error::other)?, 16)
                .map_err(io::Error::other)
        })
        .collect::<io::Result<Vec<_>>>()?;
    if bytes.len() != usize::from(name.length) || bytes.len() % 2 != 0 {
        return Err(io::Error::other("counted directory name extent"));
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}
