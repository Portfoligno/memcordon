//! Explicit native Winsock configuration input; never host policy mutation.
use crate::windows_registry_manifest::{Declaration, Key, Manifest, ValueRecord, View};
use std::{io, ptr, time::Instant};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_ITEMS, FILETIME, LocalFree},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    },
    System::Registry::*,
};

const PARAMETERS: &str = "System\\CurrentControlSet\\Services\\WinSock2\\Parameters";
const MAX_KEYS: usize = 256;
const MAX_VALUES: usize = 4096;
const MAX_BYTES: usize = 4 * 1024 * 1024;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn status(value: u32) -> io::Result<()> {
    if value == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(value as i32))
    }
}
fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original registry input cutoff exhausted",
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct Failures {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; independent owned registry cleanup: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn failures(primary: io::Error, secondary: io::Error) -> io::Error {
    io::Error::new(primary.kind(), Failures { primary, secondary })
}
fn hex_digest(bytes: &[u8]) -> String {
    use {sha2::Digest, std::fmt::Write};
    let mut text = String::new();
    for byte in sha2::Sha256::digest(bytes) {
        write!(&mut text, "{byte:02x}").expect("String formatting cannot fail");
    }
    text
}

fn source_security(root: HKEY, deadline: Instant) -> io::Result<Vec<u8>> {
    live(deadline)?;
    let mut length = 0;
    let result = unsafe { RegGetKeySecurity(root, 7, ptr::null_mut(), &mut length) };
    if result != 122 {
        status(result)?;
    }
    if length == 0 || length > 64 * 1024 {
        return Err(io::Error::other(
            "source registry security descriptor extent exceeds bound",
        ));
    }
    let mut bytes = vec![0; length as usize];
    status(unsafe { RegGetKeySecurity(root, 7, bytes.as_mut_ptr().cast(), &mut length) })?;
    if length as usize != bytes.len() {
        return Err(io::Error::other(
            "source registry security descriptor changed extent",
        ));
    }
    live(deadline)?;
    Ok(bytes)
}

pub struct OwnedKey(HKEY);
// Registry references are process-local, thread-safe native kernel references;
// moving ownership does not move a pseudo handle or impersonation context.
unsafe impl Send for OwnedKey {}
impl Drop for OwnedKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
impl OwnedKey {
    fn raw(&self) -> HKEY {
        self.0
    }
    /// The caller transfers exactly one target-local registry reference.
    ///
    /// # Safety
    /// `raw` must be a live target-local registry reference transferred
    /// exclusively to this owner; no other owner may close or adopt it.
    pub unsafe fn from_transferred(raw: u64, deadline: Instant) -> io::Result<Self> {
        let raw = usize::try_from(raw).map_err(io::Error::other)? as HKEY;
        if raw.is_null() {
            return Err(io::Error::other("registry input handle is null"));
        }
        let owner = Self(raw);
        live(deadline)?;
        let mut flags = 0;
        if unsafe { windows_sys::Win32::Foundation::GetHandleInformation(raw, &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT != 0 {
            return Err(io::Error::other("registry input reference is inheritable"));
        }
        use windows_sys::{
            Wdk::Foundation::{NtQueryObject, ObjectBasicInformation},
            Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION,
        };
        let mut basic = PUBLIC_OBJECT_BASIC_INFORMATION::default();
        let provided = std::mem::size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32;
        let mut returned = 0;
        live(deadline)?;
        // SAFETY: owner retains the original key; this is the documented fixed
        // ObjectBasicInformation structure and its exact native buffer extent.
        let result = unsafe {
            NtQueryObject(
                raw,
                ObjectBasicInformation,
                (&raw mut basic).cast(),
                provided,
                &raw mut returned,
            )
        };
        if result < 0 {
            return Err(io::Error::other(format!(
                "registry input granted-access query failed: operation=NtQueryObject; class=ObjectBasicInformation({ObjectBasicInformation}); NTSTATUS={result} ({result:#010x}); provided-bytes={provided}; returned-bytes={returned}; failed-output-not-authoritative=true"
            )));
        }
        if returned != provided {
            return Err(io::Error::other(format!(
                "registry input granted-access response length differs: operation=NtQueryObject; class=ObjectBasicInformation({ObjectBasicInformation}); NTSTATUS={result} ({result:#010x}); provided-bytes={provided}; returned-bytes={returned}"
            )));
        }
        if basic.GrantedAccess != KEY_READ {
            return Err(io::Error::other(format!(
                "registry input does not carry exact KEY_READ access: operation=NtQueryObject; class=ObjectBasicInformation({ObjectBasicInformation}); provided-bytes={provided}; returned-bytes={returned}; granted-access={:#010x}; expected-access={KEY_READ:#010x}",
                basic.GrantedAccess
            )));
        }
        live(deadline)?;
        Ok(owner)
    }
}
fn open(parent: HKEY, name: &[u16], access: u32, deadline: Instant) -> io::Result<OwnedKey> {
    live(deadline)?;
    let mut name = name.to_vec();
    name.push(0);
    let mut key = ptr::null_mut();
    status(unsafe {
        RegOpenKeyExW(
            parent,
            name.as_ptr(),
            REG_OPTION_OPEN_LINK,
            access,
            &mut key,
        )
    })?;
    let key = OwnedKey(key);
    live(deadline)?;
    Ok(key)
}

#[derive(Debug, Eq, PartialEq)]
struct Stamp {
    path: Vec<Vec<u16>>,
    subkeys: u32,
    values: u32,
    low: u32,
    high: u32,
}

fn capture(root: HKEY, deadline: Instant) -> io::Result<(Manifest, Vec<Stamp>)> {
    let mut pending = vec![(Vec::<Vec<u16>>::new(), None::<OwnedKey>)];
    let mut keys = Vec::new();
    let mut stamps = Vec::new();
    let mut value_count = 0usize;
    let mut byte_count = 0usize;
    while let Some((path, owner)) = pending.pop() {
        live(deadline)?;
        if keys.len() >= MAX_KEYS || path.len() > 16 {
            return Err(io::Error::other("registry input key/depth bound exceeded"));
        }
        let raw = owner.as_ref().map_or(root, OwnedKey::raw);
        let (mut subkeys, mut values, mut modified) = (0, 0, FILETIME::default());
        let mut class = vec![0u16; 256];
        let mut class_length = class.len() as u32;
        status(unsafe {
            RegQueryInfoKeyW(
                raw,
                class.as_mut_ptr(),
                &mut class_length,
                ptr::null(),
                &mut subkeys,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut values,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut modified,
            )
        })?;
        class.truncate(class_length as usize);
        byte_count = byte_count
            .checked_add(class.len() * 2)
            .ok_or_else(|| io::Error::other("registry class size overflow"))?;
        if byte_count > MAX_BYTES {
            return Err(io::Error::other(
                "registry class/data aggregate bound exceeded",
            ));
        }
        if subkeys as usize > MAX_KEYS || values as usize > MAX_VALUES {
            return Err(io::Error::other(
                "registry input enumeration count exceeds bound",
            ));
        }
        let mut captured = Vec::new();
        for index in 0..values {
            live(deadline)?;
            value_count += 1;
            if value_count > MAX_VALUES {
                return Err(io::Error::other("registry input value bound exceeded"));
            }
            let mut name = vec![0u16; 16384];
            let mut length = name.len() as u32;
            let (mut kind, mut bytes) = (0, 0);
            status(unsafe {
                RegEnumValueW(
                    raw,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    ptr::null(),
                    &mut kind,
                    ptr::null_mut(),
                    &mut bytes,
                )
            })?;
            if bytes as usize > 1024 * 1024 {
                return Err(io::Error::other(
                    "registry input single value exceeds bound",
                ));
            }
            let mut data = vec![0; bytes as usize];
            let mut second_name = vec![0u16; 16384];
            let mut second_length = second_name.len() as u32;
            let mut second_kind = 0;
            live(deadline)?;
            status(unsafe {
                RegEnumValueW(
                    raw,
                    index,
                    second_name.as_mut_ptr(),
                    &mut second_length,
                    ptr::null(),
                    &mut second_kind,
                    data.as_mut_ptr(),
                    &mut bytes,
                )
            })?;
            name.truncate(length as usize);
            second_name.truncate(second_length as usize);
            if name != second_name || kind != second_kind || bytes as usize != data.len() {
                return Err(io::Error::other(
                    "registry input value changed during enumeration",
                ));
            }
            byte_count = byte_count
                .checked_add(data.len() + name.len() * 2)
                .ok_or_else(|| io::Error::other("registry input size overflow"))?;
            if byte_count > MAX_BYTES {
                return Err(io::Error::other(
                    "registry input aggregate byte bound exceeded",
                ));
            }
            if kind == REG_LINK {
                return Err(io::Error::other(
                    "registry dependency contains unsupported symbolic link",
                ));
            }
            captured.push(ValueRecord {
                name,
                kind,
                bytes: data,
            });
        }
        // The exact observed counts must also terminate enumeration, not hide
        // an appended key/value from a concurrent host mutation.
        let mut name = vec![0u16; 16384];
        let mut length = name.len() as u32;
        live(deadline)?;
        let end = unsafe {
            RegEnumValueW(
                raw,
                values,
                name.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if end != ERROR_NO_MORE_ITEMS {
            return Err(io::Error::other(format!(
                "registry value enumeration did not end at observed count: {end}"
            )));
        }
        for index in 0..subkeys {
            live(deadline)?;
            let mut name = vec![0u16; 256];
            let mut length = name.len() as u32;
            status(unsafe {
                RegEnumKeyExW(
                    raw,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            })?;
            name.truncate(length as usize);
            let child = open(raw, &name, KEY_READ, deadline)?;
            let mut child_path = path.clone();
            child_path.push(name);
            byte_count = byte_count
                .checked_add(child_path.iter().map(|part| part.len() * 2).sum::<usize>())
                .ok_or_else(|| io::Error::other("registry path size overflow"))?;
            if byte_count > MAX_BYTES {
                return Err(io::Error::other(
                    "registry input name/data aggregate bound exceeded",
                ));
            }
            pending.push((child_path, Some(child)));
            if pending.len() + keys.len() > MAX_KEYS {
                return Err(io::Error::other(
                    "registry input pending key bound exceeded",
                ));
            }
        }
        let mut name = [0u16; 256];
        let mut length = name.len() as u32;
        live(deadline)?;
        let end = unsafe {
            RegEnumKeyExW(
                raw,
                subkeys,
                name.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if end != ERROR_NO_MORE_ITEMS {
            return Err(io::Error::other(format!(
                "registry key enumeration did not end at observed count: {end}"
            )));
        }
        stamps.push(Stamp {
            path: path.clone(),
            subkeys,
            values,
            low: modified.dwLowDateTime,
            high: modified.dwHighDateTime,
        });
        keys.push(Key {
            path,
            class,
            values: captured,
        });
    }
    let manifest = Manifest {
        version: 1,
        view: View::Native,
        keys,
    };
    manifest.validate().map_err(io::Error::other)?;
    stamps.sort_by(|a, b| a.path.cmp(&b.path));
    live(deadline)?;
    Ok((manifest, stamps))
}

fn coherent(root: HKEY, deadline: Instant) -> io::Result<Manifest> {
    let (first, first_stamps) = capture(root, deadline)?;
    let (second, second_stamps) = capture(root, deadline)?;
    if first_stamps != second_stamps
        || first.digest().map_err(io::Error::other)? != second.digest().map_err(io::Error::other)?
    {
        return Err(io::Error::other(
            "native registry input changed during coherent capture",
        ));
    }
    Ok(second)
}

pub struct Projection {
    root: OwnedKey,
    nodes: Vec<OwnedKey>,
    manifest: Manifest,
    declaration: Declaration,
    deadline: Instant,
    retired: bool,
    transferred: bool,
    recipients_retired: bool,
    source_security: Vec<u8>,
    namespace: String,
    cleanup_deadline: Instant,
}
impl Projection {
    pub fn declaration(&self) -> &Declaration {
        &self.declaration
    }
    fn raw(&self) -> HKEY {
        self.root.raw()
    }
    pub fn create(unique: &str, deadline: Instant, cleanup_deadline: Instant) -> io::Result<Self> {
        live(deadline)?;
        if cleanup_deadline < deadline {
            return Err(io::Error::other(
                "registry cleanup cutoff precedes original work cutoff",
            ));
        }
        if unique.is_empty() || unique.len() > 128 || !unique.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(io::Error::other("invalid owned registry namespace nonce"));
        }
        let source = open(
            HKEY_LOCAL_MACHINE,
            &PARAMETERS.encode_utf16().collect::<Vec<_>>(),
            KEY_READ,
            deadline,
        )?;
        let security_before = source_security(source.raw(), deadline)?;
        let manifest = coherent(source.raw(), deadline)?;
        if source_security(source.raw(), deadline)? != security_before {
            return Err(io::Error::other(
                "source registry security changed during capture",
            ));
        }
        let declaration = manifest.declaration().map_err(io::Error::other)?;
        // This DACL applies ONLY to each newly created fixture key. RC can read
        // configuration, never mutate it; owner/system retain cleanup custody.
        let sddl = wide("D:P(A;CI;KA;;;SY)(A;CI;KA;;;OW)(A;CI;KR;;;RC)");
        let mut sd = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        struct Security(*mut std::ffi::c_void);
        impl Drop for Security {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let security = Security(sd);
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        // One unique component creates only our owned namespace, never an
        // implicit shared intermediate key in a fresh caller profile.
        let namespace = format!("Memcordon-Winsock-{unique}");
        let name = wide(&namespace);
        let mut root = ptr::null_mut();
        let mut disposition = 0;
        status(unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                name.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_VOLATILE,
                KEY_ALL_ACCESS,
                &attributes,
                &mut root,
                &mut disposition,
            )
        })?;
        if disposition != REG_CREATED_NEW_KEY {
            unsafe {
                RegCloseKey(root);
            }
            return Err(io::Error::other("owned registry namespace already exists"));
        }
        let mut projection = Self {
            root: OwnedKey(root),
            nodes: Vec::new(),
            manifest,
            declaration,
            deadline,
            retired: false,
            transferred: false,
            recipients_retired: false,
            source_security: security_before,
            namespace,
            cleanup_deadline,
        };
        let populated = projection.populate(&mut attributes);
        if let Err(primary) = populated {
            return match projection.retire() {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(failures(primary, cleanup)),
            };
        }
        Ok(projection)
    }
    fn populate(&mut self, attributes: &mut SECURITY_ATTRIBUTES) -> io::Result<()> {
        let mut keys = self.manifest.keys.clone();
        keys.sort_by(|a, b| a.path.cmp(&b.path));
        let mut created = std::collections::BTreeMap::<Vec<Vec<u16>>, usize>::new();
        for entry in keys {
            live(self.deadline)?;
            let mut components = PARAMETERS
                .split('\\')
                .map(|part| part.encode_utf16().collect::<Vec<_>>())
                .collect::<Vec<_>>();
            components.extend(entry.path.iter().cloned());
            let mut parent = self.root.raw();
            let mut path = Vec::new();
            let final_component = components.len() - 1;
            for (component_index, component) in components.into_iter().enumerate() {
                path.push(component.clone());
                if let Some(index) = created.get(&path) {
                    parent = self.nodes[*index].raw();
                    continue;
                }
                let mut name = component;
                name.push(0);
                let mut class = if component_index == final_component {
                    entry.class.clone()
                } else {
                    Vec::new()
                };
                class.push(0);
                let mut raw = ptr::null_mut();
                let mut disposition = 0;
                live(self.deadline)?;
                status(unsafe {
                    RegCreateKeyExW(
                        parent,
                        name.as_ptr(),
                        0,
                        class.as_ptr(),
                        REG_OPTION_VOLATILE,
                        KEY_ALL_ACCESS,
                        attributes,
                        &mut raw,
                        &mut disposition,
                    )
                })?;
                let key = OwnedKey(raw);
                if disposition != REG_CREATED_NEW_KEY {
                    return Err(io::Error::other(
                        "projection descendant unexpectedly existed",
                    ));
                }
                parent = key.raw();
                created.insert(path.clone(), self.nodes.len());
                self.nodes.push(key);
            }
            for value in &entry.values {
                live(self.deadline)?;
                let mut name = value.name.clone();
                name.push(0);
                status(unsafe {
                    RegSetValueExW(
                        parent,
                        name.as_ptr(),
                        0,
                        value.kind,
                        value.bytes.as_ptr(),
                        value.bytes.len() as u32,
                    )
                })?;
            }
        }
        self.verify_owned()?;
        // Retain only controller-owned pre-seal setup references. All future
        // opens, including an ordinary same-owner workload, are read-only;
        // OWNER_RIGHTS explicitly removes implicit owner WRITE_DAC authority.
        let sddl = wide("D:P(A;;KR;;;SY)(A;;KR;;;OW)(A;;KR;;;RC)");
        let mut sd = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sealed = (|| {
            for key in self.nodes.iter().chain(std::iter::once(&self.root)) {
                live(self.deadline)?;
                status(unsafe { RegSetKeySecurity(key.raw(), DACL_SECURITY_INFORMATION, sd) })?;
            }
            self.verify_owned()
        })();
        unsafe {
            LocalFree(sd);
        }
        sealed
    }
    pub fn verify_owned(&self) -> io::Result<()> {
        verify(self.root.raw(), &self.declaration, self.deadline)
    }
    /// Deliver this sealed owned dependency only to the same retained process.
    /// The returned scalar is target-local wire data, never an adoption API.
    pub fn duplicate_into(
        &mut self,
        target: &super::WindowsImageProcess,
        deadline: Instant,
    ) -> io::Result<u64> {
        if deadline != self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry transfer differs from original work cutoff",
            ));
        }
        self.verify_owned()?;
        // SAFETY: this exclusive owner retains the live registry reference
        // through the native duplicate; target retains its original process.
        let handle = unsafe { target.duplicate_registry_input(self.root.raw(), deadline) }?;
        self.transferred = true;
        live(deadline)?;
        Ok(handle)
    }
    pub fn diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"format":"memcordon.fixture-winsock-registry-input","version":1,"declaration":self.declaration,"owned_namespace_hkcu":self.namespace,"retirement_observed":self.retired,"source_security_information":7,"source_security_bytes":self.source_security,"source_security_sha256":hex_digest(&self.source_security),"source_label_captured":false,"source_view":"native","scope":"exact native WinSock2 Parameters subtree projected below owned HKLM root","host_registry_policy_changed":false,"acceptance_authority":false})
    }
    fn transferred(&mut self) {
        self.transferred = true;
    }
    pub fn recipients_retired(&mut self) {
        self.recipients_retired = true;
    }
    pub fn retire_if_safe(&mut self) -> io::Result<()> {
        if self.transferred && !self.recipients_retired {
            return Err(io::Error::other(
                "registry input retained: original recipient retirement is unproved",
            ));
        }
        self.retire()
    }
    /// Call only after all admitted original roots/descendants have settled.
    pub fn retire(&mut self) -> io::Result<()> {
        if self.retired {
            return Ok(());
        }
        // Work cutoff cannot prohibit owned cleanup. This is the original held
        // object, never deletion through a rediscovered HKCU path.
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtDeleteKey(key: HKEY) -> i32;
        }
        // Delete deepest first through original retained references, never
        // recurse through names which another process could replace.
        while let Some(key) = self.nodes.last() {
            live(self.cleanup_deadline)?;
            let result = unsafe { NtDeleteKey(key.raw()) };
            if result < 0 {
                return Err(io::Error::other(format!(
                    "NtDeleteKey original fixture descendant failed: {result:#x}"
                )));
            }
            self.nodes.pop();
        }
        live(self.cleanup_deadline)?;
        let result = unsafe { NtDeleteKey(self.root.raw()) };
        if result < 0 {
            return Err(io::Error::other(format!(
                "NtDeleteKey original fixture root failed: {result:#x}"
            )));
        }
        self.retired = true;
        live(self.cleanup_deadline)
    }
}
impl Drop for Projection {
    fn drop(&mut self) {
        if !self.retired {
            eprintln!(
                "owned Winsock registry projection was not explicitly retired; namespace=HKCU\\{}; manifest={:?}; dependency retained for cleanup diagnosis",
                self.namespace, self.declaration.sha256
            );
        }
    }
}

fn verify(root: HKEY, declaration: &Declaration, deadline: Instant) -> io::Result<()> {
    verified_manifest(root, declaration, deadline).map(|_| ())
}
fn verified_manifest(
    root: HKEY,
    declaration: &Declaration,
    deadline: Instant,
) -> io::Result<Manifest> {
    declaration.validate().map_err(io::Error::other)?;
    let parameters = open(
        root,
        &PARAMETERS.encode_utf16().collect::<Vec<_>>(),
        KEY_READ,
        deadline,
    )?;
    let actual = coherent(parameters.raw(), deadline)?;
    if actual.digest().map_err(io::Error::other)? != declaration.sha256 {
        return Err(io::Error::other("registry input manifest digest differs"));
    }
    live(deadline)?;
    Ok(actual)
}

pub struct Mapping {
    key: OwnedKey,
    active: bool,
    deadline: Instant,
}
impl Mapping {
    pub fn install(
        key: OwnedKey,
        declaration: &Declaration,
        deadline: Instant,
    ) -> io::Result<Self> {
        let manifest = verified_manifest(key.raw(), declaration, deadline)?;
        immutable(key.raw(), &manifest, deadline)?;
        live(deadline)?;
        status(unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, key.raw()) })?;
        Ok(Self {
            key,
            active: true,
            deadline,
        })
    }
    pub fn raw(&self) -> HKEY {
        self.key.raw()
    }
    fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        status(unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, ptr::null_mut()) })
    }
    pub fn run<T>(mut self, operation: impl FnOnce(&Self) -> io::Result<T>) -> io::Result<T> {
        let result = live(self.deadline).and_then(|()| operation(&self));
        let result = match (result, live(self.deadline)) {
            (Err(primary), Err(secondary)) => Err(failures(primary, secondary)),
            (Err(primary), _) => Err(primary),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        };
        let restored = self.restore().and_then(|()| live(self.deadline));
        match (result, restored) {
            (Err(primary), Err(secondary)) => Err(failures(primary, secondary)),
            (Err(primary), _) => Err(primary),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}

fn immutable(root: HKEY, manifest: &Manifest, deadline: Instant) -> io::Result<()> {
    live(deadline)?;
    for access in [KEY_SET_VALUE, KEY_CREATE_SUB_KEY, 0x0001_0000, 0x0004_0000] {
        match open(root, &[], access, deadline) {
            Err(error) if error.raw_os_error() == Some(5) => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::other(
                    "sealed registry input permits mutation access",
                ));
            }
        }
        live(deadline)?;
    }
    let name = wide("memcordon-immutable-denial-probe");
    live(deadline)?;
    let mut created = ptr::null_mut();
    let mut disposition = 0;
    let result = unsafe {
        RegCreateKeyExW(
            root,
            name.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_VOLATILE,
            KEY_READ,
            ptr::null(),
            &mut created,
            &mut disposition,
        )
    };
    if !created.is_null() {
        unsafe {
            RegCloseKey(created);
        }
    }
    if result != 5 {
        return Err(io::Error::other(format!(
            "sealed registry input create was not denied: LSTATUS={result}"
        )));
    }
    live(deadline)?;
    let result = unsafe { RegSetValueExW(root, name.as_ptr(), 0, REG_BINARY, [1u8].as_ptr(), 1) };
    if result != 5 {
        return Err(io::Error::other(format!(
            "sealed registry input write was not denied: LSTATUS={result}"
        )));
    }
    let leaf = manifest
        .keys
        .iter()
        .max_by_key(|key| key.path.len())
        .ok_or_else(|| io::Error::other("verified registry manifest has no leaf"))?;
    let mut leaf_path = PARAMETERS.encode_utf16().collect::<Vec<_>>();
    for component in &leaf.path {
        leaf_path.push(b'\\' as u16);
        leaf_path.extend(component);
    }
    leaf_path.push(0);
    live(deadline)?;
    let result = unsafe { RegDeleteKeyExW(root, leaf_path.as_ptr(), 0, 0) };
    if result != 5 {
        return Err(io::Error::other(format!(
            "sealed registry input delete was not denied: LSTATUS={result}"
        )));
    }
    let mut security = source_security(root, deadline)?;
    live(deadline)?;
    let result = unsafe {
        RegSetKeySecurity(
            root,
            DACL_SECURITY_INFORMATION,
            security.as_mut_ptr().cast(),
        )
    };
    if result != 5 {
        return Err(io::Error::other(format!(
            "sealed registry input DACL change was not denied: LSTATUS={result}"
        )));
    }
    live(deadline)
}

fn key_name(root: HKEY, deadline: Instant) -> io::Result<Vec<u16>> {
    live(deadline)?;
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryKey(
            key: HKEY,
            class: u32,
            bytes: *mut std::ffi::c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut bytes = [0u64; 512];
    let mut returned = 0;
    let result = unsafe {
        NtQueryKey(
            root,
            3,
            bytes.as_mut_ptr().cast(),
            std::mem::size_of_val(&bytes) as u32,
            &mut returned,
        )
    };
    if result < 0 {
        return Err(io::Error::other(format!(
            "registry key name query failed: {result:#x}"
        )));
    }
    let raw = unsafe {
        std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), std::mem::size_of_val(&bytes))
    };
    let length =
        u32::from_le_bytes(raw[..4].try_into().expect("fixed native name prefix")) as usize;
    if length % std::mem::size_of::<u16>() != 0
        || length + 4 > returned as usize
        || returned as usize > raw.len()
    {
        return Err(io::Error::other("native key name extent malformed"));
    }
    live(deadline)?;
    Ok(raw[4..4 + length]
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect())
}

/// CI-only child proves process-local HKLM mappings are not inherited.
pub fn uninherited_self_check(deadline: Instant) -> io::Result<i32> {
    let root = open(
        HKEY_LOCAL_MACHINE,
        &"System".encode_utf16().collect::<Vec<_>>(),
        KEY_READ,
        deadline,
    )?;
    if !String::from_utf16(&key_name(root.raw(), deadline)?)
        .map_err(io::Error::other)?
        .eq_ignore_ascii_case("\\REGISTRY\\MACHINE\\SYSTEM")
    {
        return Err(io::Error::other(
            "fixture mapping leaked into a newly created process",
        ));
    }
    Ok(0)
}

/// Native API regression; executed only by the early Windows fixture suite.
pub fn self_check(
    mut child_command: impl FnMut(Instant) -> io::Result<std::process::Command>,
    settle_child: impl Fn(&mut std::process::Child, io::Error, Instant) -> io::Error,
) -> io::Result<i32> {
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        time::Duration,
    };
    use windows_sys::Win32::{
        Foundation::DuplicateHandle,
        Security::{
            Authorization::ConvertStringSidToSidW, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE,
            ImpersonateLoggedOnUser, RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE,
            TOKEN_QUERY,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let nonce = hex_digest(
        format!(
            "{:?}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        )
        .as_bytes(),
    );
    let mut projection = Projection::create(&nonce, deadline, deadline)?;
    let tested = (|| -> io::Result<()> {
        let source = open(
            HKEY_LOCAL_MACHINE,
            &PARAMETERS.encode_utf16().collect::<Vec<_>>(),
            KEY_READ,
            deadline,
        )?;
        let source_before = coherent(source.raw(), deadline)?
            .digest()
            .map_err(io::Error::other)?;
        let source_sd = source_security(source.raw(), deadline)?;
        let declaration = projection.declaration().clone();
        let mut mismatch = declaration.clone();
        mismatch.sha256[0] ^= 1;
        if verify(projection.raw(), &mismatch, deadline).is_ok()
            || verify(projection.raw(), &declaration, Instant::now()).is_ok()
        {
            return Err(io::Error::other(
                "registry dependency mismatch/cutoff was not refused",
            ));
        }
        if projection.diagnostic()["acceptance_authority"] != false {
            return Err(io::Error::other(
                "registry input diagnosis claimed authority",
            ));
        }
        let mut original = ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut original,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let original = unsafe { OwnedHandle::from_raw_handle(original) };
        let original_before =
            memcordon_windows_launch_core::query_token_envelope(original.as_raw_handle())
                .map_err(io::Error::other)?;
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide("S-1-5-12").as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let restricting = SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0,
        };
        let mut restricted = ptr::null_mut();
        let made = unsafe {
            CreateRestrictedToken(
                original.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                0,
                ptr::null(),
                0,
                ptr::null(),
                1,
                &restricting,
                &mut restricted,
            )
        };
        let creation_error = if made == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe {
            LocalFree(sid);
        }
        if let Some(error) = creation_error {
            return Err(error);
        }
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
        let before =
            memcordon_windows_launch_core::query_token_envelope(restricted.as_raw_handle())
                .map_err(io::Error::other)?;
        let mut duplicate = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                projection.raw(),
                GetCurrentProcess(),
                &mut duplicate,
                KEY_READ,
                0,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let key = unsafe { OwnedKey::from_transferred(duplicate as usize as u64, deadline) }?;
        live(deadline)?;
        if unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        struct Impersonation;
        impl Drop for Impersonation {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        let impersonation = Impersonation;
        let mapped = (|| -> io::Result<()> {
            let mapping = Mapping::install(key, &declaration, deadline)?;
            mapping.run(|mapping| {
                let system = "System".encode_utf16().collect::<Vec<_>>();
                let mapped_system = open(HKEY_LOCAL_MACHINE, &system, KEY_READ, deadline)?;
                let held_system = open(mapping.raw(), &system, KEY_READ, deadline)?;
                // Independent opens may create distinct KEY objects for one key.
                // Full native names check mapping readback, never reference identity;
                // RegOverridePredefKey receives the original admitted held key.
                if key_name(mapped_system.raw(), deadline)?
                    != key_name(held_system.raw(), deadline)?
                {
                    return Err(io::Error::other(
                        "process-local mapping readback differs from held input namespace",
                    ));
                }
                live(deadline)?;
                let mut command = child_command(deadline)?;
                live(deadline)?;
                let mut child = command
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::inherit())
                    .spawn()?;
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) if status.success() => break,
                        Ok(Some(status)) => {
                            return Err(io::Error::other(format!(
                                "registry mapping child failed: {status}"
                            )));
                        }
                        Err(error) => return Err(settle_child(&mut child, error, deadline)),
                        Ok(None) if Instant::now() >= deadline => {
                            return Err(settle_child(
                                &mut child,
                                io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "original registry selfcheck cutoff exhausted",
                                ),
                                deadline,
                            ));
                        }
                        Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                    }
                }
                drop(mapped_system);
                drop(held_system);
                Ok(())
            })
        })();
        drop(impersonation);
        mapped?;
        if memcordon_windows_launch_core::query_token_envelope(restricted.as_raw_handle())
            .map_err(io::Error::other)?
            != before
            || memcordon_windows_launch_core::query_token_envelope(original.as_raw_handle())
                .map_err(io::Error::other)?
                != original_before
        {
            return Err(io::Error::other(
                "registry dependency changed the original token",
            ));
        }
        if coherent(source.raw(), deadline)?
            .digest()
            .map_err(io::Error::other)?
            != source_before
            || source_security(source.raw(), deadline)? != source_sd
        {
            return Err(io::Error::other(
                "native source data/security changed during owned registry test",
            ));
        }
        uninherited_self_check(deadline)?; // This process restored its own default HKLM.
        projection.transferred();
        projection.recipients_retired();
        live(deadline)
    })();
    let retired = projection.retire_if_safe();
    match (tested, retired) {
        (Err(primary), Err(secondary)) => Err(failures(primary, secondary)),
        (Err(primary), _) => Err(primary),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(0),
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("native registry mapping restoration failed during unwind: {error}");
            // No subsequent native operation may silently use an unretired map.
            std::process::abort();
        }
    }
}
