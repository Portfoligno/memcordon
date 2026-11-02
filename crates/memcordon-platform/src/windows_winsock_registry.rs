//! Explicit native Winsock configuration input; never host policy mutation.
use crate::windows_registry_error::{at, failures, require_access_denied};
use crate::windows_registry_manifest::{Declaration, Key, Manifest, ValueRecord, View};
use crate::windows_registry_seal::{ReadAce, read_trustees, validate_read_acl, validate_sid};
use std::{io, ptr, time::Instant};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_ITEMS, FILETIME, LocalFree},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{READ_CONTROL, WRITE_DAC},
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
fn status_at(
    value: u32,
    phase: &'static str,
    api: &'static str,
    access: Option<u32>,
) -> io::Result<()> {
    at(status(value), phase, api, "LSTATUS", access)
}
fn denied_status(
    value: u32,
    phase: &'static str,
    api: &'static str,
    access: Option<u32>,
) -> io::Result<()> {
    if value == 5 {
        return Ok(());
    }
    // Preserve the assertion's original Other kind while retaining an actual
    // unexpected LSTATUS as a typed source. Successful mutation is still fatal.
    let error = if value == 0 {
        io::Error::other("sealed registry input mutation unexpectedly succeeded")
    } else {
        io::Error::other(io::Error::from_raw_os_error(value as i32))
    };
    at(Err(error), phase, api, "LSTATUS", access)
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
        status_at(
            result,
            "security/size-probe",
            "RegGetKeySecurity",
            Some(READ_CONTROL),
        )?;
    }
    if length == 0 || length > 64 * 1024 {
        return Err(io::Error::other(
            "source registry security descriptor extent exceeds bound",
        ));
    }
    let mut bytes = vec![0; length as usize];
    status_at(
        unsafe { RegGetKeySecurity(root, 7, bytes.as_mut_ptr().cast(), &mut length) },
        "security/read",
        "RegGetKeySecurity",
        Some(READ_CONTROL),
    )?;
    if length as usize != bytes.len() {
        return Err(io::Error::other(
            "source registry security descriptor changed extent",
        ));
    }
    live(deadline)?;
    Ok(bytes)
}

enum ReaderToken {
    CreatorPrimary,
    RecipientEffective,
}

fn reader_user(source: ReaderToken, deadline: Instant) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    // These are borrowed query-only, same-thread pseudo handles, never native
    // owners. The Windows SDK processthreadsapi.h inline accessors return -4
    // (GetCurrentProcessToken) and -6 (GetCurrentThreadEffectiveToken).
    // Select the role immediately before synchronous observation; do not cache
    // the effective token across an impersonation transition or send it away.
    let (token, phase) = match source {
        ReaderToken::CreatorPrimary => (-4_isize, "seal/creator-primary-user"),
        ReaderToken::RecipientEffective => (-6_isize, "seal/recipient-effective-user"),
    };
    let token = token as windows_sys::Win32::Foundation::HANDLE;
    live(deadline)?;
    let mut length = 0;
    let result = unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length) };
    if result == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(122) {
            return at(
                Err(error),
                phase,
                "GetTokenInformation(TokenUser)",
                "Win32",
                Some(TOKEN_QUERY),
            );
        }
    }
    let bound = std::mem::size_of::<TOKEN_USER>()
        + SECURITY_MAX_SID_SIZE as usize
        + std::mem::align_of::<usize>();
    if length == 0 || length as usize > bound {
        return Err(io::Error::other(
            "reader TokenUser extent exceeds native SID bound",
        ));
    }
    live(deadline)?;
    let mut storage = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    let provided = length;
    live(deadline)?;
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast(),
            provided,
            &mut length,
        )
    } == 0
    {
        return at(
            Err(io::Error::last_os_error()),
            phase,
            "GetTokenInformation(TokenUser)",
            "Win32",
            Some(TOKEN_QUERY),
        );
    }
    if length > provided {
        return Err(io::Error::other(
            "reader TokenUser returned extent exceeds allocation",
        ));
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().cast::<u8>(),
            std::mem::size_of_val(storage.as_slice()),
        )
    };
    let sid = crate::sealed::windows::token_user_sid(bytes, length as usize)
        .map_err(io::Error::other)?
        .to_vec();
    validate_sid(&sid).map_err(io::Error::other)?;
    live(deadline)?;
    Ok(sid)
}

fn sid_text(sid: &[u8], deadline: Instant) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    validate_sid(sid).map_err(io::Error::other)?;
    live(deadline)?;
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut text) } == 0 {
        return at(
            Err(io::Error::last_os_error()),
            "seal/reader-text",
            "ConvertSidToStringSidW",
            "Win32",
            None,
        );
    }
    struct SidText(*mut u16);
    impl Drop for SidText {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
    let text = SidText(text);
    if text.0.is_null() {
        return Err(io::Error::other("native SID string result is null"));
    }
    let mut units = Vec::new();
    for index in 0..256 {
        let unit = unsafe { *text.0.add(index) };
        if unit == 0 {
            let result = String::from_utf16(&units).map_err(io::Error::other)?;
            live(deadline)?;
            return Ok(result);
        }
        units.push(unit);
    }
    Err(io::Error::other(
        "native SID string exceeds fixed SID bound",
    ))
}

fn bounded_sid(bytes: &[u8], sid: *const std::ffi::c_void) -> io::Result<Vec<u8>> {
    let offset = (sid as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .ok_or_else(|| io::Error::other("owned security SID precedes descriptor"))?;
    let prefix = bytes
        .get(offset..)
        .and_then(|tail| tail.get(..8))
        .ok_or_else(|| io::Error::other("owned security SID header exceeds descriptor"))?;
    let extent = 8 + usize::from(prefix[1]) * std::mem::size_of::<u32>();
    let sid = bytes
        .get(offset..)
        .and_then(|tail| tail.get(..extent))
        .ok_or_else(|| io::Error::other("owned security SID exceeds descriptor"))?;
    validate_sid(sid).map_err(io::Error::other)?;
    Ok(sid.to_vec())
}

fn read_seal(root: HKEY, reader: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, SE_DACL_PROTECTED,
    };
    let bytes = source_security(root, deadline)?;
    let descriptor = bytes.as_ptr().cast_mut().cast();
    let mut control = 0;
    let mut revision = 0;
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    let mut present = 0;
    let mut acl = ptr::null_mut();
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return at(
            Err(io::Error::last_os_error()),
            "seal/read-control",
            "GetSecurityDescriptorControl",
            "Win32",
            None,
        );
    }
    live(deadline)?;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0 {
        return at(
            Err(io::Error::last_os_error()),
            "seal/read-owner",
            "GetSecurityDescriptorOwner",
            "Win32",
            None,
        );
    }
    // Observe the real owner; it is deliberately not assumed to equal TokenUser.
    bounded_sid(&bytes, owner)?;
    live(deadline)?;
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } == 0
    {
        return at(
            Err(io::Error::last_os_error()),
            "seal/read-dacl",
            "GetSecurityDescriptorDacl",
            "Win32",
            None,
        );
    }
    if control & SE_DACL_PROTECTED == 0 || present == 0 || acl.is_null() {
        return Err(io::Error::other(
            "owned registry seal is not a protected nonnull DACL",
        ));
    }
    let offset = (acl as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .ok_or_else(|| io::Error::other("owned DACL precedes descriptor"))?;
    let header = bytes
        .get(offset..)
        .and_then(|tail| tail.get(..std::mem::size_of::<ACL>()))
        .ok_or_else(|| io::Error::other("owned DACL header exceeds descriptor"))?;
    let acl = unsafe { ptr::read_unaligned(header.as_ptr().cast::<ACL>()) };
    let acl_bytes = bytes
        .get(offset..)
        .and_then(|tail| tail.get(..usize::from(acl.AclSize)))
        .ok_or_else(|| io::Error::other("owned DACL extent exceeds descriptor"))?;
    if acl.AceCount > 4 {
        return Err(io::Error::other("owned read seal has unexpected ACE count"));
    }
    let mut cursor = std::mem::size_of::<ACL>();
    let mut aces = Vec::new();
    for _ in 0..acl.AceCount {
        live(deadline)?;
        let header = acl_bytes
            .get(cursor..)
            .and_then(|tail| tail.get(..std::mem::size_of::<ACE_HEADER>()))
            .ok_or_else(|| io::Error::other("owned ACE header exceeds DACL"))?;
        let header = unsafe { ptr::read_unaligned(header.as_ptr().cast::<ACE_HEADER>()) };
        let ace = acl_bytes
            .get(cursor..)
            .and_then(|tail| tail.get(..usize::from(header.AceSize)))
            .ok_or_else(|| io::Error::other("owned ACE extent exceeds DACL"))?;
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if header.AceType != 0 || ace.len() < sid_offset {
            return Err(io::Error::other(
                "owned seal ACE is not a complete access allow entry",
            ));
        }
        let mask = u32::from_le_bytes(ace[4..sid_offset].try_into().map_err(io::Error::other)?);
        let sid = ace[sid_offset..].to_vec();
        aces.push(ReadAce {
            kind: header.AceType,
            flags: header.AceFlags,
            mask,
            sid,
        });
        cursor += usize::from(header.AceSize);
    }
    validate_read_acl(reader, &aces).map_err(io::Error::other)?;
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
            return at(
                Err(io::Error::last_os_error()),
                "adopt/handle-flags",
                "GetHandleInformation",
                "Win32",
                None,
            );
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
                "registry input granted-access query failed: phase=adopt/object-basic; operation=NtQueryObject; native-error-domain=NTSTATUS; class=ObjectBasicInformation({ObjectBasicInformation}); NTSTATUS={result} ({result:#010x}); provided-bytes={provided}; returned-bytes={returned}; failed-output-not-authoritative=true"
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
fn open_at(
    parent: HKEY,
    name: &[u16],
    access: u32,
    deadline: Instant,
    phase: &'static str,
) -> io::Result<OwnedKey> {
    at(
        open(parent, name, access, deadline),
        phase,
        "RegOpenKeyExW",
        "LSTATUS",
        Some(access),
    )
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
        status_at(
            unsafe {
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
            },
            "capture/key-metadata",
            "RegQueryInfoKeyW",
            Some(KEY_READ),
        )?;
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
            status_at(
                unsafe {
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
                },
                "capture/value-size",
                "RegEnumValueW",
                Some(KEY_READ),
            )?;
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
            status_at(
                unsafe {
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
                },
                "capture/value-data",
                "RegEnumValueW",
                Some(KEY_READ),
            )?;
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
            let error = if end == 0 {
                io::Error::other("registry value enumeration exceeded observed count")
            } else {
                io::Error::other(io::Error::from_raw_os_error(end as i32))
            };
            return at(
                Err(error),
                "capture/value-end",
                "RegEnumValueW",
                "LSTATUS",
                Some(KEY_READ),
            );
        }
        for index in 0..subkeys {
            live(deadline)?;
            let mut name = vec![0u16; 256];
            let mut length = name.len() as u32;
            status_at(
                unsafe {
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
                },
                "capture/subkey-name",
                "RegEnumKeyExW",
                Some(KEY_READ),
            )?;
            name.truncate(length as usize);
            let child = open_at(raw, &name, KEY_READ, deadline, "capture/subkey-open")?;
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
            let error = if end == 0 {
                io::Error::other("registry key enumeration exceeded observed count")
            } else {
                io::Error::other(io::Error::from_raw_os_error(end as i32))
            };
            return at(
                Err(error),
                "capture/key-end",
                "RegEnumKeyExW",
                "LSTATUS",
                Some(KEY_READ),
            );
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
    reader_sid: Vec<u8>,
    sealed: bool,
    root_security: Vec<u8>,
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
        let source = open_at(
            HKEY_LOCAL_MACHINE,
            &PARAMETERS.encode_utf16().collect::<Vec<_>>(),
            KEY_READ,
            deadline,
            "projection/source-open",
        )?;
        let security_before = at(
            source_security(source.raw(), deadline),
            "projection/source-security-before",
            "RegGetKeySecurity",
            "boundary",
            Some(READ_CONTROL),
        )?;
        let manifest = at(
            coherent(source.raw(), deadline),
            "projection/source-snapshot",
            "coherent",
            "boundary",
            Some(KEY_READ),
        )?;
        if at(
            source_security(source.raw(), deadline),
            "projection/source-security-after",
            "RegGetKeySecurity",
            "boundary",
            Some(READ_CONTROL),
        )? != security_before
        {
            return Err(io::Error::other(
                "source registry security changed during capture",
            ));
        }
        let declaration = manifest.declaration().map_err(io::Error::other)?;
        let reader_sid = reader_user(ReaderToken::CreatorPrimary, deadline)?;
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
            return at(
                Err(io::Error::last_os_error()),
                "projection/setup-security",
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                "Win32",
                None,
            );
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
        status_at(
            unsafe {
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
            },
            "projection/root-create",
            "RegCreateKeyExW",
            Some(KEY_ALL_ACCESS),
        )?;
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
            reader_sid,
            sealed: false,
            root_security: Vec::new(),
        };
        let populated = at(
            projection.populate(&mut attributes),
            "projection/populate-seal",
            "populate",
            "boundary",
            None,
        );
        if let Err(primary) = populated {
            return match at(
                projection.retire(),
                "projection/failure-retire",
                "Projection::retire",
                "boundary",
                None,
            ) {
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
                status_at(
                    unsafe {
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
                    },
                    "projection/descendant-create",
                    "RegCreateKeyExW",
                    Some(KEY_ALL_ACCESS),
                )?;
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
                status_at(
                    unsafe {
                        RegSetValueExW(
                            parent,
                            name.as_ptr(),
                            0,
                            value.kind,
                            value.bytes.as_ptr(),
                            value.bytes.len() as u32,
                        )
                    },
                    "projection/value-copy",
                    "RegSetValueExW",
                    Some(KEY_SET_VALUE),
                )?;
            }
        }
        at(
            self.verify_owned(),
            "projection/copied-readback",
            "verify_owned",
            "boundary",
            Some(KEY_READ),
        )?;
        // Retain only controller-owned pre-seal setup references. All future
        // opens, including an ordinary same-owner workload, are read-only;
        // OWNER_RIGHTS explicitly removes implicit owner WRITE_DAC authority.
        let mut seal = String::from("D:P");
        for sid in read_trustees(&self.reader_sid).map_err(io::Error::other)? {
            seal.push_str("(A;;KR;;;");
            seal.push_str(&sid_text(&sid, self.deadline)?);
            seal.push(')');
        }
        let sddl = wide(&seal);
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
            return at(
                Err(io::Error::last_os_error()),
                "projection/seal-security",
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                "Win32",
                None,
            );
        }
        let sealed = (|| {
            for key in self.nodes.iter().chain(std::iter::once(&self.root)) {
                live(self.deadline)?;
                status_at(
                    unsafe { RegSetKeySecurity(key.raw(), DACL_SECURITY_INFORMATION, sd) },
                    "projection/seal-dacl",
                    "RegSetKeySecurity",
                    Some(WRITE_DAC),
                )?;
            }
            self.sealed = true;
            self.root_security = read_seal(self.root.raw(), &self.reader_sid, self.deadline)?;
            at(
                self.verify_owned(),
                "projection/sealed-readback",
                "verify_owned",
                "boundary",
                Some(KEY_READ),
            )
        })();
        unsafe {
            LocalFree(sd);
        }
        sealed
    }
    pub fn verify_owned(&self) -> io::Result<()> {
        if self.sealed {
            for key in self.nodes.iter().chain(std::iter::once(&self.root)) {
                at(
                    read_seal(key.raw(), &self.reader_sid, self.deadline),
                    "seal/effective-readback",
                    "RegGetKeySecurity",
                    "boundary",
                    Some(READ_CONTROL),
                )?;
            }
        }
        at(
            verify(self.root.raw(), &self.declaration, self.deadline),
            "projection/owned-verify",
            "verify",
            "boundary",
            Some(KEY_READ),
        )
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
        let intended = sid_text(&self.reader_sid, deadline)?;
        if at(
            target.original_token_envelope(deadline),
            "seal/recipient-token",
            "WindowsImageProcess::original_token_envelope",
            "boundary",
            Some(windows_sys::Win32::Security::TOKEN_QUERY),
        )?
        .user_sid
            != intended
        {
            return Err(io::Error::other(
                "held registry recipient TokenUser differs from captured intended reader",
            ));
        }
        // SAFETY: this exclusive owner retains the live registry reference
        // through the native duplicate; target retains its original process.
        let handle = at(
            unsafe { target.duplicate_registry_input(self.root.raw(), deadline) },
            "projection/held-root-duplicate",
            "DuplicateHandle",
            "Win32",
            Some(KEY_READ),
        )?;
        self.transferred = true;
        live(deadline)?;
        Ok(handle)
    }
    pub fn diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"format":"memcordon.fixture-winsock-registry-input","version":1,"declaration":self.declaration,"owned_namespace_hkcu":self.namespace,"retirement_observed":self.retired,"source_security_information":7,"source_security_bytes":self.source_security,"source_security_sha256":hex_digest(&self.source_security),"source_label_captured":false,"source_view":"native","intended_reader_sid":self.reader_sid,"owned_root_security_at_seal":self.root_security,"owned_seal_verified_at_creation":self.sealed,"scope":"exact native WinSock2 Parameters subtree projected below owned HKLM root","host_registry_policy_changed":false,"acceptance_authority":false})
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
        at(
            self.retire(),
            "retire/owned-keys",
            "Projection::retire",
            "boundary",
            None,
        )
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
                    "phase=retire/held-descendant; api=NtDeleteKey; native-error-domain=NTSTATUS; native-code={result} ({result:#010x})"
                )));
            }
            self.nodes.pop();
        }
        live(self.cleanup_deadline)?;
        let result = unsafe { NtDeleteKey(self.root.raw()) };
        if result < 0 {
            return Err(io::Error::other(format!(
                "phase=retire/held-root; api=NtDeleteKey; native-error-domain=NTSTATUS; native-code={result} ({result:#010x})"
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
    let parameters = open_at(
        root,
        &PARAMETERS.encode_utf16().collect::<Vec<_>>(),
        KEY_READ,
        deadline,
        "verify/parameters-open",
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
        let reader = reader_user(ReaderToken::RecipientEffective, deadline)?;
        at(
            read_seal(key.raw(), &reader, deadline),
            "mapping/intended-reader-seal",
            "RegGetKeySecurity",
            "boundary",
            Some(READ_CONTROL),
        )?;
        let manifest = at(
            verified_manifest(key.raw(), declaration, deadline),
            "mapping/manifest-readback",
            "verified_manifest",
            "boundary",
            Some(KEY_READ),
        )?;
        at(
            immutable(key.raw(), &manifest, deadline),
            "mapping/immutability",
            "immutable",
            "boundary",
            Some(KEY_READ),
        )?;
        live(deadline)?;
        status_at(
            unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, key.raw()) },
            "mapping/install",
            "RegOverridePredefKey",
            Some(KEY_READ),
        )?;
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
        status_at(
            unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, ptr::null_mut()) },
            "mapping/restore",
            "RegOverridePredefKey",
            None,
        )
    }
    pub fn run<T>(mut self, operation: impl FnOnce(&Self) -> io::Result<T>) -> io::Result<T> {
        let result = at(
            live(self.deadline),
            "mapping/pre-operation-cutoff",
            "Instant",
            "deadline",
            None,
        )
        .and_then(|()| operation(&self));
        let result = match (
            result,
            at(
                live(self.deadline),
                "mapping/post-operation-cutoff",
                "Instant",
                "deadline",
                None,
            ),
        ) {
            (Err(primary), Err(secondary)) => Err(failures(primary, secondary)),
            (Err(primary), _) => Err(primary),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        };
        let restored = self.restore().and_then(|()| {
            at(
                live(self.deadline),
                "mapping/post-restore-cutoff",
                "Instant",
                "deadline",
                None,
            )
        });
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
        require_access_denied(
            open(root, &[], access, deadline),
            "immutable/mutation-open",
            "RegOpenKeyExW",
            Some(access),
        )?;
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
    denied_status(
        result,
        "immutable/create",
        "RegCreateKeyExW",
        Some(KEY_READ),
    )?;
    live(deadline)?;
    let result = unsafe { RegSetValueExW(root, name.as_ptr(), 0, REG_BINARY, [1u8].as_ptr(), 1) };
    denied_status(
        result,
        "immutable/write",
        "RegSetValueExW",
        Some(KEY_SET_VALUE),
    )?;
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
    denied_status(
        result,
        "immutable/delete-leaf",
        "RegDeleteKeyExW",
        Some(0x0001_0000),
    )?;
    let mut security = at(
        source_security(root, deadline),
        "immutable/dacl-readback",
        "RegGetKeySecurity",
        "boundary",
        Some(READ_CONTROL),
    )?;
    live(deadline)?;
    let result = unsafe {
        RegSetKeySecurity(
            root,
            DACL_SECURITY_INFORMATION,
            security.as_mut_ptr().cast(),
        )
    };
    denied_status(
        result,
        "immutable/dacl-change",
        "RegSetKeySecurity",
        Some(WRITE_DAC),
    )?;
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
            "phase=mapping/native-name; api=NtQueryKey; class=KeyNameInformation(3); native-error-domain=NTSTATUS; native-code={result} ({result:#010x}); provided-bytes={}; returned-bytes={returned}",
            std::mem::size_of_val(&bytes)
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
    let root = open_at(
        HKEY_LOCAL_MACHINE,
        &"System".encode_utf16().collect::<Vec<_>>(),
        KEY_READ,
        deadline,
        "selfcheck/uninherited-system-open",
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
    let mut projection = at(
        Projection::create(&nonce, deadline, deadline),
        "selfcheck/projection-create-seal",
        "Projection::create",
        "boundary",
        None,
    )?;
    let tested = (|| -> io::Result<()> {
        let source = open_at(
            HKEY_LOCAL_MACHINE,
            &PARAMETERS.encode_utf16().collect::<Vec<_>>(),
            KEY_READ,
            deadline,
            "selfcheck/source-open",
        )?;
        let source_before = at(
            coherent(source.raw(), deadline),
            "selfcheck/source-snapshot-before",
            "coherent",
            "boundary",
            Some(KEY_READ),
        )?
        .digest()
        .map_err(io::Error::other)?;
        let source_sd = at(
            source_security(source.raw(), deadline),
            "selfcheck/source-security-before",
            "RegGetKeySecurity",
            "boundary",
            Some(READ_CONTROL),
        )?;
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
            return at(
                Err(io::Error::last_os_error()),
                "selfcheck/original-token-open",
                "OpenProcessToken",
                "Win32",
                Some(TOKEN_QUERY | TOKEN_DUPLICATE),
            );
        }
        let original = unsafe { OwnedHandle::from_raw_handle(original) };
        let original_before = at(
            memcordon_windows_launch_core::query_token_envelope(original.as_raw_handle())
                .map_err(io::Error::other),
            "selfcheck/original-token-before",
            "query_token_envelope",
            "boundary",
            Some(TOKEN_QUERY),
        )?;
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide("S-1-5-12").as_ptr(), &mut sid) } == 0 {
            return at(
                Err(io::Error::last_os_error()),
                "selfcheck/restricting-sid",
                "ConvertStringSidToSidW",
                "Win32",
                None,
            );
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
            return at(
                Err(error),
                "selfcheck/restricted-token-create",
                "CreateRestrictedToken",
                "Win32",
                None,
            );
        }
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
        let before = at(
            memcordon_windows_launch_core::query_token_envelope(restricted.as_raw_handle())
                .map_err(io::Error::other),
            "selfcheck/restricted-token-before",
            "query_token_envelope",
            "boundary",
            Some(TOKEN_QUERY),
        )?;
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
            return at(
                Err(io::Error::last_os_error()),
                "selfcheck/readonly-key-duplicate",
                "DuplicateHandle",
                "Win32",
                Some(KEY_READ),
            );
        }
        let key = at(
            unsafe { OwnedKey::from_transferred(duplicate as usize as u64, deadline) },
            "selfcheck/readonly-key-adopt",
            "OwnedKey::from_transferred",
            "boundary",
            Some(KEY_READ),
        )?;
        live(deadline)?;
        if unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle()) } == 0 {
            return at(
                Err(io::Error::last_os_error()),
                "selfcheck/restricted-impersonation",
                "ImpersonateLoggedOnUser",
                "Win32",
                None,
            );
        }
        struct Impersonation;
        impl Drop for Impersonation {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() } == 0 {
                    let error = io::Error::last_os_error();
                    use std::io::Write;
                    let _ = writeln!(
                        io::stderr().lock(),
                        "registry phase=selfcheck/mandatory-revert; api=RevertToSelf; native-error-domain=Win32; native-code={:?}; {error}",
                        error.raw_os_error()
                    );
                    std::process::abort();
                }
            }
        }
        let impersonation = Impersonation;
        let mapped = (|| -> io::Result<()> {
            let mapping = at(
                Mapping::install(key, &declaration, deadline),
                "selfcheck/mapping-install",
                "Mapping::install",
                "boundary",
                Some(KEY_READ),
            )?;
            mapping.run(|mapping| {
                let system = "System".encode_utf16().collect::<Vec<_>>();
                let mapped_system = open_at(
                    HKEY_LOCAL_MACHINE,
                    &system,
                    KEY_READ,
                    deadline,
                    "selfcheck/mapped-system-open",
                )?;
                let held_system = open_at(
                    mapping.raw(),
                    &system,
                    KEY_READ,
                    deadline,
                    "selfcheck/held-system-open",
                )?;
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
                let mut command = at(
                    child_command(deadline),
                    "selfcheck/uninherited-child-prepare",
                    "child_command",
                    "boundary",
                    None,
                )?;
                live(deadline)?;
                let mut child = at(
                    command
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::inherit())
                        .spawn(),
                    "selfcheck/uninherited-child-spawn",
                    "Command::spawn",
                    "Win32",
                    None,
                )?;
                loop {
                    match at(
                        child.try_wait(),
                        "selfcheck/uninherited-child-wait",
                        "Child::try_wait",
                        "Win32",
                        None,
                    ) {
                        Ok(Some(status)) if status.success() => break,
                        Ok(Some(status)) => {
                            return Err(io::Error::other(format!(
                                "registry mapping child failed: {status}"
                            )));
                        }
                        Err(error) => {
                            return at(
                                Err(settle_child(&mut child, error, deadline)),
                                "selfcheck/uninherited-child-settle",
                                "settle_child",
                                "boundary",
                                None,
                            );
                        }
                        Ok(None) if Instant::now() >= deadline => {
                            return at(
                                Err(settle_child(
                                    &mut child,
                                    io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        "original registry selfcheck cutoff exhausted",
                                    ),
                                    deadline,
                                )),
                                "selfcheck/uninherited-child-settle",
                                "settle_child",
                                "boundary",
                                None,
                            );
                        }
                        Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                    }
                }
                drop(mapped_system);
                drop(held_system);
                Ok(())
            })
        })();
        if let Err(original) = &mapped {
            use std::io::Write;
            let _ = writeln!(
                io::stderr().lock(),
                "registry original operation before mandatory RevertToSelf: {original}"
            );
        }
        drop(impersonation);
        mapped?;
        if at(
            memcordon_windows_launch_core::query_token_envelope(restricted.as_raw_handle())
                .map_err(io::Error::other),
            "selfcheck/restricted-token-after",
            "query_token_envelope",
            "boundary",
            Some(TOKEN_QUERY),
        )? != before
            || at(
                memcordon_windows_launch_core::query_token_envelope(original.as_raw_handle())
                    .map_err(io::Error::other),
                "selfcheck/original-token-after",
                "query_token_envelope",
                "boundary",
                Some(TOKEN_QUERY),
            )? != original_before
        {
            return Err(io::Error::other(
                "registry dependency changed the original token",
            ));
        }
        if at(
            coherent(source.raw(), deadline),
            "selfcheck/source-snapshot-after",
            "coherent",
            "boundary",
            Some(KEY_READ),
        )?
        .digest()
        .map_err(io::Error::other)?
            != source_before
            || at(
                source_security(source.raw(), deadline),
                "selfcheck/source-security-after",
                "RegGetKeySecurity",
                "boundary",
                Some(READ_CONTROL),
            )? != source_sd
        {
            return Err(io::Error::other(
                "native source data/security changed during owned registry test",
            ));
        }
        at(
            uninherited_self_check(deadline),
            "selfcheck/restored-hklm-readback",
            "uninherited_self_check",
            "boundary",
            Some(KEY_READ),
        )?;
        projection.transferred();
        projection.recipients_retired();
        live(deadline)
    })();
    let retired = at(
        projection.retire_if_safe(),
        "selfcheck/owned-projection-retire",
        "Projection::retire_if_safe",
        "boundary",
        None,
    );
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
