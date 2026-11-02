//! Explicit native Winsock configuration input; never host policy mutation.
use crate::windows_registry_difference::ReadbackStage;
use crate::windows_registry_error::{at, failures, require_access_denied};
use crate::windows_registry_manifest::{
    Declaration, Key, Manifest, Root, TransportPresence, TransportRoot, VERSION, ValueRecord, View,
    transport_services,
};
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

const MAX_KEYS: usize = 256;
const MAX_VALUES: usize = 4096;
const MAX_BYTES: usize = 4 * 1024 * 1024;

fn set_value_exact(key: HKEY, value: &ValueRecord, deadline: Instant) -> io::Result<()> {
    use windows_sys::{Wdk::System::Registry::NtSetValueKey, Win32::Foundation::UNICODE_STRING};
    let name_bytes = value
        .name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "counted registry value name exceeds native extent",
            )
        })?;
    if value.name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "counted registry value name contains NUL",
        ));
    }
    let data_bytes = u32::try_from(value.bytes.len()).map_err(io::Error::other)?;
    let mut name = value.name.clone();
    let counted = UNICODE_STRING {
        Length: name_bytes,
        MaximumLength: name_bytes,
        Buffer: if name.is_empty() {
            ptr::null_mut()
        } else {
            name.as_mut_ptr()
        },
    };
    live(deadline)?;
    // SAFETY: the private caller retains this newly owned setup key. Both
    // counted buffers remain live for this synchronous input-only native call.
    let status = unsafe {
        NtSetValueKey(
            key,
            &counted,
            0,
            value.kind,
            if value.bytes.is_empty() {
                ptr::null()
            } else {
                value.bytes.as_ptr().cast()
            },
            data_bytes,
        )
    };
    let written = if status < 0 {
        Err(io::Error::other(format!(
            "phase=projection/value-copy; api=NtSetValueKey; native-error-domain=NTSTATUS; native-code={status} ({status:#010x}); requested-mask={KEY_SET_VALUE}; name-bytes={name_bytes}; data-bytes={data_bytes}"
        )))
    } else {
        Ok(())
    };
    match (written, live(deadline)) {
        (Err(primary), Err(secondary)) => Err(failures(primary, secondary)),
        (Err(primary), _) => Err(primary),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

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
    root: Root,
    path: Vec<Vec<u16>>,
    subkeys: u32,
    values: u32,
    low: u32,
    high: u32,
}

#[derive(Debug)]
struct RootError {
    root: Root,
    original: io::Error,
}
impl std::fmt::Display for RootError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "registry-root={:?}; {}",
            self.root, self.original
        )
    }
}
impl std::error::Error for RootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
fn root_at<T>(result: io::Result<T>, root: &Root) -> io::Result<T> {
    at(
        result.map_err(|original| {
            io::Error::new(
                original.kind(),
                RootError {
                    root: root.clone(),
                    original,
                },
            )
        }),
        match root {
            Root::Winsock2Parameters => "forest/winsock2-parameters",
            Root::WinsockParameters => "forest/winsock-parameters",
            Root::TransportWinsock { .. } => "forest/transport-winsock",
        },
        "registry-forest-root",
        "boundary",
        Some(KEY_READ),
    )
}
fn roots_at(parent: HKEY, deadline: Instant) -> io::Result<Vec<(Root, OwnedKey)>> {
    let mut roots = Vec::with_capacity(Root::ALL.len());
    for kind in Root::ALL {
        let key = root_at(
            open_at(parent, &kind.path(), KEY_READ, deadline, "forest/root-open"),
            &kind,
        )?;
        roots.push((kind, key));
    }
    Ok(roots)
}
type ForestSecurity = Vec<(Root, Vec<u8>)>;
fn forest_security(roots: &[(Root, OwnedKey)], deadline: Instant) -> io::Result<ForestSecurity> {
    roots
        .iter()
        .map(|(kind, key)| {
            root_at(source_security(key.raw(), deadline), kind)
                .map(|security| (kind.clone(), security))
        })
        .collect()
}
#[derive(Default)]
struct CaptureState {
    keys: Vec<Key>,
    stamps: Vec<Stamp>,
    values: usize,
    bytes: usize,
    absent: usize,
}
fn capture(
    roots: &[(Root, OwnedKey)],
    state: &mut CaptureState,
    deadline: Instant,
) -> io::Result<()> {
    let mut pending = roots
        .iter()
        .map(|(kind, key)| {
            (
                kind.clone(),
                Vec::<Vec<u16>>::new(),
                None::<OwnedKey>,
                key.raw(),
            )
        })
        .collect::<Vec<_>>();
    let mut keys = std::mem::take(&mut state.keys);
    let mut stamps = std::mem::take(&mut state.stamps);
    let mut value_count = state.values;
    let mut byte_count = state.bytes;
    while let Some((kind, path, owner, root)) = pending.pop() {
        let captured_root = (|| -> io::Result<()> {
            live(deadline)?;
            byte_count = byte_count
                .checked_add(kind.identity_bytes())
                .ok_or_else(|| io::Error::other("registry root tag size overflow"))?;
            if keys.len() + state.absent >= MAX_KEYS || path.len() > 16 {
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
                pending.push((kind.clone(), child_path, Some(child), root));
                if pending.len() + keys.len() + state.absent + 1 > MAX_KEYS {
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
                root: kind.clone(),
                path: path.clone(),
                subkeys,
                values,
                low: modified.dwLowDateTime,
                high: modified.dwHighDateTime,
            });
            keys.push(Key {
                root: kind.clone(),
                path,
                class,
                values: captured,
            });
            Ok(())
        })();
        root_at(captured_root, &kind)?;
    }
    state.keys = keys;
    state.stamps = stamps;
    state.values = value_count;
    state.bytes = byte_count;
    live(deadline)?;
    Ok(())
}

fn native_equal(left: &[u16], right: &[u16], deadline: Instant) -> io::Result<bool> {
    live(deadline)?;
    if left.is_empty() || right.is_empty() {
        return Ok(left.is_empty() && right.is_empty());
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CompareStringOrdinal(
            left: *const u16,
            left_count: i32,
            right: *const u16,
            right_count: i32,
            ignore_case: i32,
        ) -> i32;
    }
    let result = unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            i32::try_from(left.len()).map_err(io::Error::other)?,
            right.as_ptr(),
            i32::try_from(right.len()).map_err(io::Error::other)?,
            1,
        )
    };
    let observed = if result == 0 {
        at(
            Err(io::Error::last_os_error()),
            "forest/native-name-compare",
            "CompareStringOrdinal",
            "Win32",
            None,
        )
    } else {
        Ok(result == 2)
    };
    match (observed, live(deadline)) {
        (Err(primary), Err(secondary)) => Err(failures(primary, secondary)),
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(equal), Ok(())) => Ok(equal),
    }
}
fn native_transport_services(keys: &[Key], deadline: Instant) -> io::Result<Vec<Vec<u16>>> {
    let configuration = keys
        .iter()
        .find(|key| key.root == Root::WinsockParameters && key.path.is_empty())
        .ok_or_else(|| io::Error::other("Winsock transport configuration root is absent"))?;
    let expected = "Transports".encode_utf16().collect::<Vec<_>>();
    let mut matches = 0usize;
    for value in &configuration.values {
        if native_equal(&value.name, &expected, deadline)? {
            matches += 1;
            if value.name.len() != expected.len()
                || !value.name.iter().zip(&expected).all(|(left, right)| {
                    *left <= 0x7f && (*left as u8).eq_ignore_ascii_case(&(*right as u8))
                })
            {
                return Err(io::Error::other(
                    "unsupported native alias for Transports value name",
                ));
            }
        }
    }
    if matches != 1 {
        return Err(io::Error::other(
            "native Transports value identity is ambiguous or absent",
        ));
    }
    let services = transport_services(keys).map_err(io::Error::other)?;
    for (index, service) in services.iter().enumerate() {
        for other in &services[..index] {
            if native_equal(service, other, deadline)? {
                return Err(io::Error::other(
                    "distinct transport spellings alias one native service key",
                ));
            }
        }
    }
    live(deadline)?;
    Ok(services)
}
struct Snapshot {
    manifest: Manifest,
    stamps: Vec<Stamp>,
    security: ForestSecurity,
}
fn closure_snapshot(parent: HKEY, deadline: Instant) -> io::Result<Snapshot> {
    let mut sources = roots_at(parent, deadline)?;
    let mut security = forest_security(&sources, deadline)?;
    let mut state = CaptureState::default();
    capture(&sources, &mut state, deadline)?;
    let services = native_transport_services(&state.keys, deadline)?;
    let mut transports = Vec::with_capacity(services.len());
    let mut additional = Vec::with_capacity(services.len());
    for service in services {
        live(deadline)?;
        let root = Root::TransportWinsock {
            service: service.clone(),
        };
        let mut transport = TransportRoot {
            service,
            presence: TransportPresence::Present,
        };
        state.bytes = state
            .bytes
            .checked_add(transport.extent_bytes())
            .ok_or_else(|| io::Error::other("transport membership extent overflow"))?;
        if state.bytes > MAX_BYTES {
            return Err(io::Error::other(
                "transport membership exceeds shared byte bound",
            ));
        }
        // Classify the direct native result before any context wrapper. Only
        // witnessed ERROR_FILE_NOT_FOUND is an accepted absent dependency.
        match open(parent, &root.path(), KEY_READ, deadline) {
            Ok(key) => {
                security.push((
                    root.clone(),
                    root_at(source_security(key.raw(), deadline), &root)?,
                ));
                additional.push((root, key));
            }
            Err(error) if error.raw_os_error() == Some(2) => {
                transport.presence = TransportPresence::Absent { lstatus: 2 };
                state.absent += 1;
            }
            Err(error) => return root_at(Err(error), &root),
        }
        if state.keys.len() + additional.len() + state.absent > MAX_KEYS {
            return Err(io::Error::other(
                "transport roots exceed shared key inventory",
            ));
        }
        transports.push(transport);
    }
    capture(&additional, &mut state, deadline)?;
    sources.extend(additional);
    security.sort_by(|left, right| left.0.cmp(&right.0));
    let mut after = forest_security(&sources, deadline)?;
    after.sort_by(|left, right| left.0.cmp(&right.0));
    if security != after {
        return Err(io::Error::other(
            "native registry closure security changed during capture",
        ));
    }
    let manifest = Manifest {
        version: VERSION,
        view: View::Native,
        transports,
        keys: state.keys,
    };
    manifest.validate().map_err(io::Error::other)?;
    state
        .stamps
        .sort_by(|left, right| (&left.root, &left.path).cmp(&(&right.root, &right.path)));
    live(deadline)?;
    Ok(Snapshot {
        manifest,
        stamps: state.stamps,
        security,
    })
}
fn coherent(parent: HKEY, deadline: Instant) -> io::Result<(Manifest, ForestSecurity)> {
    let first = closure_snapshot(parent, deadline)?;
    let second = closure_snapshot(parent, deadline)?;
    if first.stamps != second.stamps
        || first.security != second.security
        || first.manifest.digest().map_err(io::Error::other)?
            != second.manifest.digest().map_err(io::Error::other)?
    {
        return Err(io::Error::other(
            "native registry dependency closure changed during coherent capture",
        ));
    }
    Ok((second.manifest, second.security))
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
    source_security: ForestSecurity,
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
        Self::create_with_roundtrip(unique, deadline, cleanup_deadline, false)
    }
    fn create_with_roundtrip(
        unique: &str,
        deadline: Instant,
        cleanup_deadline: Instant,
        native_roundtrip: bool,
    ) -> io::Result<Self> {
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
        let (manifest, security_before) = at(
            coherent(HKEY_LOCAL_MACHINE, deadline),
            "projection/source-snapshot",
            "coherent",
            "boundary",
            Some(KEY_READ),
        )?;
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
            (if native_roundtrip {
                projection.exact_value_self_check()
            } else {
                Ok(())
            })
            .and_then(|()| projection.populate(&mut attributes)),
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
        keys.sort_by(|a, b| (&a.root, &a.path).cmp(&(&b.root, &b.path)));
        let mut created = std::collections::BTreeMap::<Vec<Vec<u16>>, usize>::new();
        for entry in keys {
            live(self.deadline)?;
            let root_path = entry.root.path();
            let mut components = root_path
                .split(|unit| *unit == b'\\' as u16)
                .map(<[u16]>::to_vec)
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
                at(
                    set_value_exact(parent, value, self.deadline),
                    "projection/value-copy",
                    "NtSetValueKey",
                    "NTSTATUS",
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
    fn exact_value_self_check(&mut self) -> io::Result<()> {
        if self.sealed {
            return Err(io::Error::other(
                "native value-copy probe requires an unsealed owned parent",
            ));
        }
        // The native-only constructor calls this while the fresh parent is
        // still mutable, before population or sealing. Retain the disposable
        // child in held cleanup before any fallible write/readback work.
        let reader = sid_text(&self.reader_sid, self.deadline)?;
        let sddl = wide(&format!("D:P(A;;KA;;;SY)(A;;KA;;;OW)(A;;KA;;;{reader})"));
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return at(
                Err(io::Error::last_os_error()),
                "selfcheck/value-copy-security",
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
        let descriptor = Security(descriptor);
        if descriptor.0.is_null() {
            return Err(io::Error::other(
                "native value-copy probe security descriptor is null",
            ));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let mut raw = ptr::null_mut();
        let mut disposition = 0;
        live(self.deadline)?;
        status_at(
            unsafe {
                RegCreateKeyExW(
                    self.root.raw(),
                    wide("value-copy-native-self-check").as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_VOLATILE,
                    KEY_ALL_ACCESS,
                    &attributes,
                    &mut raw,
                    &mut disposition,
                )
            },
            "selfcheck/value-copy-key-create",
            "RegCreateKeyExW",
            Some(KEY_ALL_ACCESS),
        )?;
        let owned = OwnedKey(raw);
        if disposition != REG_CREATED_NEW_KEY {
            return Err(io::Error::other(
                "native value-copy probe unexpectedly existed",
            ));
        }
        self.nodes.push(owned);
        let key = self
            .nodes
            .last()
            .expect("new value-copy key is retained")
            .raw();
        let tested = (|| -> io::Result<()> {
            let bytes = |units: &[u16]| {
                units
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>()
            };
            let unterminated = "counted native value".encode_utf16().collect::<Vec<_>>();
            let mut terminated = unterminated.clone();
            terminated.push(0);
            let values = [
                ValueRecord {
                    name: "expand-unterminated".encode_utf16().collect(),
                    kind: REG_EXPAND_SZ,
                    bytes: bytes(&unterminated),
                },
                ValueRecord {
                    name: "expand-terminated".encode_utf16().collect(),
                    kind: REG_EXPAND_SZ,
                    bytes: bytes(&terminated),
                },
                ValueRecord {
                    name: "string".encode_utf16().collect(),
                    kind: REG_SZ,
                    bytes: bytes(&terminated),
                },
                ValueRecord {
                    name: "multi-string".encode_utf16().collect(),
                    kind: REG_MULTI_SZ,
                    bytes: bytes(&[b'a' as u16, 0, b'b' as u16, 0, 0]),
                },
                ValueRecord {
                    name: "empty-binary".encode_utf16().collect(),
                    kind: REG_BINARY,
                    bytes: Vec::new(),
                },
                ValueRecord {
                    name: Vec::new(),
                    kind: REG_BINARY,
                    bytes: vec![1, 0, 255],
                },
            ];
            for (index, value) in values.iter().enumerate() {
                set_value_exact(key, value, self.deadline)?;
                let mut name = value.name.clone();
                name.push(0);
                let (mut kind, mut length) = (0, 0);
                live(self.deadline)?;
                status_at(
                    unsafe {
                        RegQueryValueExW(
                            key,
                            name.as_ptr(),
                            ptr::null(),
                            &mut kind,
                            ptr::null_mut(),
                            &mut length,
                        )
                    },
                    "selfcheck/value-copy-readback-size",
                    "RegQueryValueExW",
                    Some(KEY_QUERY_VALUE),
                )?;
                if kind != value.kind || length as usize != value.bytes.len() {
                    return Err(io::Error::other(format!(
                        "native value-copy roundtrip extent differs; case={index}; expected-type={}; actual-type={kind}; expected-bytes={}; actual-bytes={length}",
                        value.kind,
                        value.bytes.len()
                    )));
                }
                let mut actual = vec![0; length as usize];
                live(self.deadline)?;
                status_at(
                    unsafe {
                        RegQueryValueExW(
                            key,
                            name.as_ptr(),
                            ptr::null(),
                            &mut kind,
                            if actual.is_empty() {
                                ptr::null_mut()
                            } else {
                                actual.as_mut_ptr()
                            },
                            &mut length,
                        )
                    },
                    "selfcheck/value-copy-readback-data",
                    "RegQueryValueExW",
                    Some(KEY_QUERY_VALUE),
                )?;
                if kind != value.kind
                    || length as usize != value.bytes.len()
                    || actual != value.bytes
                {
                    return Err(io::Error::other(format!(
                        "native value-copy roundtrip data differs; case={index}"
                    )));
                }
                live(self.deadline)?;
            }
            Ok(())
        })();
        let removed = (|| -> io::Result<()> {
            live(self.cleanup_deadline)?;
            let status = unsafe { windows_sys::Wdk::System::Registry::NtDeleteKey(key) };
            if status < 0 {
                return Err(io::Error::other(format!(
                    "phase=selfcheck/value-copy-key-retire; api=NtDeleteKey; native-error-domain=NTSTATUS; native-code={status} ({status:#010x})"
                )));
            }
            drop(
                self.nodes
                    .pop()
                    .expect("value-copy probe remains the last held node"),
            );
            live(self.cleanup_deadline)
        })();
        match (tested, removed) {
            (Err(primary), Err(secondary)) => Err(failures(primary, secondary)),
            (Err(primary), _) => Err(primary),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
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
            verified_readback(
                self.root.raw(),
                &self.declaration,
                Some(&self.manifest),
                if self.sealed {
                    ReadbackStage::Sealed
                } else {
                    ReadbackStage::Copied
                },
                self.deadline,
            )
            .map(|_| ()),
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
        let security = self.source_security.iter().map(|(root, bytes)| serde_json::json!({"root":root,"path_utf16":root.path(),"bytes":bytes,"sha256":hex_digest(bytes)})).collect::<Vec<_>>();
        serde_json::json!({"format":"memcordon.fixture-winsock-registry-input","version":3,"declaration":self.declaration,"transports":self.manifest.transports,"owned_namespace_hkcu":self.namespace,"retirement_observed":self.retired,"source_security_information":7,"source_security_roots":security,"source_label_captured":false,"source_view":"native","intended_reader_sid":self.reader_sid,"owned_root_security_at_seal":self.root_security,"owned_seal_verified_at_creation":self.sealed,"scope":"exact native Winsock roots and configuration-derived transport Winsock inputs, including witnessed absence, projected below one owned HKLM root","host_registry_policy_changed":false,"acceptance_authority":false})
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
    verified_readback(root, declaration, None, ReadbackStage::Recipient, deadline)
}
fn verified_readback(
    root: HKEY,
    declaration: &Declaration,
    expected: Option<&Manifest>,
    stage: ReadbackStage,
    deadline: Instant,
) -> io::Result<Manifest> {
    declaration.validate().map_err(io::Error::other)?;
    let (actual, _) = coherent(root, deadline)?;
    let actual_digest = actual.digest().map_err(io::Error::other)?;
    if actual_digest != declaration.sha256 {
        let cutoff = live(deadline);
        let detail = if cutoff.is_ok() {
            crate::windows_registry_difference::diagnostic(
                expected,
                &actual,
                declaration,
                deadline,
                stage,
            )
        } else {
            serde_json::json!({"format":"memcordon.fixture-registry-difference","revision":1,"stage":stage.label(),"diagnostic_only":true,"acceptance_authority":false,"detail_unavailable":"original-cutoff","expected_sha256":declaration.sha256,"actual_sha256":actual_digest,"expected_payload_available":false,"owner_payload_supplied":expected.is_some()})
        };
        // Emit the already bounded record independently: contextual error
        // wrappers cap their source text and could cut an appended JSON blob.
        // Diagnostic I/O never replaces the mandatory original mismatch.
        use std::io::Write;
        let retained = at(
            writeln!(io::stderr().lock(), "{detail}"),
            "registry/mismatch-diagnostic-stderr",
            "Write::write_fmt",
            "I/O",
            None,
        );
        let mismatch = io::Error::other("registry input manifest digest differs");
        let mismatch = match retained {
            Ok(()) => mismatch,
            Err(error) => failures(mismatch, error),
        };
        return match cutoff.and_then(|()| live(deadline)) {
            Ok(()) => Err(mismatch),
            Err(cutoff) => Err(failures(mismatch, cutoff)),
        };
    }
    live(deadline)?;
    Ok(actual)
}
fn present_roots(manifest: &Manifest) -> impl Iterator<Item = &Root> {
    manifest
        .keys
        .iter()
        .filter(|key| key.path.is_empty())
        .map(|key| &key.root)
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
        for kind in present_roots(&manifest) {
            let parameters = root_at(
                open_at(
                    key.raw(),
                    &kind.path(),
                    KEY_READ,
                    deadline,
                    "mapping/root-seal-open",
                ),
                kind,
            )?;
            root_at(read_seal(parameters.raw(), &reader, deadline), kind)?;
        }
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
    immutable_surface(root, deadline)?;
    for kind in present_roots(manifest) {
        let checked = (|| -> io::Result<()> {
            let parameters = open_at(
                root,
                &kind.path(),
                KEY_READ,
                deadline,
                "immutable/parameters-open",
            )?;
            immutable_surface(parameters.raw(), deadline)?;
            let leaf = manifest
                .keys
                .iter()
                .filter(|key| &key.root == kind)
                .max_by_key(|key| key.path.len())
                .ok_or_else(|| io::Error::other("verified registry forest has no root leaf"))?;
            let mut leaf_path = kind.path();
            for component in &leaf.path {
                leaf_path.push(b'\\' as u16);
                leaf_path.extend(component);
            }
            leaf_path.push(0);
            live(deadline)?;
            denied_status(
                unsafe { RegDeleteKeyExW(root, leaf_path.as_ptr(), 0, 0) },
                "immutable/delete-leaf",
                "RegDeleteKeyExW",
                Some(0x0001_0000),
            )?;
            live(deadline)
        })();
        root_at(checked, kind)?;
    }
    live(deadline)
}
fn immutable_surface(root: HKEY, deadline: Instant) -> io::Result<()> {
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
        Projection::create_with_roundtrip(&nonce, deadline, deadline, true),
        "selfcheck/projection-create-seal",
        "Projection::create",
        "boundary",
        None,
    )?;
    let tested = (|| -> io::Result<()> {
        let (source_before, source_sd) = at(
            coherent(HKEY_LOCAL_MACHINE, deadline),
            "selfcheck/source-snapshot-before",
            "coherent",
            "boundary",
            Some(KEY_READ),
        )?;
        let source_before = source_before.digest().map_err(io::Error::other)?;
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
        let mut impersonation = Some(Impersonation);
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
                let mapped_manifest =
                    verified_manifest(HKEY_LOCAL_MACHINE, &declaration, deadline)?;
                for kind in present_roots(&mapped_manifest) {
                    let checked = (|| -> io::Result<()> {
                        let path = kind.path();
                        let mapped = open_at(
                            HKEY_LOCAL_MACHINE,
                            &path,
                            KEY_READ,
                            deadline,
                            "selfcheck/mapped-forest-open",
                        )?;
                        let held = open_at(
                            mapping.raw(),
                            &path,
                            KEY_READ,
                            deadline,
                            "selfcheck/held-forest-open",
                        )?;
                        if key_name(mapped.raw(), deadline)? != key_name(held.raw(), deadline)? {
                            return Err(io::Error::other(
                                "mapped forest root name differs from held input",
                            ));
                        }
                        live(deadline)
                    })();
                    root_at(checked, kind)?;
                }
                live(deadline)?;
                // The restricted proofs are complete. Revert exactly once,
                // while the same process-local mapping stays owned by run.
                // The child tests mapping noninheritance, not a thread token.
                drop(
                    impersonation
                        .take()
                        .expect("restricted proof owns its impersonation guard"),
                );
                live(deadline)?;
                let ordinary_manifest = at(
                    verified_manifest(mapping.raw(), &declaration, deadline),
                    "selfcheck/ordinary-manifest",
                    "verified_manifest",
                    "boundary",
                    Some(KEY_READ),
                )?;
                at(
                    immutable(mapping.raw(), &ordinary_manifest, deadline),
                    "selfcheck/ordinary-immutability",
                    "immutable",
                    "boundary",
                    Some(KEY_READ),
                )?;
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
        if let (Some(_), Err(original)) = (&impersonation, &mapped) {
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
        let (source_after, source_security_after) = at(
            coherent(HKEY_LOCAL_MACHINE, deadline),
            "selfcheck/source-snapshot-after",
            "coherent",
            "boundary",
            Some(KEY_READ),
        )?;
        if source_after.digest().map_err(io::Error::other)? != source_before
            || source_security_after != source_sd
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
