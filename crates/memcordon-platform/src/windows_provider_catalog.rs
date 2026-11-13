//! Documented catalog-read APIs inside an already verified private registry mapping.
use super::windows_winsock_registry::Mapping;
use std::{io, time::Instant};
use windows_sys::Win32::{
    Networking::WinSock::{WSAPROTOCOL_INFOW, WSCEnumProtocols, WSCGetProviderPath},
    System::Environment::ExpandEnvironmentStringsW,
};

fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original catalog preparation cutoff expired",
        ))
    } else {
        Ok(())
    }
}

/// Owns the preparation child's private stdin capability protocol. Callers do
/// not receive any safe integer-to-key adoption API.
pub fn child_stdio() -> io::Result<()> {
    use super::windows_winsock_registry::OwnedKey;
    use crate::windows_provider_catalog_protocol::{FRAME_BYTES, Ready, Spec, Transfer, digest};
    use std::io::{BufRead, Read, Write};
    fn read<T: serde::de::DeserializeOwned>(input: &mut impl BufRead) -> io::Result<T> {
        let mut bytes = Vec::new();
        input
            .take(FRAME_BYTES as u64 + 1)
            .read_until(b'\n', &mut bytes)?;
        if bytes.len() > FRAME_BYTES || bytes.last() != Some(&b'\n') {
            return Err(io::Error::other("catalog input is truncated or oversized"));
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
            .map_err(io::Error::other)?;
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }
    fn line(value: &impl serde::Serialize) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
        if bytes.len() >= FRAME_BYTES {
            return Err(io::Error::other("catalog output frame bound"));
        }
        bytes.push(b'\n');
        let mut output = std::io::stdout().lock();
        output.write_all(&bytes)?;
        output.flush()
    }
    let mut input = io::stdin().lock();
    let spec: Spec = read(&mut input)?;
    spec.validate()?;
    let sampled = Instant::now();
    let (now, frequency) = super::windows_performance_counter()?;
    if frequency != spec.frequency || now >= spec.cutoff_qpc {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "catalog supplied clock expired or differs",
        ));
    }
    let nanos = u128::from(spec.cutoff_qpc - now) * 1_000_000_000 / u128::from(frequency);
    let work = sampled
        .checked_add(std::time::Duration::from_nanos(
            u64::try_from(nanos).map_err(io::Error::other)?,
        ))
        .ok_or_else(|| io::Error::other("catalog clock overflow"))?;
    let identity = super::ProcessIdentity::current()?;
    let birth = u64::try_from(identity.birth).map_err(io::Error::other)?;
    let binding = digest(&spec)?;
    line(&Ready {
        version: 1,
        pid: identity.pid,
        birth,
        spec_sha256: binding.clone(),
    })?;
    let transfer: Transfer = read(&mut input)?;
    live(work)?;
    if transfer.version != 1 || transfer.spec_sha256 != binding || transfer.handle == 0 {
        return Err(io::Error::other("catalog capability transfer differs"));
    }
    // SAFETY: this process's private owned protocol delivered this unique
    // read-only target-local capability from its authenticated held parent.
    let key = unsafe { OwnedKey::from_transferred(transfer.handle, work) }?;
    let mapping = Mapping::install(key, &spec.declaration, work)?;
    let observed = mapping.run(|mapping| snapshot(mapping, &spec.declaration_sha256, work))?;
    live(work)?;
    line(
        &serde_json::json!({"version":1,"pid":identity.pid,"birth":birth,"spec_sha256":binding,"snapshot":observed}),
    )
}

/// This performs no explicit WSAStartup, socket, provider load or workload call.
/// The separate preparation process must retire before either original root starts.
pub fn snapshot(
    _mapping: &Mapping,
    declaration_sha256: &str,
    deadline: Instant,
) -> io::Result<serde_json::Value> {
    const ENTRIES: usize = 64;
    const PATH: usize = 2048;
    live(deadline)?;
    if declaration_sha256.len() != 64
        || !declaration_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::other("catalog declaration digest is malformed"));
    }
    // SAFETY: native output structures have a valid all-zero representation.
    let mut rows: Vec<WSAPROTOCOL_INFOW> = (0..ENTRIES)
        .map(|_| unsafe { std::mem::zeroed() })
        .collect();
    let capacity = u32::try_from(rows.len() * std::mem::size_of::<WSAPROTOCOL_INFOW>())
        .map_err(io::Error::other)?;
    let mut bytes = capacity;
    let mut code = 0;
    // SAFETY: aligned fixed-capacity structures and exact writable byte extent.
    let count =
        unsafe { WSCEnumProtocols(std::ptr::null(), rows.as_mut_ptr(), &mut bytes, &mut code) };
    if count < 0 {
        return Err(if code != 0 {
            io::Error::from_raw_os_error(code)
        } else {
            io::Error::other("catalog enumeration failed without native status")
        });
    }
    live(deadline)?;
    if count as usize > ENTRIES
        || bytes > capacity
        || bytes < (count as u32).saturating_mul(std::mem::size_of::<WSAPROTOCOL_INFOW>() as u32)
    {
        return Err(io::Error::other(
            "catalog enumeration is incomplete or outside bounded buffer",
        ));
    }
    let mut providers = Vec::new();
    for entry in rows
        .iter()
        .take(count as usize)
        .filter(|entry| entry.iAddressFamily == 2 && entry.iSocketType == 1 && entry.iProtocol == 6)
    {
        live(deadline)?;
        if providers.len() == 8
            || entry.ProtocolChain.ChainLen < 0
            || entry.ProtocolChain.ChainLen as usize > entry.ProtocolChain.ChainEntries.len()
        {
            return Err(io::Error::other(
                "catalog providers or chain exceed experiment bound",
            ));
        }
        let mut path = [0u16; PATH];
        let mut length = PATH as i32;
        let mut code = 0;
        // SAFETY: provider GUID came from this exact complete mapped-catalog enumeration.
        let status = unsafe {
            WSCGetProviderPath(&entry.ProviderId, path.as_mut_ptr(), &mut length, &mut code)
        };
        if status != 0 {
            return Err(if code != 0 {
                io::Error::from_raw_os_error(code)
            } else {
                io::Error::other("provider path failed without native status")
            });
        }
        live(deadline)?;
        let end = path
            .iter()
            .position(|unit| *unit == 0)
            .filter(|end| *end > 0)
            .ok_or_else(|| io::Error::other("provider path is empty or unterminated"))?;
        if length <= 0 || length as usize > PATH {
            return Err(io::Error::other("provider path extent is unsupported"));
        }
        let mut expanded = [0u16; PATH];
        // SAFETY: terminated bounded original path and exact writable output capacity.
        let expanded_length =
            unsafe { ExpandEnvironmentStringsW(path.as_ptr(), expanded.as_mut_ptr(), PATH as u32) };
        if expanded_length == 0 {
            return Err(io::Error::last_os_error());
        }
        live(deadline)?;
        if expanded_length as usize > PATH
            || expanded_length <= 1
            || expanded[expanded_length as usize - 1] != 0
            || expanded[..expanded_length as usize - 1].contains(&0)
        {
            return Err(io::Error::other(
                "expanded provider path is empty, truncated or malformed",
            ));
        }
        let guid = entry.ProviderId;
        let mut provider_id = [0u8; 16];
        provider_id[..4].copy_from_slice(&guid.data1.to_le_bytes());
        provider_id[4..6].copy_from_slice(&guid.data2.to_le_bytes());
        provider_id[6..8].copy_from_slice(&guid.data3.to_le_bytes());
        provider_id[8..].copy_from_slice(&guid.data4);
        providers.push(serde_json::json!({"catalog_id":entry.dwCatalogEntryId,"provider_id":provider_id,"address_family":entry.iAddressFamily,"socket_type":entry.iSocketType,"protocol":entry.iProtocol,"chain_length":entry.ProtocolChain.ChainLen,"chain_entries":entry.ProtocolChain.ChainEntries[..entry.ProtocolChain.ChainLen as usize],"configured_path":path[..end],"expanded_path":expanded[..expanded_length as usize-1]}));
    }
    live(deadline)?;
    Ok(
        serde_json::json!({"version":1,"declaration_sha256":declaration_sha256,"complete":true,"catalog_entries":count,"matching_providers":providers}),
    )
}
