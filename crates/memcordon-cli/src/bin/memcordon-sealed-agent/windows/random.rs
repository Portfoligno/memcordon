//! Native randomness for service and attempt identities.
use memcordon_core::identifiers::Nonce128;

pub fn random_nonce() -> Result<Nonce128, String> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut bytes = [0_u8; 16];
    // SAFETY: the writable buffer and its exact length are supplied.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err("native runtime nonce generation failed".into());
    }
    Ok(Nonce128(bytes))
}
