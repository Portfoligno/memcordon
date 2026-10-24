//! Diagnostic token equivalence; never authorization or startup certification.
use memcordon_core::WindowsCallerTokenEnvelopeV1;

pub fn validate_token_pair(
    primary: &WindowsCallerTokenEnvelopeV1,
    probe: &WindowsCallerTokenEnvelopeV1,
) -> Result<(), String> {
    // Native TOKEN_TYPE and SECURITY_IMPERSONATION_LEVEL wire values.
    if primary.token_type != 1 || probe.token_type != 2 || probe.impersonation_level != 2 {
        return Err("startup probe token type/impersonation level differs".into());
    }
    let mut comparable = probe.clone();
    comparable.token_type = primary.token_type;
    comparable.impersonation_level = primary.impersonation_level;
    if &comparable != primary {
        return Err("startup probe token differs from original primary beyond its explicit impersonation type/level".into());
    }
    Ok(())
}
