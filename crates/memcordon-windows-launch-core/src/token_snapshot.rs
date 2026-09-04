use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetTokenIdentityV1 {
    pub envelope_sha256: String,
    pub authentication_id: u64,
    pub session_id: u32,
}

pub fn token_envelope_sha256(
    envelope: &memcordon_core::WindowsCallerTokenEnvelopeV1,
) -> Result<String, String> {
    serde_json::to_vec(envelope)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|error| error.to_string())
}
