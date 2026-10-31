//! Canonical, bounded wire encoding for private fixture stream bytes.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{
    Deserializer, Serializer,
    de::{Error, Visitor},
    ser::Error as _,
};

pub const MAX_STREAM_BYTES: usize = 16 * 1024;
const MAX_ENCODED_BYTES: usize = MAX_STREAM_BYTES.div_ceil(3) * 4;

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if bytes.len() > MAX_STREAM_BYTES {
        return Err(S::Error::custom(
            "fixture stream exceeds decoded byte bound",
        ));
    }
    serializer.serialize_str(&STANDARD.encode(bytes))
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct StreamVisitor;
    impl Visitor<'_> for StreamVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded canonical standard base64 stream bytes")
        }

        fn visit_str<E: Error>(self, encoded: &str) -> Result<Self::Value, E> {
            if encoded.len() > MAX_ENCODED_BYTES
                || !encoded.as_bytes().chunks_exact(4).remainder().is_empty()
            {
                return Err(E::custom(
                    "fixture stream exceeds encoded byte bound or padding is invalid",
                ));
            }
            let padding = if encoded.ends_with("==") {
                "==".len()
            } else if encoded.ends_with('=') {
                "=".len()
            } else {
                0
            };
            let upper = encoded.len() / 4 * 3;
            let decoded = upper
                .checked_sub(padding)
                .ok_or_else(|| E::custom("invalid fixture stream padding"))?;
            if decoded > MAX_STREAM_BYTES {
                return Err(E::custom("fixture stream exceeds decoded byte bound"));
            }
            // The decoder's bounded scratch estimate includes at most two padding bytes.
            let mut bytes = vec![0; upper];
            let count = STANDARD
                .decode_slice(encoded, &mut bytes)
                .map_err(E::custom)?;
            if count != decoded {
                return Err(E::custom("fixture stream decoded length differs"));
            }
            bytes.truncate(count);
            if STANDARD.encode(&bytes) != encoded {
                return Err(E::custom("fixture stream base64 is not canonical"));
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_str(StreamVisitor)
}
