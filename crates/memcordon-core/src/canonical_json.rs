//! Neutral bounded JSON key uniqueness for current wire decoders.
use serde::{Deserialize, Deserializer};
pub fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<(), String> {
    use serde::de::{MapAccess, SeqAccess, Visitor};
    struct Unique;
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            struct Check;
            impl<'de> Visitor<'de> for Check {
                type Value = Unique;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("JSON with unique object keys")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                    let mut keys = std::collections::BTreeSet::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if key.len() > 256 || keys.len() >= 256 {
                            return Err(serde::de::Error::custom(
                                "JSON object key count exceeds bound",
                            ));
                        }
                        if !keys.insert(key.as_str().to_owned()) {
                            return Err(serde::de::Error::custom("duplicate JSON key"));
                        }
                        map.next_value::<Unique>()?;
                    }
                    Ok(Unique)
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Unique, A::Error> {
                    while sequence.next_element::<Unique>()?.is_some() {}
                    Ok(Unique)
                }
                fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Unique, E> {
                    Err(E::custom("floating JSON numbers are forbidden"))
                }
                fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique)
                }
            }
            decoder.deserialize_any(Check)
        }
    }
    serde_json::from_slice::<Unique>(bytes)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
