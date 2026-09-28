//! The upstream oracle envelopes, without its native runtime dependencies.
use bitcoin::psbt::Psbt;
use sapio_base::program::{ProgramInstance, ProgramSpendPath};
use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub const MAX_PSBT: usize = 65_536;
const MAX_WITNESS: usize = 32 + 12 + 37 + crate::contract::MAX_CLIENT_DATA + 72;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WirePsbt(pub Psbt);

impl Serialize for WirePsbt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = vec![0; 4];
        let length = self
            .0
            .serialize_to_writer(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        if length > MAX_PSBT {
            return Err(serde::ser::Error::custom("PSBT exceeds 64 KiB"));
        }
        bytes[..4].copy_from_slice(&(length as u32).to_be_bytes());
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for WirePsbt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedPsbt;
        impl<'de> Visitor<'de> for BoundedPsbt {
            type Value = WirePsbt;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a four-byte big-endian length followed by one bounded PSBT")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut prefix = [0; 4];
                for byte in &mut prefix {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::custom("truncated PSBT length"))?;
                }
                let length = u32::from_be_bytes(prefix) as usize;
                if length == 0 || length > MAX_PSBT {
                    return Err(A::Error::custom("invalid bounded PSBT length"));
                }
                let mut bytes = Vec::with_capacity(length);
                for _ in 0..length {
                    bytes.push(
                        seq.next_element()?
                            .ok_or_else(|| A::Error::custom("truncated PSBT payload"))?,
                    );
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(A::Error::custom("trailing wire PSBT bytes"));
                }
                Psbt::deserialize(&bytes)
                    .map(WirePsbt)
                    .map_err(A::Error::custom)
            }
        }
        deserializer.deserialize_bytes(BoundedPsbt)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub instance: ProgramInstance,
    pub input_index: u32,
    #[serde(deserialize_with = "bounded_witness")]
    pub witness: Vec<u8>,
    pub path: ProgramSpendPath,
    pub psbt: WirePsbt,
}

fn bounded_witness<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct BoundedWitness;
    impl<'de> Visitor<'de> for BoundedWitness {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded passkey witness byte array")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_WITNESS));
            while let Some(byte) = seq.next_element()? {
                if bytes.len() == MAX_WITNESS {
                    return Err(A::Error::custom("passkey witness exceeds byte limit"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(BoundedWitness)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum OracleRequest {
    SignProgramV1(SigningRequest),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum OracleResponse {
    SignedV1(WirePsbt),
    RejectedV1(String),
}
