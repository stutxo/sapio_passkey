#![no_std]

//! Inline WebAuthn ES256 spending predicate; no secret keys or signing interface.
//! All transaction fields are authorized through the exact WASM-v2 view digest.

extern crate alloc;

mod abi;

use abi::{Arguments, Reader};
use alloc::string::String;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::Deserialize;

const DOMAIN: &[u8] = b"sapio-passkey/v3\0";
const MAX_CLIENT_DATA: usize = 4096;
const MAX_ORIGIN: usize = 256;

#[link(wasm_import_module = "sapio_crypto_v1")]
extern "C" {
    fn sha256(pointer: u32, length: u32, output: u32) -> i32;
}

#[link(wasm_import_module = "sapio_crypto_v2")]
extern "C" {
    fn xonly_tweak_check(key: u32, tweak: u32, output: u32, parity: u32) -> i32;
}

#[no_mangle]
pub extern "C" fn sapio_evaluate_v2(
    program_pointer: u32,
    program_length: u32,
    parameters_pointer: u32,
    parameters_length: u32,
    view_pointer: u32,
    view_length: u32,
    witness_pointer: u32,
    witness_length: u32,
) -> i32 {
    abi::arguments([
        program_pointer,
        program_length,
        parameters_pointer,
        parameters_length,
        view_pointer,
        view_length,
        witness_pointer,
        witness_length,
    ])
    .and_then(evaluate)
    .is_some() as i32
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ceremony: String,
    challenge: String,
    origin: String,
    // A default bool accepts absence/false but rejects null and every other
    // JSON type. Derive rejects duplicate fields, including escaped names.
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
    // WebAuthn client data is extensible (Chromium randomly adds a GREASE
    // member). Ignore unknown members, but never permit top-origin context.
    #[serde(rename = "topOrigin", default, deserialize_with = "reject_top_origin")]
    top_origin: bool,
}

fn reject_top_origin<'de, D: serde::Deserializer<'de>>(_: D) -> Result<bool, D::Error> {
    Err(serde::de::Error::custom("topOrigin is not supported"))
}

fn evaluate(arguments: Arguments<'_>) -> Option<()> {
    let mut policy = Reader::new(arguments.parameters);
    if policy.take(4)? != b"SPK3" {
        return None;
    }
    // Genesis hash is an application-domain commitment, not a chain oracle.
    policy.take(32)?;
    let public_key = policy.take(33)?;
    if !matches!(public_key[0], 2 | 3) {
        return None;
    }
    let rp_hash = policy.take(32)?;
    let origin = policy.sized()?;
    if origin.is_empty() || origin.len() > MAX_ORIGIN {
        return None;
    }
    let origin = core::str::from_utf8(origin).ok()?;
    policy.finish()?;

    // The selected funding output must commit to the host-provided program
    // internal key with no script tree. Any added tree must fail even with a
    // valid assertion authorizing the modified transaction.
    verify_committed_view(arguments.view)?;

    let mut witness = Reader::new(arguments.witness);
    let nonce = witness.take(32)?;
    let authenticator_data = witness.sized()?;
    let client_data = witness.sized()?;
    let signature = witness.sized()?;
    witness.finish()?;
    if authenticator_data.len() != 37
        || client_data.is_empty()
        || client_data.len() > MAX_CLIENT_DATA
        || !(8..=72).contains(&signature.len())
    {
        return None;
    }
    if &authenticator_data[..32] != rp_hash {
        return None;
    }
    let flags = authenticator_data[32];
    // UP and UV required; reserved, AT and ED bits forbidden. Synced passkeys
    // may set BE/BS, but BS without BE is invalid. The 32-bit signature counter
    // has no persistent state here: zero counters and nonzero counters work.
    if flags & 0x05 != 0x05 || flags & !0x1d != 0 || flags & 0x10 != 0 && flags & 0x08 == 0 {
        return None;
    }

    let mut commitment = [0u8; DOMAIN.len() + 96];
    commitment[..DOMAIN.len()].copy_from_slice(DOMAIN);
    commitment[DOMAIN.len()..DOMAIN.len() + 32].copy_from_slice(&hash(arguments.parameters)?);
    commitment[DOMAIN.len() + 32..DOMAIN.len() + 64].copy_from_slice(&hash(arguments.view)?);
    commitment[DOMAIN.len() + 64..].copy_from_slice(nonce);
    let challenge = base64url(&hash(&commitment)?);
    let client: ClientData = serde_json::from_slice(client_data).ok()?;
    if client.ceremony != "webauthn.get"
        || client.challenge.as_bytes() != challenge
        || client.origin != origin
        || client.cross_origin
        || client.top_origin
    {
        return None;
    }

    // Hash original clientDataJSON bytes, never a parsed/reserialized version.
    let mut signed = [0u8; 69];
    signed[..37].copy_from_slice(authenticator_data);
    signed[37..].copy_from_slice(&hash(client_data)?);
    let digest = hash(&signed)?;
    let key = VerifyingKey::from_sec1_bytes(public_key).ok()?;
    // RustCrypto validates canonical DER and 1 <= r,s < n. Ordinary browser
    // ES256 signatures may have high S; do not impose Bitcoin's low-S policy.
    let signature = Signature::from_der(signature).ok()?;
    key.verify_prehash(&digest, &signature).ok()
}

fn verify_committed_view(view: &[u8]) -> Option<()> {
    let mut reader = Reader::new(view);
    reader.take(8)?; // i32 version + u32 locktime, committed without rewriting.
    let selected = reader.u32()?;
    let inputs = reader.u32()?;
    if inputs == 0 || selected >= inputs || inputs as usize > reader.remaining() / 52 {
        return None;
    }
    let mut output_key: Option<&[u8; 32]> = None;
    for index in 0..inputs {
        reader.take(48)?; // outpoint[36], sequence u32, prevout value u64.
        let script = reader.sized()?;
        if index == selected {
            if script.len() != 34 || script[..2] != [0x51, 0x20] {
                return None;
            }
            output_key = Some(script[2..].try_into().ok()?);
        }
    }
    let outputs = reader.u32()?;
    if outputs as usize > reader.remaining() / 12 {
        return None;
    }
    for _ in 0..outputs {
        reader.take(8)?; // output value u64.
        reader.sized()?; // scriptPubKey, including zero-length scripts.
    }
    let internal_key: &[u8; 32] = reader.take(32)?.try_into().ok()?;
    if !reader.sized()?.is_empty() {
        return None; // Annex support requires a separately versioned profile.
    }
    reader.finish()?;

    // BIP341's tree-free tweak hashes only the internal key, not a zero root.
    let tag = hash(b"TapTweak")?;
    let mut tagged = [0u8; 96];
    tagged[..32].copy_from_slice(&tag);
    tagged[32..64].copy_from_slice(&tag);
    tagged[64..96].copy_from_slice(internal_key);
    let tweak = hash(&tagged)?;
    let output_key = output_key?;
    for parity in 0..=1 {
        let result = unsafe {
            xonly_tweak_check(
                internal_key.as_ptr() as u32,
                tweak.as_ptr() as u32,
                output_key.as_ptr() as u32,
                parity,
            )
        };
        match result {
            1 => return Some(()),
            0 => (),
            _ => return None,
        }
    }
    None
}

fn hash(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() > abi::MAX_VIEW {
        return None;
    }
    let mut output = [0u8; 32];
    let result = unsafe {
        sha256(
            bytes.as_ptr() as u32,
            bytes.len() as u32,
            output.as_mut_ptr() as u32,
        )
    };
    (result == 0).then_some(output)
}

fn base64url(bytes: &[u8; 32]) -> [u8; 43] {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = [0u8; 43];
    for i in 0..10 {
        let a = bytes[3 * i];
        let b = bytes[3 * i + 1];
        let c = bytes[3 * i + 2];
        encoded[4 * i] = ALPHABET[(a >> 2) as usize];
        encoded[4 * i + 1] = ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize];
        encoded[4 * i + 2] = ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize];
        encoded[4 * i + 3] = ALPHABET[(c & 63) as usize];
    }
    encoded[40] = ALPHABET[(bytes[30] >> 2) as usize];
    encoded[41] = ALPHABET[(((bytes[30] & 3) << 4) | (bytes[31] >> 4)) as usize];
    encoded[42] = ALPHABET[((bytes[31] & 15) << 2) as usize];
    encoded
}
