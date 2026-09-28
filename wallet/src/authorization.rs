//! Stateless public restoration and immutable passkey transaction authorization.
use crate::{
    context::Wallet,
    contract,
    wire::{OracleRequest, OracleResponse, SigningRequest, WirePsbt, MAX_PSBT},
};
use anyhow::{anyhow, ensure, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Address, Amount, Txid};
use miniscript::psbt::PsbtExt;
use p256::ecdsa::{Signature, VerifyingKey};
use sapio_base::program::{EvaluatorId, ProgramInstance, ProgramSpendPath};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const MAX_MONEY: u64 = 2_100_000_000_000_000;
const MAX_INPUTS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletInput {
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInput {
    public_key: String,
    psbt: String,
    input_index: u32,
    nonce: String,
    authenticator_data: String,
    client_data_json: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreNonce {
    nonce: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreInput {
    nonce: String,
    assertions: [RestoreAssertion; 2],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreAssertion {
    credential_id: String,
    authenticator_data: String,
    client_data_json: String,
    signature: String,
}

// Match the guest's extensible clientDataJSON parsing without reserializing the
// signed bytes. Derive rejects duplicate recognized fields, even escaped names.
#[derive(Deserialize)]
struct RestoreClientData {
    #[serde(rename = "type")]
    ceremony: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
    #[serde(rename = "topOrigin", default, deserialize_with = "reject_top_origin")]
    top_origin: bool,
}

fn reject_top_origin<'de, D: serde::Deserializer<'de>>(_: D) -> Result<bool, D::Error> {
    Err(serde::de::Error::custom("topOrigin is not supported"))
}

fn decode_hex(value: &str, maximum: usize, name: &str) -> Result<Vec<u8>> {
    ensure!(value.len() <= maximum * 2, "{name} exceeds byte limit");
    hex::decode(value).with_context(|| format!("invalid {name} hex"))
}

fn policy(app: &Wallet<'_>, public_key: &str) -> Result<ProgramInstance> {
    let key = decode_hex(public_key, 33, "public key")?;
    contract::instance(app.network, app.rp_id, app.origin, &key)
}

fn checked_sats(value: u64, name: &str) -> Result<Amount> {
    ensure!(
        (1..=MAX_MONEY).contains(&value),
        "{name} must be positive integer satoshis within MAX_MONEY"
    );
    Ok(Amount::from_sat(value))
}

/// Strip only compatible public BDK metadata; never repair a different spend policy.
pub(crate) fn canonical_psbt(app: &Wallet<'_>, public_key: &str, rich: &Psbt) -> Result<Psbt> {
    let instance = policy(app, public_key)?;
    let key = contract::derive_public_key(&instance, app.root)?;
    let funding_script = contract::funding_script(key);
    ensure!(
        rich.version == 0 && rich.proprietary.is_empty() && rich.unknown.is_empty(),
        "unsupported global PSBT metadata"
    );
    ensure!(
        (1..=MAX_INPUTS).contains(&rich.inputs.len())
            && rich.inputs.len() == rich.unsigned_tx.input.len()
            && rich.outputs.len() == rich.unsigned_tx.output.len(),
        "invalid PSBT input or output maps"
    );
    let mut minimal = Psbt::from_unsigned_tx(rich.unsigned_tx.clone())?;
    for (index, input) in rich.inputs.iter().enumerate() {
        ensure!(
            input.sighash_type == Some(TapSighashType::All.into())
                && input.tap_internal_key == Some(key)
                && input.tap_merkle_root.is_none()
                && input.tap_scripts.is_empty()
                && input.tap_script_sigs.is_empty(),
            "PSBT must use the exact tree-free wallet key and SIGHASH_ALL"
        );
        ensure!(
            input.partial_sigs.is_empty()
                && input.tap_key_sig.is_none()
                && input.final_script_sig.is_none()
                && input.final_script_witness.is_none()
                && input.redeem_script.is_none()
                && input.witness_script.is_none()
                && input.bip32_derivation.is_empty()
                && input.ripemd160_preimages.is_empty()
                && input.sha256_preimages.is_empty()
                && input.hash160_preimages.is_empty()
                && input.hash256_preimages.is_empty()
                && input.proprietary.is_empty()
                && input.unknown.is_empty(),
            "unsupported PSBT input metadata or existing signature"
        );
        ensure!(
            input
                .tap_key_origins
                .iter()
                .all(|(origin_key, (leaves, _))| *origin_key == key && leaves.is_empty()),
            "key origin describes a different Taproot spend"
        );
        let prevout = input
            .witness_utxo
            .as_ref()
            .context("missing funding prevout")?;
        ensure!(
            prevout.script_pubkey == funding_script,
            "funding script does not match the committed passkey wallet"
        );
        if let Some(parent) = &input.non_witness_utxo {
            let outpoint = rich.unsigned_tx.input[index].previous_output;
            ensure!(
                !parent.input.is_empty()
                    && parent.compute_txid() == outpoint.txid
                    && parent.output.get(outpoint.vout as usize) == Some(prevout),
                "funding transaction does not match its prevout"
            );
        }
        minimal.inputs[index].witness_utxo = Some(prevout.clone());
        minimal.inputs[index].tap_internal_key = Some(key);
        minimal.inputs[index].sighash_type = Some(TapSighashType::All.into());
    }
    for (output, txout) in rich.outputs.iter().zip(&rich.unsigned_tx.output) {
        ensure!(
            output.redeem_script.is_none()
                && output.witness_script.is_none()
                && output.bip32_derivation.is_empty()
                && output.tap_tree.is_none()
                && output.proprietary.is_empty()
                && output.unknown.is_empty(),
            "unsupported PSBT output metadata"
        );
        ensure!(
            output.tap_internal_key.is_none_or(|output_key| {
                output_key == key && txout.script_pubkey == funding_script
            }) && output
                .tap_key_origins
                .iter()
                .all(|(origin_key, (leaves, _))| {
                    *origin_key == key && leaves.is_empty() && txout.script_pubkey == funding_script
                }),
            "output metadata describes a different wallet or Taproot spend"
        );
    }
    // Global xpubs and compatible key origins are advisory, not signing policy.
    // Parent transactions were cross-checked above; the minimal prevouts bind fees.
    check_signing_psbt(app, &instance, &minimal)?;
    Ok(minimal)
}

/// Check the exact tree-free PSBT shape before passkey signing or finalization.
fn check_signing_psbt(app: &Wallet<'_>, instance: &ProgramInstance, psbt: &Psbt) -> Result<u64> {
    ensure!(psbt.serialize().len() <= MAX_PSBT, "PSBT exceeds 64 KiB");
    ensure!(
        (1..=MAX_INPUTS).contains(&psbt.inputs.len())
            && psbt.unsigned_tx.input.len() == psbt.inputs.len(),
        "wallet signs between one and sixteen funding inputs"
    );
    ensure!(
        psbt.unsigned_tx.version == bitcoin::transaction::Version::TWO
            && psbt.unsigned_tx.lock_time == bitcoin::absolute::LockTime::ZERO,
        "unexpected transaction version or locktime"
    );
    ensure!(
        (1..=2).contains(&psbt.unsigned_tx.output.len()),
        "expected payment and optional change output"
    );
    let key = contract::derive_public_key(instance, app.root)?;
    let funding_script = contract::funding_script(key);
    let mut expected = Psbt::from_unsigned_tx(psbt.unsigned_tx.clone())?;
    let mut seen = BTreeSet::new();
    let mut funding = 0u64;
    for (index, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        ensure!(
            txin.sequence == bitcoin::Sequence(0xffff_fffd)
                && txin.previous_output.txid != Txid::all_zeros()
                && seen.insert(txin.previous_output),
            "invalid or duplicate funding outpoint/sequence"
        );
        let prevout = psbt.inputs[index]
            .witness_utxo
            .as_ref()
            .context("missing funding prevout")?;
        checked_sats(prevout.value.to_sat(), "funding value")?;
        ensure!(
            prevout.script_pubkey == funding_script,
            "funding script does not match the committed passkey wallet"
        );
        funding = funding
            .checked_add(prevout.value.to_sat())
            .context("funding sum overflow")?;
        ensure!(funding <= MAX_MONEY, "funding sum exceeds MAX_MONEY");
        expected.inputs[index].witness_utxo = Some(prevout.clone());
        expected.inputs[index].tap_internal_key = Some(key);
        expected.inputs[index].sighash_type = Some(TapSighashType::All.into());
    }
    ensure!(
        *psbt == expected,
        "unexpected PSBT metadata, signature, annex, or alternate Taproot path"
    );
    let mut total = 0u64;
    for (index, output) in psbt.unsigned_tx.output.iter().enumerate() {
        checked_sats(output.value.to_sat(), "output value")?;
        ensure!(
            output.value >= output.script_pubkey.minimal_non_dust(),
            "output is dust"
        );
        ensure!(
            output.script_pubkey.is_p2pkh()
                || output.script_pubkey.is_p2sh()
                || output.script_pubkey.is_p2wpkh()
                || output.script_pubkey.is_p2wsh()
                || output.script_pubkey.is_p2tr(),
            "unsupported recipient script"
        );
        if index == 1 {
            ensure!(
                output.script_pubkey == funding_script,
                "change must return to the passkey wallet"
            );
        }
        total = total
            .checked_add(output.value.to_sat())
            .context("output sum overflow")?;
    }
    let fee = funding
        .checked_sub(total)
        .context("outputs exceed funding")?;
    checked_sats(fee, "fee")?;
    Ok(fee)
}

fn finalize(mut signed: Psbt, original_txid: Txid, fee: u64) -> Result<Value> {
    signed
        .finalize_mut(&Secp256k1::verification_only())
        .map_err(|errors| anyhow!("could not finalize verified Taproot signature: {errors:?}"))?;
    let signed_psbt = STANDARD.encode(signed.serialize());
    let transaction = signed
        .extract_tx()
        .context("extracting transaction with fee-rate safety check")?;
    ensure!(
        transaction.compute_txid() == original_txid,
        "finalization changed the unsigned transaction"
    );
    Ok(
        json!({"txid": transaction.compute_txid().to_string(), "transaction_hex": hex::encode(serialize(&transaction)), "signed_psbt": signed_psbt, "fee_sats": fee}),
    )
}

fn parse_body<T: serde::de::DeserializeOwned>(body: Value) -> Result<T> {
    // Do not reflect caller-supplied field values in ABI errors.
    serde_json::from_value(body).map_err(|_| anyhow!("invalid operation body"))
}

fn decode_psbt(encoded: &str) -> Result<Psbt> {
    ensure!(
        encoded.len() <= MAX_PSBT.div_ceil(3) * 4,
        "PSBT exceeds 64 KiB"
    );
    let bytes = STANDARD.decode(encoded).context("invalid base64 PSBT")?;
    ensure!(bytes.len() <= MAX_PSBT, "PSBT exceeds 64 KiB");
    Psbt::deserialize(&bytes).context("invalid PSBT")
}

fn nonce(encoded: &str) -> Result<[u8; 32]> {
    ensure!(
        encoded.len() == 64
            && encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "nonce must be 32-byte lowercase hex"
    );
    decode_hex(encoded, 32, "nonce")?
        .try_into()
        .map_err(|_| anyhow!("nonce must be 32 bytes"))
}

fn restoration_challenges(app: &Wallet<'_>, nonce: &[u8; 32]) -> [[u8; 32]; 2] {
    let module = contract::hash(contract::WASM);
    let genesis = bitcoin::blockdata::constants::genesis_block(app.network)
        .block_hash()
        .to_byte_array();
    let root = app.root.encode();
    let rp_id = contract::hash(app.rp_id.as_bytes());
    let origin = contract::hash(app.origin.as_bytes());
    let mut base = sha256::Hash::engine();
    base.input(b"sapio-passkey/restore/v1\0");
    base.input(nonce);
    [0, 1].map(|index| {
        let mut engine = base.clone();
        engine.input(&[index]);
        engine.input(&module);
        engine.input(&genesis);
        engine.input(&root);
        engine.input(&rp_id);
        engine.input(&origin);
        sha256::Hash::from_engine(engine).to_byte_array()
    })
}

fn restoration_candidates(
    app: &Wallet<'_>,
    assertion: &RestoreAssertion,
    challenge: &[u8; 32],
) -> Result<[Option<[u8; 33]>; 4]> {
    let auth = decode_hex(&assertion.authenticator_data, 37, "authenticator data")?;
    let client = decode_hex(
        &assertion.client_data_json,
        contract::MAX_CLIENT_DATA,
        "clientDataJSON",
    )?;
    let der = decode_hex(&assertion.signature, 72, "signature")?;
    ensure!(auth.len() == 37, "invalid authenticator data length");
    ensure!(!client.is_empty(), "empty clientDataJSON");
    ensure!((8..=72).contains(&der.len()), "invalid ES256 DER length");
    ensure!(
        auth[..32] == contract::hash(app.rp_id.as_bytes()),
        "restoration RP ID mismatch"
    );
    let flags = auth[32];
    ensure!(
        flags & 0x05 == 0x05 && flags & !0x1d == 0 && (flags & 0x10 == 0 || flags & 0x08 != 0),
        "invalid authenticator flags"
    );
    let parsed: RestoreClientData =
        serde_json::from_slice(&client).map_err(|_| anyhow!("invalid clientDataJSON"))?;
    let mut expected = [0; 43];
    URL_SAFE_NO_PAD
        .encode_slice(challenge, &mut expected)
        .expect("32-byte challenge encodes into 43 bytes");
    ensure!(
        parsed.ceremony == "webauthn.get"
            && parsed.challenge.as_bytes() == expected
            && parsed.origin == app.origin
            && !parsed.cross_origin
            && !parsed.top_origin,
        "restoration client data mismatch"
    );
    // Original signed JSON is authoritative; parsing is only for context checks.
    let mut signed = [0; 69];
    signed[..37].copy_from_slice(&auth);
    signed[37..].copy_from_slice(&contract::hash(&client));
    let digest = contract::hash(&signed);
    // Strict DER/scalar parsing deliberately preserves valid high-S signatures.
    let signature = Signature::from_der(&der).map_err(|_| anyhow!("invalid ES256 signature"))?;
    let mut candidates = [None; 4];
    for id in 0u8..4 {
        // RustCrypto RecoveryId has exactly the two-bit values 0..=3. Recovery
        // also verifies each candidate against this digest and signature.
        if let Ok(key) = VerifyingKey::recover_from_prehash(
            &digest,
            &signature,
            id.try_into().expect("valid two-bit RecoveryId"),
        ) {
            let mut compressed = [0; 33];
            compressed.copy_from_slice(key.to_encoded_point(true).as_bytes());
            candidates[usize::from(id)] = Some(compressed);
        }
    }
    Ok(candidates)
}

fn restore(app: &Wallet<'_>, input: RestoreInput) -> Result<Value> {
    let challenges = restoration_challenges(app, &nonce(&input.nonce)?);
    let first_id = decode_hex(&input.assertions[0].credential_id, 1024, "credential ID")?;
    let second_id = decode_hex(&input.assertions[1].credential_id, 1024, "credential ID")?;
    ensure!(
        !first_id.is_empty() && first_id == second_id,
        "restoration requires the same nonempty credential ID"
    );
    let first = restoration_candidates(app, &input.assertions[0], &challenges[0])?;
    let second = restoration_candidates(app, &input.assertions[1], &challenges[1])?;
    let mut common = None;
    for key in first.into_iter().flatten() {
        if second.contains(&Some(key)) {
            ensure!(
                common.is_none() || common == Some(key),
                "ambiguous restoration public key"
            );
            common = Some(key);
        }
    }
    let public_key = common.context("restoration assertions have no common public key")?;
    // Public-data reconstruction only: no authorization state or signing path.
    Ok(json!({
        "public_key": hex::encode(public_key),
        "credential_id": hex::encode(first_id),
    }))
}

pub(crate) fn dispatch(app: &Wallet<'_>, operation: &str, body: Value) -> Result<Value> {
    match operation {
        "configure" => {
            ensure!(
                body.as_object().is_some_and(|body| body.is_empty()),
                "configure requires an empty object"
            );
            Ok(json!({
                "rp_id": app.rp_id, "origin": app.origin, "network": app.network,
                "genesis_hash": hex::encode(bitcoin::blockdata::constants::genesis_block(app.network).block_hash().to_byte_array()),
                "xpub": app.root.to_string(), "module_sha256": hex::encode(contract::hash(contract::WASM)),
                "module_bytes": contract::WASM.len(), "local_dev": app.local_dev,
            }))
        }
        "wallet" => {
            let input: WalletInput = parse_body(body)?;
            let instance = policy(app, &input.public_key)?;
            let key = contract::derive_public_key(&instance, app.root)?;
            let script = contract::funding_script(key);
            let address = Address::from_script(&script, app.network)?;
            Ok(json!({
                "parameters": hex::encode(instance.parameters()), "program_id": instance.id(),
                "address": address.to_string(), "script_pubkey": hex::encode(script.as_bytes()),
                "internal_key": key.to_string(),
            }))
        }
        "restore_challenges" => {
            let input: RestoreNonce = parse_body(body)?;
            Ok(json!({
                "challenges": restoration_challenges(app, &nonce(&input.nonce)?).map(hex::encode),
            }))
        }
        "restore" => restore(app, parse_body(body)?),
        "request" => request(app, parse_body(body)?),
        "finalize_passkey" => finalize_passkey(app, parse_body(body)?),
        _ => anyhow::bail!("unknown wallet operation"),
    }
}

/// Project an already reviewed transaction into the unchanged indexed policy challenges.
pub(crate) fn proposal(
    app: &Wallet<'_>,
    public_key: &str,
    psbt: &Psbt,
    summary: Value,
    nonce_hex: &str,
) -> Result<Value> {
    let nonce = nonce(nonce_hex)?;
    let instance = policy(app, public_key)?;
    check_signing_psbt(app, &instance, psbt)?;
    let address = contract::address(&instance, app.root, app.network)?;
    let views: Vec<_> = (0..psbt.inputs.len())
        .map(|index| contract::signed_view(psbt, index as u32))
        .collect::<Result<_>>()?;
    let challenges: Vec<_> = views
        .iter()
        .map(|view| hex::encode(contract::challenge(instance.parameters(), view, &nonce)))
        .collect();
    Ok(json!({
        "parameters": hex::encode(instance.parameters()),
        "address": address.to_string(),
        "program_id": instance.id(), "summary": summary,
        "nonce": hex::encode(nonce),
        "challenges": challenges,
        "views": views.iter().map(hex::encode).collect::<Vec<_>>(),
        "psbt": STANDARD.encode(psbt.serialize()),
    }))
}

fn request(app: &Wallet<'_>, input: SignInput) -> Result<Value> {
    let instance = policy(app, &input.public_key)?;
    let psbt = decode_psbt(&input.psbt)?;
    check_signing_psbt(app, &instance, &psbt)?;
    ensure!(
        (input.input_index as usize) < psbt.inputs.len(),
        "selected input is out of range"
    );
    let nonce = nonce(&input.nonce)?;
    let auth = decode_hex(&input.authenticator_data, 37, "authenticator data")?;
    let client_data = decode_hex(
        &input.client_data_json,
        contract::MAX_CLIENT_DATA,
        "clientDataJSON",
    )?;
    let signature = decode_hex(&input.signature, 72, "signature")?;
    Ok(serde_json::to_value(OracleRequest::SignProgramV1(
        SigningRequest {
            instance,
            input_index: input.input_index,
            witness: contract::witness(&nonce, &auth, &client_data, &signature)?,
            path: ProgramSpendPath::KeyPath,
            psbt: WirePsbt(psbt),
        },
    ))?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyFinalization {
    request: OracleRequest,
    responses: Vec<OracleResponse>,
}

/// Authenticate the original request's policy to the loaded static context.
fn check_instance(app: &Wallet<'_>, instance: &ProgramInstance) -> Result<()> {
    ensure!(
        instance.evaluator() == EvaluatorId::wasm_v2() && instance.program() == contract::WASM,
        "request does not use the pinned inline passkey evaluator"
    );
    let parameters = instance.parameters();
    contract::check_parameters(parameters)?;
    ensure!(
        parameters[4..36]
            == bitcoin::blockdata::constants::genesis_block(app.network)
                .block_hash()
                .to_byte_array(),
        "request policy uses a different Bitcoin network"
    );
    ensure!(
        matches!(parameters[36], 2 | 3),
        "invalid compressed passkey public key"
    );
    p256::PublicKey::from_sec1_bytes(&parameters[36..69])
        .map_err(|_| anyhow!("invalid policy passkey"))?;
    ensure!(
        parameters[69..101] == contract::hash(app.rp_id.as_bytes())
            && &parameters[105..] == app.origin.as_bytes(),
        "request policy has a different WebAuthn context"
    );
    Ok(())
}

fn check_witness(witness: &[u8]) -> Result<()> {
    ensure!(witness.len() >= 32, "truncated passkey witness");
    let nonce: &[u8; 32] = witness[..32].try_into()?;
    let mut remaining = &witness[32..];
    let mut fields = [&[][..]; 3];
    for field in &mut fields {
        ensure!(remaining.len() >= 4, "truncated passkey witness field");
        let length = u32::from_le_bytes(remaining[..4].try_into()?) as usize;
        remaining = &remaining[4..];
        ensure!(
            length <= remaining.len(),
            "truncated passkey witness payload"
        );
        *field = &remaining[..length];
        remaining = &remaining[length..];
    }
    ensure!(remaining.is_empty(), "trailing passkey witness bytes");
    // Reuse the policy's exact field bounds and canonical framing.
    ensure!(
        contract::witness(nonce, fields[0], fields[1], fields[2])? == witness,
        "invalid passkey witness"
    );
    Ok(())
}

fn finalize_passkey(app: &Wallet<'_>, input: PasskeyFinalization) -> Result<Value> {
    let OracleRequest::SignProgramV1(request) = input.request;
    ensure!(
        request.input_index == 0 && request.path == ProgramSpendPath::KeyPath,
        "finalization requires the original first-input key-path request"
    );
    check_instance(app, &request.instance)?;
    check_witness(&request.witness)?;
    let mut original = request.psbt.0;
    let fee = check_signing_psbt(app, &request.instance, &original)?;
    ensure!(
        input.responses.len() == original.inputs.len(),
        "one oracle response per input is required"
    );
    let secp = Secp256k1::verification_only();
    let key = contract::derive_public_key(&request.instance, app.root)?;
    let output_key = key.tap_tweak(&secp, None).0.to_x_only_public_key();
    let prevouts: Vec<_> = original
        .inputs
        .iter()
        .map(|input| input.witness_utxo.as_ref().expect("checked prevout"))
        .collect();
    let mut sighashes = SighashCache::new(&original.unsigned_tx);
    let mut signatures = Vec::with_capacity(original.inputs.len());
    for (index, response) in input.responses.into_iter().enumerate() {
        let mut signed = match response {
            OracleResponse::SignedV1(WirePsbt(psbt)) => psbt,
            OracleResponse::RejectedV1(reason) => {
                anyhow::bail!("oracle rejected passkey authorization: {reason}")
            }
        };
        let signature = signed
            .inputs
            .get_mut(index)
            .and_then(|input| input.tap_key_sig.take())
            .context("oracle response is missing the requested signature")?;
        ensure!(
            signed == original,
            "oracle response modified unrelated PSBT data"
        );
        ensure!(
            signature.sighash_type == TapSighashType::All,
            "oracle response must use explicit SIGHASH_ALL"
        );
        let sighash = sighashes.taproot_key_spend_signature_hash(
            index,
            &Prevouts::All(&prevouts),
            TapSighashType::All,
        )?;
        secp.verify_schnorr(
            &signature.signature,
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .context("invalid oracle signature for the pinned wallet and original PSBT")?;
        signatures.push(signature);
    }
    for (input, signature) in original.inputs.iter_mut().zip(signatures) {
        input.tap_key_sig = Some(signature);
    }
    let txid = original.unsigned_tx.compute_txid();
    finalize(original, txid, fee)
}

#[cfg(test)]
#[path = "authorization_tests.rs"]
mod tests;
