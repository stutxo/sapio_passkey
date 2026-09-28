use super::*;
use crate::context::{Identity, InlineEvaluator, ProgramProfile, WalletContext};
use bdk_wallet::miniscript::{psbt::PsbtExt as BdkPsbtExt, Descriptor, DescriptorPublicKey};
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::consensus::deserialize;
use bitcoin::taproot::{TapLeafHash, TapNodeHash};
use bitcoin::{Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};
use p256::ecdsa::{signature::Signer, SigningKey};
use sapio_base::program::program_derivation_path;
use std::str::FromStr;

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8080";

fn context(root: Xpub) -> WalletContext {
    WalletContext {
        identity: Identity {
            protocol: "sapio-tee/program-oracle/1".into(),
            mode: "local-dev".into(),
            xpub: root,
            settings: Value::Null,
            signing: ProgramProfile {
                protocol: "SignProgramV1".into(),
                inline_evaluators: vec![InlineEvaluator {
                    id: EvaluatorId::wasm_v2(),
                    wasm_version: 2,
                }],
                registered_evaluators: vec![],
                max_connections: 4,
                request_timeout_secs: 30,
            },
        },
        origin: ORIGIN.into(),
        rp_id: RP_ID.into(),
        allow_local_dev: true,
    }
}

struct Fixture {
    context: WalletContext,
    root: Xpriv,
    credential: SigningKey,
    public_key: String,
    psbt: Psbt,
    parents: Vec<Transaction>,
}

fn fixture() -> Fixture {
    let secp = Secp256k1::new();
    // These deterministic test-only keys never enter the public wallet runtime.
    let root = Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap();
    let context = context(Xpub::from_priv(&secp, &root));
    let credential = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let public_key = hex::encode(credential.verifying_key().to_encoded_point(true));
    let app = context.validate().unwrap();
    let instance = policy(&app, &public_key).unwrap();
    let key = contract::derive_public_key(&instance, app.root).unwrap();
    let script = contract::funding_script(key);
    let parents: Vec<_> = [2, 3]
        .map(|tag| Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: script.clone(),
            }],
        })
        .into();
    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: parents
            .iter()
            .map(|parent| TxIn {
                previous_output: OutPoint::new(parent.compute_txid(), 0),
                sequence: bitcoin::Sequence(0xffff_fffd),
                ..TxIn::default()
            })
            .collect(),
        output: vec![
            TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [3; 20],
                )),
            },
            TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: script,
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();
    for (input, parent) in psbt.inputs.iter_mut().zip(&parents) {
        input.witness_utxo = Some(parent.output[0].clone());
        input.tap_internal_key = Some(key);
        input.sighash_type = Some(TapSighashType::All.into());
    }
    Fixture {
        context,
        root,
        credential,
        public_key,
        psbt,
        parents,
    }
}

fn assertion(key: &SigningKey, challenge: &[u8; 32], origin: &str) -> Value {
    let mut auth = contract::hash(RP_ID.as_bytes()).to_vec();
    auth.push(5);
    auth.extend_from_slice(&0u32.to_be_bytes());
    let client = serde_json::to_vec(&json!({
        "type": "webauthn.get", "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": origin, "crossOrigin": false,
    }))
    .unwrap();
    let mut message = auth.clone();
    message.extend_from_slice(&contract::hash(&client));
    let signature: Signature = key.sign(&message);
    json!({
        "credential_id": hex::encode([0xab; 32]),
        "authenticator_data": hex::encode(auth), "client_data_json": hex::encode(client),
        "signature": hex::encode(signature.to_der()),
    })
}

fn request_for(f: &Fixture) -> Value {
    let app = f.context.validate().unwrap();
    let instance = policy(&app, &f.public_key).unwrap();
    let view = contract::signed_view(&f.psbt, 0).unwrap();
    let challenge = contract::challenge(instance.parameters(), &view, &[23; 32]);
    let approval = assertion(&f.credential, &challenge, ORIGIN);
    dispatch(
        &app,
        "request",
        json!({
            "public_key": f.public_key, "psbt": STANDARD.encode(f.psbt.serialize()),
            "input_index": 0, "nonce": hex::encode([23; 32]),
            "authenticator_data": approval["authenticator_data"],
            "client_data_json": approval["client_data_json"], "signature": approval["signature"],
        }),
    )
    .unwrap()
}

fn signed_responses(f: &Fixture) -> Vec<OracleResponse> {
    let secp = Secp256k1::new();
    let app = f.context.validate().unwrap();
    let instance = policy(&app, &f.public_key).unwrap();
    let signing_key = f
        .root
        .derive_priv(&secp, &program_derivation_path(instance.id()))
        .unwrap()
        .to_keypair(&secp)
        .tap_tweak(&secp, None)
        .to_keypair();
    let prevouts: Vec<_> = f
        .psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.as_ref().unwrap())
        .collect();
    let mut cache = SighashCache::new(&f.psbt.unsigned_tx);
    (0..f.psbt.inputs.len())
        .map(|index| {
            let hash = cache
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    TapSighashType::All,
                )
                .unwrap();
            let mut signed = f.psbt.clone();
            signed.inputs[index].tap_key_sig = Some(bitcoin::taproot::Signature {
                signature: secp.sign_schnorr_no_aux_rand(
                    &Message::from_digest(hash.to_byte_array()),
                    &signing_key,
                ),
                sighash_type: TapSighashType::All,
            });
            OracleResponse::SignedV1(WirePsbt(signed))
        })
        .collect()
}

#[test]
fn finalization_requires_every_signature_over_the_original_multi_input_psbt() {
    let f = fixture();
    let app = f.context.validate().unwrap();
    let request = request_for(&f);
    let responses = signed_responses(&f);
    let finish = |responses: Vec<OracleResponse>| {
        dispatch(
            &app,
            "finalize_passkey",
            json!({
                "request": request, "responses": responses,
            }),
        )
    };
    let finalized = finish(responses.clone()).unwrap();
    let transaction: Transaction =
        deserialize(&hex::decode(finalized["transaction_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        transaction.compute_txid(),
        f.psbt.unsigned_tx.compute_txid()
    );
    assert_eq!(finalized["fee_sats"], 1_000);
    assert_eq!(transaction.output, f.psbt.unsigned_tx.output);
    for input in &transaction.input {
        let witness: Vec<_> = input.witness.iter().collect();
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].len(), 65);
        assert_eq!(witness[0][64], TapSighashType::All as u8);
    }

    let OracleResponse::SignedV1(WirePsbt(second)) = &responses[1] else {
        unreachable!()
    };
    let mut payment = second.clone();
    payment.unsigned_tx.output[0].value -= Amount::ONE_SAT;
    let mut prevout = second.clone();
    prevout.inputs[0].witness_utxo.as_mut().unwrap().value += Amount::ONE_SAT;
    let mut signature = second.clone();
    signature.inputs[1].tap_key_sig.as_mut().unwrap().signature =
        bitcoin::secp256k1::schnorr::Signature::from_slice(&[0; 64]).unwrap();
    let mut default_sighash = second.clone();
    default_sighash.inputs[1]
        .tap_key_sig
        .as_mut()
        .unwrap()
        .sighash_type = TapSighashType::Default;
    let mut tree = second.clone();
    tree.inputs[1].tap_merkle_root = Some(TapNodeHash::from_byte_array([1; 32]));
    for altered in [payment, prevout, signature, default_sighash, tree] {
        assert!(finish(vec![
            responses[0].clone(),
            OracleResponse::SignedV1(WirePsbt(altered))
        ])
        .is_err());
    }
    assert!(finish(vec![responses[0].clone()]).is_err());
    assert!(finish(vec![responses[0].clone(), responses[0].clone()]).is_err());
}

#[test]
fn bdk_metadata_is_projected_without_repairing_incompatible_authorization() {
    let f = fixture();
    let app = f.context.validate().unwrap();
    let key = f.psbt.inputs[0].tap_internal_key.unwrap();
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&format!("tr({key})"))
        .unwrap()
        .at_derivation_index(0)
        .unwrap();
    let mut rich = f.psbt.clone();
    for index in 0..rich.inputs.len() {
        BdkPsbtExt::update_input_with_descriptor(&mut rich, index, &descriptor).unwrap();
        rich.inputs[index].non_witness_utxo = Some(f.parents[index].clone());
    }
    BdkPsbtExt::update_output_with_descriptor(&mut rich, 1, &descriptor).unwrap();
    rich.xpub.insert(
        *app.root,
        (app.root.fingerprint(), DerivationPath::default()),
    );
    let minimal = canonical_psbt(&app, &f.public_key, &rich).unwrap();
    assert_eq!(minimal, f.psbt);
    assert_eq!(minimal.unsigned_tx, rich.unsigned_tx);

    let mut wrong_parent = rich.clone();
    wrong_parent.inputs[0]
        .non_witness_utxo
        .as_mut()
        .unwrap()
        .output[0]
        .value += Amount::ONE_SAT;
    let mut wrong_sighash = rich.clone();
    wrong_sighash.inputs[0].sighash_type = Some(TapSighashType::Default.into());
    let mut hidden_leaf = rich.clone();
    hidden_leaf.inputs[0].tap_key_origins.insert(
        key,
        (
            vec![TapLeafHash::from_byte_array([7; 32])],
            (app.root.fingerprint(), DerivationPath::default()),
        ),
    );
    let mut wrong_output = rich.clone();
    wrong_output.outputs[0].tap_internal_key = Some(key);
    let mut unknown = rich.clone();
    unknown.inputs[0].unknown.insert(
        bitcoin::psbt::raw::Key {
            type_value: 0xee,
            key: vec![1],
        },
        vec![2],
    );
    for incompatible in [
        wrong_parent,
        wrong_sighash,
        hidden_leaf,
        wrong_output,
        unknown,
    ] {
        assert!(canonical_psbt(&app, &f.public_key, &incompatible).is_err());
    }
}

#[test]
fn finalization_rejects_wire_smuggling_and_foreign_policy() {
    let f = fixture();
    let app = f.context.validate().unwrap();
    let request = request_for(&f);
    let responses = serde_json::to_value(signed_responses(&f)).unwrap();
    let mut trailing = responses.clone();
    trailing[0]["SignedV1"]
        .as_array_mut()
        .unwrap()
        .push(json!(0));
    let mut truncated = responses.clone();
    truncated[0]["SignedV1"].as_array_mut().unwrap().pop();
    let mut oversized = responses.clone();
    for index in 0..4 {
        oversized[0]["SignedV1"][index] = json!(255);
    }
    for altered in [trailing, truncated, oversized] {
        assert!(dispatch(
            &app,
            "finalize_passkey",
            json!({"request": request, "responses": altered})
        )
        .is_err());
    }
    let mut substituted = request.clone();
    substituted["SignProgramV1"]["instance"]["program"][0] = json!(255);
    assert!(dispatch(
        &app,
        "finalize_passkey",
        json!({"request": substituted, "responses": responses})
    )
    .is_err());
    let mut foreign = f.context.clone();
    foreign.origin = "http://localhost:8081".into();
    assert!(dispatch(
        &foreign.validate().unwrap(),
        "finalize_passkey",
        json!({"request": request, "responses": responses})
    )
    .is_err());
}

#[test]
fn stateless_restoration_binds_two_indexed_assertions_and_original_json() {
    let f = fixture();
    let app = f.context.validate().unwrap();
    let nonce = [31; 32];
    let challenges = restoration_challenges(&app, &nonce);
    // Independent byte framing keeps the existing recovery protocol stable.
    for (index, challenge) in challenges.iter().enumerate() {
        let mut committed = b"sapio-passkey/restore/v1\0".to_vec();
        committed.extend_from_slice(&nonce);
        committed.push(index as u8);
        committed.extend_from_slice(&contract::hash(contract::WASM));
        committed.extend_from_slice(
            &bitcoin::blockdata::constants::genesis_block(Network::Regtest)
                .block_hash()
                .to_byte_array(),
        );
        committed.extend_from_slice(&app.root.encode());
        committed.extend_from_slice(&contract::hash(RP_ID.as_bytes()));
        committed.extend_from_slice(&contract::hash(ORIGIN.as_bytes()));
        assert_eq!(*challenge, contract::hash(&committed));
    }
    let approvals = challenges.map(|challenge| assertion(&f.credential, &challenge, ORIGIN));
    let body = json!({"nonce": hex::encode(nonce), "assertions": approvals});
    let recovered = dispatch(&app, "restore", body.clone()).unwrap();
    assert_eq!(recovered["public_key"], f.public_key);
    assert_eq!(recovered["credential_id"], hex::encode([0xab; 32]));
    let mut repeated = body.clone();
    repeated["assertions"][1] = repeated["assertions"][0].clone();
    assert!(dispatch(&app, "restore", repeated).is_err());
    let mut mismatched = body.clone();
    mismatched["assertions"][1]["credential_id"] = json!(hex::encode([0xcd; 32]));
    assert!(dispatch(&app, "restore", mismatched).is_err());
    let mut stale = body.clone();
    stale["nonce"] = json!(hex::encode([32; 32]));
    assert!(dispatch(&app, "restore", stale).is_err());
    let other = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    let mut different_key = body.clone();
    different_key["assertions"][1] = assertion(&other, &challenges[1], ORIGIN);
    assert!(dispatch(&app, "restore", different_key).is_err());

    let mut duplicate = body;
    let original = hex::decode(
        duplicate["assertions"][0]["client_data_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let original = std::str::from_utf8(&original).unwrap();
    let client = format!("{{\"origin\":\"{ORIGIN}\",{}", &original[1..]);
    let mut message = hex::decode(
        duplicate["assertions"][0]["authenticator_data"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    message.extend_from_slice(&contract::hash(client.as_bytes()));
    let signature: Signature = f.credential.sign(&message);
    duplicate["assertions"][0]["client_data_json"] = json!(hex::encode(client.as_bytes()));
    duplicate["assertions"][0]["signature"] = json!(hex::encode(signature.to_der()));
    assert!(dispatch(&app, "restore", duplicate).is_err());
}

#[test]
fn public_context_allows_only_nitro_signet_or_opted_in_localhost_regtest() {
    let f = fixture();
    assert_eq!(f.context.validate().unwrap().network, Network::Regtest);
    let mut no_opt_in = f.context.clone();
    no_opt_in.allow_local_dev = false;
    assert!(no_opt_in.validate().is_err());
    let mut remote_dev = f.context.clone();
    remote_dev.origin = "https://wallet.example".into();
    remote_dev.rp_id = "wallet.example".into();
    assert!(remote_dev.validate().is_err());
    let mut nitro = remote_dev;
    nitro.identity.mode = "nitro".into();
    nitro.identity.settings = json!({"network": "signet"});
    assert_eq!(nitro.validate().unwrap().network, Network::Signet);
    for network in ["bitcoin", "testnet", "regtest"] {
        let mut unsupported = nitro.clone();
        unsupported.identity.settings = json!({"network": network});
        assert!(unsupported.validate().is_err());
    }
    nitro.origin = ORIGIN.into();
    nitro.rp_id = RP_ID.into();
    assert_eq!(nitro.validate().unwrap().network, Network::Signet);
    nitro.allow_local_dev = false;
    assert!(nitro.validate().is_err());
}
