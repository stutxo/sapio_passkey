use super::*;
use bdk_wallet::chain::{BlockId, CheckPoint};
use bitcoin::{bip32::Xpriv, TxIn, TxOut, WPubkeyHash};
use p256::ecdsa::SigningKey;
use sapio_base::program::program_derivation_path;

struct Fixture {
    root: Xpriv,
    xpub: Xpub,
    public_key: String,
    engine: Engine,
}

fn app(root: &Xpub) -> Wallet<'_> {
    Wallet {
        root,
        network: Network::Regtest,
        local_dev: true,
        origin: "http://localhost:8080",
        rp_id: "localhost",
    }
}

fn fixture() -> Fixture {
    // Deterministic, test-only oracle keys; the browser engine has no secret key.
    let root = Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap();
    let xpub = Xpub::from_priv(&Secp256k1::new(), &root);
    let passkey = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let public_key = hex::encode(passkey.verifying_key().to_encoded_point(true));
    let engine = Engine::new(&app(&xpub), &public_key).unwrap();
    Fixture {
        root,
        xpub,
        public_key,
        engine,
    }
}

fn block(height: u32, tag: u8) -> BlockId {
    BlockId {
        height,
        hash: BlockHash::from_byte_array([tag; 32]),
    }
}

fn checkpoint(genesis: BlockHash, blocks: &[BlockId]) -> CheckPoint {
    CheckPoint::new(BlockId {
        height: 0,
        hash: genesis,
    })
    .extend(blocks.iter().copied())
    .unwrap()
}

fn deposit(f: &mut Fixture, value: u64, tag: u8, confirmed: bool) -> Transaction {
    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: f.engine.address.script_pubkey(),
        }],
    };
    let mut update = Update::default();
    update.chain = Some(checkpoint(
        f.engine.binding.genesis_hash,
        &[block(1, 1), block(120, 120)],
    ));
    update.tx_update.txs.push(Arc::new(transaction.clone()));
    if confirmed {
        update.tx_update.anchors.insert((
            ConfirmationBlockTime {
                block_id: block(1, 1),
                confirmation_time: 1_000,
            },
            transaction.compute_txid(),
        ));
    } else {
        update
            .tx_update
            .seen_ats
            .insert((transaction.compute_txid(), 1_000));
    }
    f.engine.apply_update(update, 1_000).unwrap();
    transaction
}

fn external_address() -> String {
    Address::from_script(
        &ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([9; 20])),
        Network::Regtest,
    )
    .unwrap()
    .to_string()
}

fn prepare(f: &mut Fixture, amount: Option<u64>, recipient: &str) -> Value {
    f.engine
        .prepare(
            &app(&f.xpub),
            json!({
                "recipient": recipient, "amount_sats": amount, "fee_rate_sat_vb": 1,
                "nonce": hex::encode([20; 32]),
            }),
            2_000,
        )
        .unwrap()
}

fn sign_prepared(f: &mut Fixture, now: u64) -> Transaction {
    let psbt = &f.engine.prepared.as_ref().unwrap().psbt;
    let instance = contract::instance(
        Network::Regtest,
        "localhost",
        "http://localhost:8080",
        &hex::decode(&f.public_key).unwrap(),
    )
    .unwrap();
    let secp = Secp256k1::new();
    let key = f
        .root
        .derive_priv(&secp, &program_derivation_path(instance.id()))
        .unwrap()
        .to_keypair(&secp)
        .tap_tweak(&secp, None)
        .to_keypair();
    let mut transaction = psbt.unsigned_tx.clone();
    let prevouts: Vec<_> = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.as_ref().unwrap())
        .collect();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (index, input) in transaction.input.iter_mut().enumerate() {
        let hash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::All)
            .unwrap();
        let signature = bitcoin::taproot::Signature {
            signature: secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &key),
            sighash_type: TapSighashType::All,
        };
        input.witness = Witness::from_slice(&[signature.to_vec()]);
    }
    f.engine
        .record_finalized(&hex::encode(serialize(&transaction)), now)
        .unwrap();
    transaction
}

fn status(snapshot: &Value, txid: Txid) -> &str {
    snapshot["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["txid"] == txid.to_string())
        .unwrap()["status"]
        .as_str()
        .unwrap()
}

#[test]
fn uncertain_and_dismissed_payments_keep_reservations_across_eviction_and_cache_load() {
    let mut f = fixture();
    deposit(&mut f, 60_000, 2, true);
    deposit(&mut f, 40_000, 3, true);
    prepare(&mut f, Some(50_000), &external_address());
    let signed = sign_prepared(&mut f, 2_000);
    let txid = signed.compute_txid();
    f.engine
        .broadcast_result(json!({ "txid": txid, "status": "uncertain" }), 2_001)
        .unwrap();
    let mut omission = Update::default();
    omission.tx_update.evicted_ats.insert((txid, 100_000));
    f.engine.apply_update(omission.clone(), 100_000).unwrap();
    let snapshot = f.engine.snapshot(100_000).unwrap();
    assert_eq!(snapshot["balance"]["spendable_sats"], 40_000);
    assert_eq!(status(&snapshot, txid), "uncertain");
    assert_eq!(
        snapshot["outbox"][0]["transaction_hex"],
        hex::encode(serialize(&signed))
    );
    let dismissed = f
        .engine
        .discard_result(json!({ "txid": txid }), 100_001)
        .unwrap();
    assert!(dismissed["outbox"].as_array().unwrap().is_empty());
    assert_eq!(dismissed["balance"]["spendable_sats"], 40_000);

    let state = f.engine.export_state().unwrap();
    let mut restored = Engine::new(&app(&f.xpub), &f.public_key).unwrap();
    restored
        .import_state(json!({ "state": state }), 100_002)
        .unwrap();
    restored.apply_update(omission, 100_003).unwrap();
    assert!(restored
        .prepare(
            &app(&f.xpub),
            json!({
                "recipient": external_address(), "amount_sats": 50_000, "fee_rate_sat_vb": 1,
                "nonce": hex::encode([21; 32]),
            }),
            100_004
        )
        .is_err());
    assert_eq!(
        restored.snapshot(100_004).unwrap()["balance"]["spendable_sats"],
        40_000
    );
    // Reopening needs no cache or secret recovery file: chain data reconstructs
    // both the address and the accepted transaction's current accounting.
    let mut clean = Engine::new(&app(&f.xpub), &f.public_key).unwrap();
    let mut update = Update::default();
    update.chain = Some(f.engine.wallet.latest_checkpoint());
    update.tx_update = f.engine.wallet.tx_graph().clone().into();
    clean.apply_update(update, 100_005).unwrap();
    assert_eq!(
        clean.snapshot(100_005).unwrap()["address"],
        dismissed["address"]
    );
    assert_eq!(
        clean.snapshot(100_005).unwrap()["balance"],
        dismissed["balance"]
    );
}

#[test]
fn only_confirmed_conflicts_release_other_reserved_inputs_and_reorg_restores_them() {
    let mut f = fixture();
    deposit(&mut f, 40_000, 2, true);
    deposit(&mut f, 30_000, 3, true);
    prepare(&mut f, Some(60_000), &external_address());
    let signed = sign_prepared(&mut f, 2_000);
    let original = signed.compute_txid();
    let first = signed.input[0].previous_output;
    let first_value = f.engine.wallet.tx_graph().get_txout(first).unwrap().value;
    let conflict = Transaction {
        version: signed.version,
        lock_time: signed.lock_time,
        input: vec![signed.input[0].clone()],
        output: vec![TxOut {
            script_pubkey: signed.output[0].script_pubkey.clone(),
            value: first_value - Amount::from_sat(1_000),
        }],
    };
    let conflict_id = conflict.compute_txid();
    let mut update = Update::default();
    update.tx_update.txs.push(Arc::new(conflict));
    update.tx_update.seen_ats.insert((conflict_id, 3_000));
    f.engine.apply_update(update, 3_000).unwrap();
    let pending = f.engine.snapshot(3_000).unwrap();
    assert_eq!(status(&pending, original), "replaced");
    assert_eq!(pending["balance"]["spendable_sats"], 0);
    assert_eq!(pending["outbox"][0]["txid"], original.to_string());

    let mut confirm = Update::default();
    confirm.chain = Some(
        f.engine
            .wallet
            .latest_checkpoint()
            .push(block(121, 121))
            .unwrap(),
    );
    confirm.tx_update.anchors.insert((
        ConfirmationBlockTime {
            block_id: block(121, 121),
            confirmation_time: 4_000,
        },
        conflict_id,
    ));
    f.engine.apply_update(confirm, 4_000).unwrap();
    let confirmed = f.engine.snapshot(4_000).unwrap();
    assert_eq!(
        confirmed["balance"]["spendable_sats"],
        70_000 - first_value.to_sat()
    );
    assert!(confirmed["outbox"].as_array().unwrap().is_empty());

    let mut reorg = Update::default();
    reorg.chain = Some(checkpoint(
        f.engine.binding.genesis_hash,
        &[block(1, 1), block(120, 120), block(121, 122)],
    ));
    f.engine.apply_update(reorg, 5_000).unwrap();
    let snapshot = f.engine.snapshot(5_000).unwrap();
    assert_eq!(snapshot["balance"]["spendable_sats"], 0);
    assert_eq!(snapshot["outbox"][0]["txid"], original.to_string());
    assert_eq!(status(&snapshot, conflict_id), "pending");
}

#[test]
fn own_confirmation_and_reorg_reconcile_change_without_releasing_the_spent_input() {
    let mut f = fixture();
    deposit(&mut f, 100_000, 2, true);
    prepare(&mut f, Some(50_000), &external_address());
    let transaction = sign_prepared(&mut f, 2_000);
    let txid = transaction.compute_txid();
    f.engine
        .broadcast_result(json!({ "txid": txid, "status": "accepted" }), 2_001)
        .unwrap();
    let mut confirm = Update::default();
    confirm.chain = Some(
        f.engine
            .wallet
            .latest_checkpoint()
            .push(block(121, 121))
            .unwrap(),
    );
    confirm.tx_update.anchors.insert((
        ConfirmationBlockTime {
            block_id: block(121, 121),
            confirmation_time: 3_000,
        },
        txid,
    ));
    f.engine.apply_update(confirm, 3_000).unwrap();
    let confirmed = f.engine.snapshot(3_000).unwrap();
    assert_eq!(status(&confirmed, txid), "confirmed");
    assert_eq!(
        confirmed["balance"]["spendable_sats"],
        transaction.output[1].value.to_sat()
    );
    assert!(confirmed["outbox"].as_array().unwrap().is_empty());
    let mut reorg = Update::default();
    reorg.chain = Some(checkpoint(
        f.engine.binding.genesis_hash,
        &[block(1, 1), block(120, 120), block(121, 122)],
    ));
    reorg.tx_update.evicted_ats.insert((txid, 10_000));
    f.engine.apply_update(reorg, 10_000).unwrap();
    let pending = f.engine.snapshot(10_000).unwrap();
    assert_eq!(status(&pending, txid), "pending");
    assert_eq!(pending["balance"]["spendable_sats"], 0);
    assert_eq!(
        pending["balance"]["pending_sats"],
        transaction.output[1].value.to_sat()
    );
    assert_eq!(
        pending["outbox"][0]["transaction_hex"],
        hex::encode(serialize(&transaction))
    );
}

#[test]
fn rbf_preserves_self_payment_recipient_and_requires_fresh_signatures() {
    let mut f = fixture();
    deposit(&mut f, 100_000, 2, true);
    let recipient = f.engine.address.to_string();
    prepare(&mut f, Some(10_000), &recipient);
    let original = sign_prepared(&mut f, 2_000);
    let proposal = f.engine.bump(&app(&f.xpub), json!({
        "txid": original.compute_txid(), "fee_rate_sat_vb": 3, "nonce": hex::encode([30; 32]),
    }), 2_000).unwrap();
    let replacement = decode_psbt(proposal["psbt"].as_str().unwrap()).unwrap();
    assert_eq!(replacement.unsigned_tx.output[0], original.output[0]);
    assert!(replacement.unsigned_tx.output[1].value < original.output[1].value);
    assert!(f
        .engine
        .record_finalized(&hex::encode(serialize(&original)), 2_000)
        .is_err());
    let signed = sign_prepared(&mut f, 2_000);
    let snapshot = f.engine.snapshot(2_000).unwrap();
    assert_eq!(status(&snapshot, original.compute_txid()), "replaced");
    assert_eq!(status(&snapshot, signed.compute_txid()), "signed");
    assert_eq!(proposal["summary"]["recipient"], recipient);
    assert_eq!(proposal["summary"]["amount_sats"], 10_000);
}

#[test]
fn cached_replacement_is_not_superseded_by_its_unconfirmed_original() {
    let mut f = fixture();
    deposit(&mut f, 100_000, 2, true);
    prepare(&mut f, Some(50_000), &external_address());
    let original = sign_prepared(&mut f, 2_000);
    // Reopening without a cache discovers the original from the indexer.
    let mut clean = Engine::new(&app(&f.xpub), &f.public_key).unwrap();
    let mut chain = Update::default();
    chain.chain = Some(f.engine.wallet.latest_checkpoint());
    chain.tx_update = f.engine.wallet.tx_graph().clone().into();
    clean.apply_update(chain, 2_001).unwrap();
    f.engine = clean;
    f.engine.bump(&app(&f.xpub), json!({
        "txid": original.compute_txid(), "fee_rate_sat_vb": 3, "nonce": hex::encode([32; 32]),
    }), 3_000).unwrap();
    let replacement = sign_prepared(&mut f, 3_000);
    let mut restored = Engine::new(&app(&f.xpub), &f.public_key).unwrap();
    restored
        .import_state(json!({ "state": f.engine.export_state().unwrap() }), 4_000)
        .unwrap();

    let mut still_original = Update::default();
    still_original
        .tx_update
        .seen_ats
        .insert((original.compute_txid(), 5_000));
    still_original
        .tx_update
        .evicted_ats
        .insert((replacement.compute_txid(), 5_000));
    restored.apply_update(still_original, 5_000).unwrap();
    assert_eq!(
        status(
            &restored.snapshot(5_000).unwrap(),
            replacement.compute_txid()
        ),
        "signed"
    );

    // A mined original really does invalidate the cached replacement.
    let mut confirmed = Update::default();
    confirmed.chain = Some(
        restored
            .wallet
            .latest_checkpoint()
            .push(block(121, 121))
            .unwrap(),
    );
    confirmed.tx_update.anchors.insert((
        ConfirmationBlockTime {
            block_id: block(121, 121),
            confirmation_time: 6_000,
        },
        original.compute_txid(),
    ));
    restored.apply_update(confirmed, 6_000).unwrap();
    assert_eq!(
        status(
            &restored.snapshot(6_000).unwrap(),
            replacement.compute_txid()
        ),
        "replaced"
    );
}

#[test]
fn max_replacement_preserves_the_entire_payment_and_uses_only_confirmed_additional_coins() {
    let mut f = fixture();
    deposit(&mut f, 100_000, 2, true);
    let recipient = f.engine.address.to_string();
    prepare(&mut f, None, &recipient);
    let original = sign_prepared(&mut f, 2_000);
    assert_eq!(original.output.len(), 1);
    deposit(&mut f, 20_000, 3, false);
    let bump = json!({ "txid": original.compute_txid(), "fee_rate_sat_vb": 3, "nonce": hex::encode([31; 32]) });
    assert!(f.engine.bump(&app(&f.xpub), bump.clone(), 3_000).is_err());
    let additional = deposit(&mut f, 20_000, 4, true);
    let proposal = f.engine.bump(&app(&f.xpub), bump, 3_000).unwrap();
    let replacement = decode_psbt(proposal["psbt"].as_str().unwrap()).unwrap();
    assert_eq!(replacement.unsigned_tx.output[0], original.output[0]);
    assert!(replacement
        .unsigned_tx
        .input
        .iter()
        .any(|input| input.previous_output.txid == additional.compute_txid()));
    assert_eq!(replacement.unsigned_tx.input.len(), 2);
}

#[test]
fn reauthorization_keeps_reviewed_bytes_and_rejects_mutations_and_spent_funding() {
    let mut f = fixture();
    let funding = deposit(&mut f, 100_000, 2, true);
    let proposal = prepare(&mut f, Some(50_000), &external_address());
    let renewed = f
        .engine
        .reauthorize(
            &app(&f.xpub),
            json!({
                "psbt": proposal["psbt"], "nonce": hex::encode([40; 32]),
            }),
        )
        .unwrap();
    assert_eq!(renewed["psbt"], proposal["psbt"]);
    assert_eq!(renewed["summary"], proposal["summary"]);
    assert_ne!(renewed["challenges"], proposal["challenges"]);
    let mut modified = decode_psbt(proposal["psbt"].as_str().unwrap()).unwrap();
    modified.unsigned_tx.output[0].value += Amount::ONE_SAT;
    assert!(f
        .engine
        .assert_prepared(&STANDARD.encode(modified.serialize()))
        .is_err());
    let conflict = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), 0),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: Address::from_str(&external_address())
                .unwrap()
                .assume_checked()
                .script_pubkey(),
        }],
    };
    let mut update = Update::default();
    update
        .tx_update
        .seen_ats
        .insert((conflict.compute_txid(), 3_000));
    update.tx_update.txs.push(Arc::new(conflict));
    f.engine.apply_update(update, 3_000).unwrap();
    assert!(f
        .engine
        .reauthorize(
            &app(&f.xpub),
            json!({
                "psbt": proposal["psbt"], "nonce": hex::encode([41; 32]),
            })
        )
        .is_err());
}

#[test]
fn cache_rejects_another_context_corruption_and_live_state_rollback_atomically() {
    let mut f = fixture();
    deposit(&mut f, 100_000, 2, true);
    let state = f.engine.export_state().unwrap();
    let mut changed_app = app(&f.xpub);
    changed_app.origin = "http://localhost:8081";
    let mut other = Engine::new(&changed_app, &f.public_key).unwrap();
    assert!(other
        .import_state(json!({ "state": state }), 2_000)
        .is_err());
    assert_eq!(other.snapshot(2_000).unwrap()["balance"]["total_sats"], 0);
    let mut corruption = state.clone();
    corruption["payload"]["changeset"]["network"] = json!("bitcoin");
    let mut clean = Engine::new(&app(&f.xpub), &f.public_key).unwrap();
    assert!(clean
        .import_state(json!({ "state": corruption }), 2_000)
        .is_err());
    assert_eq!(clean.snapshot(2_000).unwrap()["balance"]["total_sats"], 0);
    clean
        .import_state(json!({ "state": state }), 2_000)
        .unwrap();
    assert_eq!(
        clean.snapshot(2_000).unwrap()["balance"]["confirmed_sats"],
        100_000
    );
    prepare(&mut f, Some(50_000), &external_address());
    let signed = sign_prepared(&mut f, 2_000);
    assert!(f
        .engine
        .import_state(json!({ "state": state }), 2_001)
        .is_err());
    assert_eq!(
        f.engine.snapshot(2_001).unwrap()["outbox"][0]["txid"],
        signed.compute_txid().to_string()
    );
}

#[test]
fn coinbase_maturity_and_input_cap_apply_without_a_discovery_limit() {
    let mut f = fixture();
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: f.engine.address.script_pubkey(),
        }],
    };
    let mut update = Update::default();
    update.chain = Some(checkpoint(
        f.engine.binding.genesis_hash,
        &[block(1, 1), block(99, 99)],
    ));
    update.tx_update.txs.push(Arc::new(coinbase.clone()));
    update.tx_update.anchors.insert((
        ConfirmationBlockTime {
            block_id: block(1, 1),
            confirmation_time: 1_000,
        },
        coinbase.compute_txid(),
    ));
    f.engine.apply_update(update, 2_000).unwrap();
    let body = json!({ "recipient": external_address(), "amount_sats": 50_000, "fee_rate_sat_vb": 1, "nonce": hex::encode([50; 32]) });
    assert!(f
        .engine
        .prepare(&app(&f.xpub), body.clone(), 2_000)
        .is_err());
    assert_eq!(
        f.engine.snapshot(2_000).unwrap()["balance"]["immature_sats"],
        100_000
    );
    let mut mature = Update::default();
    mature.chain = Some(
        f.engine
            .wallet
            .latest_checkpoint()
            .push(block(100, 100))
            .unwrap(),
    );
    f.engine.apply_update(mature, 3_000).unwrap();
    assert_eq!(
        f.engine.prepare(&app(&f.xpub), body, 3_000).unwrap()["summary"]["amount_sats"],
        50_000
    );

    let mut fragmented = fixture();
    for tag in 2..=70 {
        deposit(&mut fragmented, 1_000, tag, true);
    }
    assert_eq!(
        fragmented.engine.snapshot(2_000).unwrap()["balance"]["spendable_sats"],
        69_000
    );
    assert!(fragmented
        .engine
        .prepare(
            &app(&fragmented.xpub),
            json!({
                "recipient": external_address(), "amount_sats": null, "fee_rate_sat_vb": 1,
                "nonce": hex::encode([51; 32]),
            }),
            2_000
        )
        .is_err());
    let small = prepare(&mut fragmented, Some(10_000), &external_address());
    assert_eq!(small["summary"]["amount_sats"], 10_000);
    assert!(small["summary"]["input_count"].as_u64().unwrap() <= 16);
}
