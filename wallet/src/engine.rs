//! Fixed-descriptor, public-only BDK wallet and locally authorized transaction journal.

use crate::{authorization, context::Wallet, contract};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bdk_wallet::{
    chain::{CanonicalizationParams, ChainPosition, ConfirmationBlockTime, Merge},
    coin_selection::LargestFirstCoinSelection,
    ChangeSet, KeychainKind, TxOrdering, Update,
};
use bitcoin::{
    absolute::LockTime,
    bip32::Xpub,
    consensus::{deserialize, serialize},
    hashes::Hash,
    key::TapTweak,
    psbt::Psbt,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    Address, Amount, BlockHash, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, Txid,
    Witness,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};

const MAX_INPUTS: usize = 16;
const MAX_MONEY: u64 = 2_100_000_000_000_000;
const MAX_PSBT_BYTES: usize = 64 * 1024;

type Positions = BTreeMap<Txid, ChainPosition<ConfirmationBlockTime>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    root: Xpub,
    network: Network,
    genesis_hash: BlockHash,
    origin: String,
    rp_id: String,
    local_dev: bool,
    public_key: String,
    program_id: String,
    module_sha256: String,
    descriptor: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BroadcastState {
    Signed,
    Accepted,
    Uncertain,
}

#[derive(Clone)]
struct Outgoing {
    transaction: Arc<Transaction>,
    state: BroadcastState,
    replaces: Option<Txid>,
    fee_sats: u64,
    created_at: u64,
    dismissed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedOutgoing {
    txid: Txid,
    transaction_hex: String,
    state: BroadcastState,
    replaces: Option<Txid>,
    fee_sats: u64,
    created_at: u64,
    dismissed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachePayload {
    binding: Binding,
    changeset: ChangeSet,
    outgoing: Vec<CachedOutgoing>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEnvelope {
    version: u32,
    payload: CachePayload,
    checksum: String,
}

struct Prepared {
    psbt: Psbt,
    summary: Value,
    replaces: Option<Txid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareInput {
    recipient: String,
    amount_sats: Option<u64>,
    fee_rate_sat_vb: u64,
    nonce: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BumpInput {
    txid: Txid,
    fee_rate_sat_vb: u64,
    nonce: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthorizeInput {
    psbt: String,
    nonce: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BroadcastInput {
    txid: Txid,
    status: BroadcastState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TxidInput {
    txid: Txid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportInput {
    state: Value,
}

pub(crate) struct Engine {
    wallet: bdk_wallet::Wallet,
    binding: Binding,
    internal_key: XOnlyPublicKey,
    address: Address,
    changeset: ChangeSet,
    outgoing: BTreeMap<Txid, Outgoing>,
    prepared: Option<Prepared>,
    synced: bool,
}

impl Engine {
    pub(crate) fn new(app: &Wallet<'_>, public_key: &str) -> Result<Self> {
        ensure!(
            public_key.len() == 66,
            "expected a compressed 33-byte public key"
        );
        let public_key = hex::decode(public_key).context("invalid public key hex")?;
        let instance = contract::instance(app.network, app.rp_id, app.origin, &public_key)?;
        let internal_key = contract::derive_public_key(&instance, app.root)?;
        let descriptor = format!("tr({internal_key})");
        let mut wallet = bdk_wallet::Wallet::create_single(descriptor.clone())
            .network(app.network)
            .create_wallet_no_persist()?;
        let address = wallet.reveal_next_address(KeychainKind::External).address;
        ensure!(
            address == contract::address(&instance, app.root, app.network)?,
            "descriptor address mismatch"
        );
        let binding = Binding {
            root: *app.root,
            network: app.network,
            genesis_hash: bitcoin::blockdata::constants::genesis_block(app.network).block_hash(),
            origin: app.origin.to_owned(),
            rp_id: app.rp_id.to_owned(),
            local_dev: app.local_dev,
            public_key: hex::encode(public_key),
            program_id: instance.id().0.to_string(),
            module_sha256: hex::encode(contract::hash(contract::WASM)),
            descriptor,
        };
        let changeset = wallet
            .take_staged()
            .context("new wallet has no changeset")?;
        Ok(Self {
            wallet,
            binding,
            internal_key,
            address,
            changeset,
            outgoing: BTreeMap::new(),
            prepared: None,
            synced: false,
        })
    }

    pub(crate) fn public_key(&self) -> &str {
        &self.binding.public_key
    }

    pub(crate) fn bdk(&self) -> &bdk_wallet::Wallet {
        &self.wallet
    }

    fn app(&self) -> Wallet<'_> {
        Wallet {
            root: &self.binding.root,
            network: self.binding.network,
            local_dev: self.binding.local_dev,
            origin: &self.binding.origin,
            rp_id: &self.binding.rp_id,
        }
    }

    fn stage(&mut self) {
        if let Some(changeset) = self.wallet.take_staged() {
            self.changeset.merge(changeset);
        }
    }

    fn positions(&self) -> Positions {
        self.wallet
            .tx_graph()
            .list_canonical_txs(
                self.wallet.local_chain(),
                self.wallet.latest_checkpoint().block_id(),
                CanonicalizationParams::default(),
            )
            .map(|tx| (tx.tx_node.txid, tx.chain_position))
            .collect()
    }

    /// A replacement of an ancestor invalidates its children as well. Only a
    /// best-chain confirmation is sufficient to release a local reservation.
    fn conflict(
        &self,
        tx: &Transaction,
        positions: &Positions,
        confirmed_only: bool,
    ) -> Option<Txid> {
        let graph = self.wallet.tx_graph();
        let txid = tx.compute_txid();
        let replaces = self
            .outgoing
            .get(&txid)
            .and_then(|outgoing| outgoing.replaces);
        let mut visit = vec![txid];
        let mut visited = BTreeSet::new();
        while let Some(txid) = visit.pop() {
            if !visited.insert(txid) {
                continue;
            }
            let Some(node) = graph.get_tx(txid) else {
                continue;
            };
            for input in &node.input {
                let mut conflicts: Vec<_> = graph
                    .outspends(input.previous_output)
                    .iter()
                    .filter(|other| **other != txid)
                    .filter_map(|other| positions.get(other).map(|pos| (*other, pos)))
                    .filter(|(_, pos)| !confirmed_only || pos.is_confirmed())
                    // Observing an RBF original in the mempool does not
                    // supersede its signed replacement. Its confirmation does.
                    .filter(|(other, pos)| Some(*other) != replaces || pos.is_confirmed())
                    .collect();
                // Prefer confirmed evidence and then deterministic txid ordering.
                conflicts.sort_by_key(|(id, pos)| (!pos.is_confirmed(), *id));
                if let Some((other, _)) = conflicts.first() {
                    return Some(*other);
                }
                if !input.previous_output.is_null() {
                    visit.push(input.previous_output.txid);
                }
            }
        }
        None
    }

    fn settled(&self, txid: Txid, outgoing: &Outgoing, positions: &Positions) -> bool {
        positions
            .get(&txid)
            .is_some_and(ChainPosition::is_confirmed)
            || self
                .conflict(&outgoing.transaction, positions, true)
                .is_some()
    }

    fn replacement_family(&self, replaces: Option<Txid>) -> BTreeSet<Txid> {
        let mut family = BTreeSet::new();
        let mut cursor = replaces;
        while let Some(txid) = cursor {
            if !family.insert(txid) {
                break;
            }
            cursor = self.outgoing.get(&txid).and_then(|tx| tx.replaces);
        }
        family
    }

    fn reservations(&self, positions: &Positions, except: &BTreeSet<Txid>) -> BTreeSet<OutPoint> {
        self.outgoing
            .iter()
            .filter(|(id, outgoing)| {
                !except.contains(*id) && !self.settled(**id, outgoing, positions)
            })
            .flat_map(|(_, outgoing)| {
                outgoing
                    .transaction
                    .input
                    .iter()
                    .map(|input| input.previous_output)
            })
            .collect()
    }

    fn mature_confirmed(&self, outpoint: OutPoint, positions: &Positions) -> bool {
        let Some(ChainPosition::Confirmed { anchor, .. }) = positions.get(&outpoint.txid) else {
            return false;
        };
        let tip = self.wallet.latest_checkpoint().height();
        if anchor.block_id.height > tip {
            return false;
        }
        let Some(parent) = self.wallet.tx_graph().get_tx(outpoint.txid) else {
            return false;
        };
        !parent.is_coinbase()
            || tip - anchor.block_id.height + 1 >= bitcoin::constants::COINBASE_MATURITY
    }

    fn unspendable(&self, replaces: Option<Txid>) -> Vec<OutPoint> {
        let positions = self.positions();
        let mut excluded = self.reservations(&positions, &self.replacement_family(replaces));
        excluded.extend(
            self.wallet
                .list_unspent()
                .filter(|coin| !self.mature_confirmed(coin.outpoint, &positions))
                .map(|coin| coin.outpoint),
        );
        excluded.into_iter().collect()
    }

    /// Recheck the reviewed transaction without selecting different coins. In
    /// particular, a refresh during an approval cannot silently reuse inputs.
    fn check_funding(&self, psbt: &Psbt, replaces: Option<Txid>) -> Result<()> {
        ensure!(
            self.synced,
            "refresh the wallet before authorizing a payment"
        );
        let positions = self.positions();
        let family = self.replacement_family(replaces);
        if let Some(txid) = replaces {
            ensure!(
                positions
                    .get(&txid)
                    .is_some_and(ChainPosition::is_unconfirmed),
                "replacement target is no longer pending"
            );
        }
        let reserved = self.reservations(&positions, &family);
        for (input, metadata) in psbt.unsigned_tx.input.iter().zip(&psbt.inputs) {
            let outpoint = input.previous_output;
            ensure!(
                self.mature_confirmed(outpoint, &positions),
                "funding is no longer confirmed and mature; refresh and prepare again"
            );
            ensure!(
                !reserved.contains(&outpoint),
                "funding is reserved by another signed transaction"
            );
            ensure!(
                self.wallet.tx_graph().get_txout(outpoint) == metadata.witness_utxo.as_ref(),
                "funding prevout changed"
            );
            ensure!(
                self.wallet
                    .tx_graph()
                    .outspends(outpoint)
                    .iter()
                    .all(|spender| {
                        !positions.contains_key(spender) || family.contains(spender)
                    }),
                "funding has been spent by another transaction; refresh and prepare again"
            );
        }
        Ok(())
    }

    pub(crate) fn prepare(&mut self, app: &Wallet<'_>, body: Value, _now: u64) -> Result<Value> {
        ensure!(
            body.get("amount_sats").is_some(),
            "amount_sats is required; use explicit null for send MAX"
        );
        let input: PrepareInput = serde_json::from_value(body)?;
        let rate = fee_rate(input.fee_rate_sat_vb)?;
        ensure!(self.synced, "refresh the wallet before preparing a payment");
        let recipient =
            Address::from_str(&input.recipient)?.require_network(self.binding.network)?;
        let script = recipient.script_pubkey();
        ensure!(
            standard_script(&script),
            "recipient must use a standard Bitcoin address"
        );
        if let Some(amount) = input.amount_sats {
            ensure!(
                (1..=MAX_MONEY).contains(&amount),
                "amount must be positive satoshis within MAX_MONEY"
            );
            ensure!(
                Amount::from_sat(amount) >= script.minimal_non_dust(),
                "recipient output is below its dust threshold"
            );
        }
        let rich = self
            .build_payment(&script, input.amount_sats.map(Amount::from_sat), rate, None)
            .context("cannot fund payment from confirmed coins")?;
        self.review(app, rich, input.fee_rate_sat_vb, &input.nonce, None)
    }

    pub(crate) fn bump(&mut self, app: &Wallet<'_>, body: Value, _now: u64) -> Result<Value> {
        let input: BumpInput = serde_json::from_value(body)?;
        let rate = fee_rate(input.fee_rate_sat_vb)?;
        ensure!(self.synced, "refresh the wallet before replacing a payment");
        let previous = self
            .wallet
            .get_tx(input.txid)
            .context("unknown or replaced outgoing transaction")?;
        ensure!(
            previous.chain_position.is_unconfirmed(),
            "confirmed transactions cannot be replaced"
        );
        let original = self.psbt_for(&previous.tx_node.tx)?;
        let original = authorization::canonical_psbt(app, self.public_key(), &original)?;
        self.check_funding(&original, Some(input.txid))?;
        let recipient = original.unsigned_tx.output[0].clone();
        let original_fee = self.wallet.calculate_fee(&previous.tx_node.tx)?.to_sat();
        let rich = self.build_payment(&recipient.script_pubkey, Some(recipient.value), rate, Some(input.txid))
            .context("cannot increase fee while preserving the recipient; insufficient change or confirmed additional funds, or fee rate too low")?;
        let replacement_fee = self.wallet.calculate_fee(&rich.unsigned_tx)?.to_sat();
        ensure!(replacement_fee >= original_fee.checked_add(signed_vsize(&rich.unsigned_tx)).context("replacement fee overflow")?,
            "replacement must increase the absolute fee by at least the incremental relay fee; choose a higher fee rate");
        self.review(
            app,
            rich,
            input.fee_rate_sat_vb,
            &input.nonce,
            Some(input.txid),
        )
    }

    fn build_payment(
        &mut self,
        recipient: &ScriptBuf,
        amount: Option<Amount>,
        rate: FeeRate,
        replaces: Option<Txid>,
    ) -> Result<Psbt> {
        let excluded = self.unspendable(replaces);
        let mut absolute_fee = None;
        // BDK calculates rates per weight unit. Our displayed sat/vB rate uses
        // Bitcoin Core's rounded virtual size, which can require a few more
        // satoshis. Rebuild through BDK rather than editing change by hand.
        // Each increase can add funding inputs; stop at the authorization cap.
        for _ in 0..MAX_INPUTS + 2 {
            let mut builder = match replaces {
                Some(txid) => self.wallet.build_fee_bump(txid)?,
                None => self.wallet.build_tx(),
            }
            .coin_selection(LargestFirstCoinSelection);
            builder
                .fee_rate(rate)
                .version(2)
                .nlocktime(LockTime::ZERO)
                .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME)
                .sighash(TapSighashType::All.into())
                .ordering(TxOrdering::Untouched)
                .only_witness_utxo()
                .unspendable(excluded.clone())
                .exclude_unconfirmed();
            if let Some(fee) = absolute_fee {
                builder.fee_absolute(fee);
            }
            match amount {
                Some(amount) => {
                    // Restore the exact recipient even for an owned script;
                    // BDK's change heuristic otherwise removes self-payments.
                    builder
                        .set_recipients(vec![(recipient.clone(), amount)])
                        .drain_to(self.address.script_pubkey());
                }
                None => {
                    builder.drain_wallet().drain_to(recipient.clone());
                }
            }
            let rich = builder.finish()?;
            self.stage();
            ensure!(
                (1..=MAX_INPUTS).contains(&rich.inputs.len()),
                "payment needs more than the 16-input authorization limit; use a smaller payment"
            );
            let minimum = rate
                .fee_vb(signed_vsize(&rich.unsigned_tx))
                .context("fee overflow")?;
            if self.wallet.calculate_fee(&rich.unsigned_tx)? >= minimum {
                return Ok(rich);
            }
            absolute_fee = Some(minimum);
        }
        anyhow::bail!("fee construction did not converge within the input limit")
    }

    fn review(
        &mut self,
        app: &Wallet<'_>,
        rich: Psbt,
        rate: u64,
        nonce: &str,
        replaces: Option<Txid>,
    ) -> Result<Value> {
        ensure!(
            (1..=MAX_INPUTS).contains(&rich.inputs.len()),
            "payment needs more than the 16-input authorization limit; use a smaller payment"
        );
        let psbt = authorization::canonical_psbt(app, self.public_key(), &rich)?;
        self.check_funding(&psbt, replaces)?;
        let tx = &psbt.unsigned_tx;
        let fee = self.wallet.calculate_fee(tx)?.to_sat();
        let vsize = signed_vsize(tx);
        ensure!(
            fee >= rate.checked_mul(vsize).context("fee overflow")?,
            "constructed fee is below the requested virtual-byte rate"
        );
        let recipient = Address::from_script(&tx.output[0].script_pubkey, self.binding.network)?;
        let funding: Vec<_> = tx.input.iter().zip(&psbt.inputs).map(|(input, metadata)| json!({
            "txid": input.previous_output.txid, "vout": input.previous_output.vout,
            "value_sats": metadata.witness_utxo.as_ref().expect("canonical prevout").value.to_sat(),
        })).collect();
        let summary = json!({
            "funding": funding, "recipient": recipient.to_string(), "amount_sats": tx.output[0].value.to_sat(),
            "fee_sats": fee, "fee_rate_sat_vb": rate, "vsize": vsize,
            "change_sats": tx.output.get(1).map_or(0, |output| output.value.to_sat()),
            "change_address": self.address.to_string(), "txid": tx.compute_txid(),
            "network": self.binding.network, "input_count": tx.input.len(), "replaces": replaces,
        });
        let proposal =
            authorization::proposal(app, self.public_key(), &psbt, summary.clone(), nonce)?;
        self.prepared = Some(Prepared {
            psbt,
            summary,
            replaces,
        });
        Ok(proposal)
    }

    pub(crate) fn assert_prepared(&self, psbt_base64: &str) -> Result<()> {
        let prepared = self
            .prepared
            .as_ref()
            .context("no active reviewed proposal")?;
        ensure!(
            decode_psbt(psbt_base64)? == prepared.psbt,
            "PSBT differs from the active reviewed proposal"
        );
        self.check_funding(&prepared.psbt, prepared.replaces)
    }

    pub(crate) fn reauthorize(&self, app: &Wallet<'_>, body: Value) -> Result<Value> {
        let input: ReauthorizeInput = serde_json::from_value(body)?;
        self.assert_prepared(&input.psbt)?;
        let prepared = self
            .prepared
            .as_ref()
            .context("no active reviewed proposal")?;
        authorization::proposal(
            app,
            self.public_key(),
            &prepared.psbt,
            prepared.summary.clone(),
            &input.nonce,
        )
    }

    fn psbt_for(&self, transaction: &Transaction) -> Result<Psbt> {
        let mut unsigned = transaction.clone();
        for input in &mut unsigned.input {
            input.witness = Witness::new();
        }
        let mut psbt = Psbt::from_unsigned_tx(unsigned)?;
        for (input, metadata) in transaction.input.iter().zip(&mut psbt.inputs) {
            metadata.witness_utxo = Some(
                self.wallet
                    .tx_graph()
                    .get_txout(input.previous_output)
                    .context("missing original funding transaction")?
                    .clone(),
            );
            metadata.tap_internal_key = Some(self.internal_key);
            metadata.sighash_type = Some(TapSighashType::All.into());
        }
        Ok(psbt)
    }

    fn verify_signed(&self, transaction: &Transaction, psbt: &Psbt) -> Result<()> {
        let mut unsigned = transaction.clone();
        for input in &mut unsigned.input {
            input.witness = Witness::new();
        }
        ensure!(
            unsigned == psbt.unsigned_tx,
            "signed transaction differs from reviewed transaction"
        );
        let secp = Secp256k1::verification_only();
        let output_key = self
            .internal_key
            .tap_tweak(&secp, None)
            .0
            .to_x_only_public_key();
        let prevouts: Vec<_> = psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .as_ref()
                    .context("missing funding prevout")
            })
            .collect::<Result<_>>()?;
        let mut sighashes = SighashCache::new(&psbt.unsigned_tx);
        for (index, input) in transaction.input.iter().enumerate() {
            ensure!(
                input.witness.len() == 1,
                "expected exactly one key-path signature"
            );
            let bytes = input.witness.iter().next().context("missing signature")?;
            ensure!(
                bytes.len() == 65 && bytes[64] == TapSighashType::All as u8,
                "expected explicit SIGHASH_ALL signature"
            );
            let signature = bitcoin::taproot::Signature::from_slice(bytes)?;
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
            .context("invalid signed outgoing transaction")?;
        }
        Ok(())
    }

    pub(crate) fn record_finalized(&mut self, transaction_hex: &str, now: u64) -> Result<()> {
        let transaction = decode_transaction(transaction_hex)?;
        let txid = transaction.compute_txid();
        let prepared = self
            .prepared
            .as_ref()
            .context("no active reviewed proposal")?;
        self.check_funding(&prepared.psbt, prepared.replaces)?;
        self.verify_signed(&transaction, &prepared.psbt)?;
        let fee_sats = self.wallet.calculate_fee(&transaction)?.to_sat();
        ensure!(
            self.outgoing.get(&txid).is_none(),
            "transaction has already been finalized"
        );
        let outgoing = Outgoing {
            transaction: Arc::new(transaction),
            state: BroadcastState::Signed,
            replaces: prepared.replaces,
            fee_sats,
            created_at: now,
            dismissed: false,
        };
        let seen_at = outgoing
            .transaction
            .input
            .iter()
            .flat_map(|input| self.wallet.tx_graph().outspends(input.previous_output))
            .filter_map(|txid| self.wallet.tx_graph().get_tx_node(*txid)?.last_seen)
            .chain(self.wallet.tx_graph().get_last_evicted(txid))
            .max()
            .map_or(now, |seen| now.max(seen.saturating_add(1)));
        self.wallet
            .apply_unconfirmed_txs([(outgoing.transaction.clone(), seen_at)]);
        self.outgoing.insert(txid, outgoing);
        self.prepared = None;
        self.stage();
        Ok(())
    }

    pub(crate) fn broadcast_result(&mut self, body: Value, now: u64) -> Result<Value> {
        let input: BroadcastInput = serde_json::from_value(body)?;
        ensure!(
            input.status != BroadcastState::Signed,
            "broadcast status must be accepted or uncertain"
        );
        let outgoing = self
            .outgoing
            .get_mut(&input.txid)
            .context("unknown locally signed transaction")?;
        // A later inconclusive retry does not undo an earlier definite acceptance.
        if outgoing.state != BroadcastState::Accepted {
            outgoing.state = input.status;
        }
        outgoing.dismissed = false;
        self.snapshot(now)
    }

    pub(crate) fn discard_result(&mut self, body: Value, now: u64) -> Result<Value> {
        let input: TxidInput = serde_json::from_value(body)?;
        self.outgoing
            .get_mut(&input.txid)
            .context("unknown locally signed transaction")?
            .dismissed = true;
        // Dismissing a result cannot cancel a broadcast. The signed bytes and
        // reservation deliberately remain in memory and the optional cache.
        self.snapshot(now)
    }

    pub(crate) fn apply_update(&mut self, mut update: Update, _now: u64) -> Result<()> {
        // A missing mempool response is not evidence that our signed transaction
        // cannot still propagate. BDK anchors/conflicts, not timeouts, settle it.
        update
            .tx_update
            .evicted_ats
            .retain(|(txid, _)| !self.outgoing.contains_key(txid));
        self.wallet.apply_update(update)?;
        self.stage();
        self.synced = true;
        Ok(())
    }

    pub(crate) fn snapshot(&self, _now: u64) -> Result<Value> {
        let positions = self.positions();
        let reserved = self.reservations(&positions, &BTreeSet::new());
        let balance = self.wallet.balance();
        let spendable: u64 = self
            .wallet
            .list_unspent()
            .filter(|coin| {
                self.mature_confirmed(coin.outpoint, &positions)
                    && !reserved.contains(&coin.outpoint)
            })
            .map(|coin| coin.txout.value.to_sat())
            .sum();
        let tip = self.wallet.latest_checkpoint();
        let mut history = Vec::new();
        for node in self.wallet.tx_graph().full_txs() {
            let (sent, received) = self.wallet.sent_and_received(&node.tx);
            let local = self.outgoing.get(&node.txid);
            if sent == Amount::ZERO && received == Amount::ZERO && local.is_none() {
                continue;
            }
            let position = positions.get(&node.txid);
            let replaced_by = if position.is_some_and(ChainPosition::is_confirmed) {
                None
            } else {
                self.conflict(&node.tx, &positions, false)
            };
            // Ignore irrelevant, never-canonical graph fragments, but retain
            // evicted/replaced wallet history and every locally signed result.
            let (block_height, timestamp, confirmations) = match position {
                Some(ChainPosition::Confirmed { anchor, .. }) => (
                    Some(anchor.block_id.height),
                    Some(anchor.confirmation_time),
                    tip.height().saturating_sub(anchor.block_id.height) + 1,
                ),
                _ => (None, local.map(|tx| tx.created_at).or(node.last_seen), 0),
            };
            let status = if block_height.is_some() {
                "confirmed"
            } else if replaced_by.is_some() {
                "replaced"
            } else {
                match local.map(|tx| tx.state) {
                    Some(BroadcastState::Signed) => "signed",
                    Some(BroadcastState::Uncertain) => "uncertain",
                    Some(BroadcastState::Accepted) => "pending",
                    None if position.is_some() => "pending",
                    None => "uncertain",
                }
            };
            let outgoing = sent > Amount::ZERO;
            let can_bump = outgoing
                && position.is_some_and(ChainPosition::is_unconfirmed)
                && replaced_by.is_none()
                && self.bumpable_shape(&node.tx);
            let row = json!({
                "txid": node.txid, "received_sats": received.to_sat(), "sent_sats": sent.to_sat(),
                "fee_sats": self.wallet.calculate_fee(&node.tx).ok().map(|fee| fee.to_sat()),
                "status": status, "confirmations": confirmations, "block_height": block_height,
                "timestamp": timestamp, "outgoing": outgoing, "can_bump": can_bump, "replaced_by": replaced_by,
            });
            history.push((
                block_height.is_some(),
                timestamp.unwrap_or(0),
                node.txid,
                row,
            ));
        }
        history.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.cmp(&b.2))
        });
        let mut outbox: Vec<_> = self.outgoing.iter()
            .filter(|(txid, outgoing)| !outgoing.dismissed && !self.settled(**txid, outgoing, &positions))
            .map(|(txid, outgoing)| json!({
                "txid": txid, "transaction_hex": hex::encode(serialize(outgoing.transaction.as_ref())),
                "state": outgoing.state, "replaces": outgoing.replaces, "fee_sats": outgoing.fee_sats,
                "created_at": outgoing.created_at,
            })).collect();
        outbox.sort_by(|a, b| {
            b["created_at"]
                .as_u64()
                .cmp(&a["created_at"].as_u64())
                .then_with(|| a["txid"].as_str().cmp(&b["txid"].as_str()))
        });
        Ok(json!({
            "address": self.address.to_string(), "chain_tip": { "height": tip.height(), "hash": tip.hash() },
            "synced": self.synced,
            "balance": {
                "confirmed_sats": balance.confirmed.to_sat(),
                "pending_sats": (balance.trusted_pending + balance.untrusted_pending).to_sat(),
                "immature_sats": balance.immature.to_sat(), "total_sats": balance.total().to_sat(),
                "spendable_sats": spendable,
            },
            "transactions": history.into_iter().map(|(_, _, _, row)| row).collect::<Vec<_>>(), "outbox": outbox,
        }))
    }

    fn bumpable_shape(&self, transaction: &Transaction) -> bool {
        self.psbt_for(transaction)
            .and_then(|psbt| authorization::canonical_psbt(&self.app(), self.public_key(), &psbt))
            .is_ok()
    }

    pub(crate) fn export_state(&self) -> Result<Value> {
        let mut changeset = self.changeset.clone();
        if let Some(staged) = self.wallet.staged() {
            changeset.merge(staged.clone());
        }
        let payload = CachePayload {
            binding: self.binding.clone(),
            changeset,
            outgoing: self
                .outgoing
                .iter()
                .map(|(txid, outgoing)| CachedOutgoing {
                    txid: *txid,
                    transaction_hex: hex::encode(serialize(outgoing.transaction.as_ref())),
                    state: outgoing.state,
                    replaces: outgoing.replaces,
                    fee_sats: outgoing.fee_sats,
                    created_at: outgoing.created_at,
                    dismissed: outgoing.dismissed,
                })
                .collect(),
        };
        let checksum = cache_checksum(&payload)?;
        Ok(serde_json::to_value(CacheEnvelope {
            version: 1,
            payload,
            checksum,
        })?)
    }

    pub(crate) fn import_state(&mut self, body: Value, now: u64) -> Result<Value> {
        let input: ImportInput = serde_json::from_value(body)?;
        let envelope: CacheEnvelope =
            serde_json::from_value(input.state.clone()).context("invalid public cache schema")?;
        // Reject unknown fields in the BDK payload too; BDK's own Deserialize
        // intentionally accepts them for database compatibility.
        ensure!(
            serde_json::to_value(&envelope)? == input.state,
            "noncanonical or unsupported public cache fields"
        );
        ensure!(envelope.version == 1, "unsupported public cache version");
        ensure!(
            envelope.payload.binding == self.binding,
            "public cache belongs to a different wallet context"
        );
        ensure!(
            cache_checksum(&envelope.payload)? == envelope.checksum,
            "public cache checksum mismatch"
        );
        let payload = envelope.payload;
        validate_changeset(&payload.changeset)?;
        let wallet = bdk_wallet::Wallet::load()
            .descriptor(
                KeychainKind::External,
                Some(self.binding.descriptor.clone()),
            )
            .descriptor(KeychainKind::Internal, None::<String>)
            .check_network(self.binding.network)
            .check_genesis_hash(self.binding.genesis_hash)
            .load_wallet_no_persist(payload.changeset.clone())?
            .context("empty public cache")?;
        ensure!(
            wallet.peek_address(KeychainKind::External, 0).address == self.address,
            "cached wallet address mismatch"
        );
        let expected_indexer = &self.changeset.indexer;
        ensure!(
            payload.changeset.indexer == *expected_indexer,
            "invalid fixed-descriptor cache index"
        );
        ensure!(
            payload.changeset.locked_outpoints.outpoints.is_empty(),
            "unexpected cached coin locks"
        );
        let mut candidate = Self {
            wallet,
            binding: self.binding.clone(),
            internal_key: self.internal_key,
            address: self.address.clone(),
            changeset: payload.changeset,
            outgoing: BTreeMap::new(),
            prepared: None,
            synced: false,
        };
        for cached in payload.outgoing {
            ensure!(
                !candidate.outgoing.contains_key(&cached.txid),
                "duplicate cached outgoing transaction"
            );
            let transaction = decode_transaction(&cached.transaction_hex)?;
            ensure!(
                transaction.compute_txid() == cached.txid,
                "cached transaction ID mismatch"
            );
            ensure!(
                candidate.wallet.tx_graph().get_tx(cached.txid).as_deref() == Some(&transaction),
                "cached outgoing transaction missing from BDK graph"
            );
            let psbt = candidate.psbt_for(&transaction)?;
            let psbt =
                authorization::canonical_psbt(&candidate.app(), candidate.public_key(), &psbt)?;
            candidate.verify_signed(&transaction, &psbt)?;
            ensure!(
                candidate.wallet.calculate_fee(&transaction)?.to_sat() == cached.fee_sats,
                "cached outgoing fee mismatch"
            );
            ensure!(
                candidate
                    .changeset
                    .tx_graph
                    .last_seen
                    .get(&cached.txid)
                    .is_some_and(|seen| {
                        candidate
                            .changeset
                            .tx_graph
                            .last_evicted
                            .get(&cached.txid)
                            .is_none_or(|evicted| evicted < seen)
                    }),
                "invalid cached outgoing observation"
            );
            candidate.outgoing.insert(
                cached.txid,
                Outgoing {
                    transaction: Arc::new(transaction),
                    state: cached.state,
                    replaces: cached.replaces,
                    fee_sats: cached.fee_sats,
                    created_at: cached.created_at,
                    dismissed: cached.dismissed,
                },
            );
        }
        for (txid, outgoing) in &candidate.outgoing {
            if let Some(replaces) = outgoing.replaces {
                ensure!(replaces != *txid, "transaction cannot replace itself");
                let previous = candidate
                    .wallet
                    .tx_graph()
                    .get_tx(replaces)
                    .context("missing replacement predecessor")?;
                ensure!(
                    previous.output.first() == outgoing.transaction.output.first(),
                    "cached replacement changed the recipient"
                );
                ensure!(
                    outgoing.transaction.input.iter().any(|input| previous
                        .input
                        .iter()
                        .any(|old| old.previous_output == input.previous_output)),
                    "replacement does not conflict with predecessor"
                );
                ensure!(
                    candidate.wallet.calculate_fee(&previous)?.to_sat() < outgoing.fee_sats,
                    "replacement did not increase fee"
                );
            }
        }
        // Do not permit an imported snapshot to forget a live signed result.
        // Loading is only a bootstrap optimization, never a rollback operation.
        ensure!(
            self.outgoing.is_empty() && self.prepared.is_none() && !self.synced,
            "public cache can only be imported before this session's first sync or payment"
        );
        let snapshot = candidate.snapshot(now)?;
        *self = candidate;
        Ok(snapshot)
    }
}

fn standard_script(script: &ScriptBuf) -> bool {
    script.is_p2pkh()
        || script.is_p2sh()
        || script.is_p2wpkh()
        || script.is_p2wsh()
        || script.is_p2tr()
}

fn fee_rate(rate: u64) -> Result<FeeRate> {
    ensure!(
        (1..=1000).contains(&rate),
        "fee rate must be an integer from 1 to 1000 sat/vB"
    );
    FeeRate::from_sat_per_vb(rate).context("invalid fee rate")
}

fn signed_vsize(transaction: &Transaction) -> u64 {
    // Ask Bitcoin's serializer for the exact weight; no parallel weight formula.
    let mut signed = transaction.clone();
    for input in &mut signed.input {
        input.witness = Witness::from_slice(&[[0u8; 65]]);
    }
    signed.vsize() as u64
}

fn decode_psbt(encoded: &str) -> Result<Psbt> {
    ensure!(
        encoded.len() <= MAX_PSBT_BYTES.div_ceil(3) * 4,
        "PSBT exceeds byte limit"
    );
    let bytes = STANDARD.decode(encoded).context("invalid PSBT base64")?;
    ensure!(bytes.len() <= MAX_PSBT_BYTES, "PSBT exceeds byte limit");
    Ok(Psbt::deserialize(&bytes)?)
}

fn decode_transaction(encoded: &str) -> Result<Transaction> {
    ensure!(
        encoded.len() <= MAX_PSBT_BYTES * 2,
        "outgoing transaction exceeds byte limit"
    );
    let bytes = hex::decode(encoded).context("invalid transaction hex")?;
    let transaction: Transaction = deserialize(&bytes)?;
    ensure!(
        serialize(&transaction) == bytes,
        "noncanonical transaction encoding"
    );
    Ok(transaction)
}

fn cache_checksum(payload: &CachePayload) -> Result<String> {
    // Integrity against partial/corrupt storage, not authentication of the indexer.
    Ok(hex::encode(contract::hash(&serde_json::to_vec(payload)?)))
}

fn validate_changeset(changeset: &ChangeSet) -> Result<()> {
    let mut txids = BTreeSet::new();
    for transaction in &changeset.tx_graph.txs {
        let txid = transaction.compute_txid();
        ensure!(
            txids.insert(txid),
            "conflicting cached transaction witnesses"
        );
        ensure!(
            !transaction.input.is_empty() && !transaction.output.is_empty(),
            "invalid cached transaction"
        );
        let mut inputs = BTreeSet::new();
        ensure!(
            transaction
                .input
                .iter()
                .all(|input| inputs.insert(input.previous_output)),
            "duplicate cached transaction input"
        );
        let mut value = 0u64;
        for (index, output) in transaction.output.iter().enumerate() {
            value = value
                .checked_add(output.value.to_sat())
                .context("cached output sum overflow")?;
            ensure!(value <= MAX_MONEY, "cached output sum exceeds MAX_MONEY");
            if let Some(floating) = changeset
                .tx_graph
                .txouts
                .get(&OutPoint::new(txid, index as u32))
            {
                ensure!(floating == output, "inconsistent cached prevout");
            }
        }
    }
    ensure!(
        changeset
            .tx_graph
            .txouts
            .values()
            .all(|output| output.value.to_sat() <= MAX_MONEY),
        "cached prevout exceeds MAX_MONEY"
    );
    Ok(())
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
