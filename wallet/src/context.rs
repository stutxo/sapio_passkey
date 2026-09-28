use anyhow::{ensure, Context, Result};
use bitcoin::{bip32::Xpub, Network};
use sapio_base::program::{EvaluatorId, MAX_PROGRAM_ROOT_DEPTH};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub protocol: String,
    pub mode: String,
    pub xpub: Xpub,
    pub settings: Value,
    pub signing: ProgramProfile,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InlineEvaluator {
    pub id: EvaluatorId,
    pub wasm_version: u8,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredEvaluator {
    pub name: String,
    pub id: EvaluatorId,
    pub wasm_version: u8,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramProfile {
    pub protocol: String,
    pub inline_evaluators: Vec<InlineEvaluator>,
    pub registered_evaluators: Vec<RegisteredEvaluator>,
    pub max_connections: usize,
    pub request_timeout_secs: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletContext {
    pub identity: Identity,
    pub origin: String,
    pub rp_id: String,
    pub allow_local_dev: bool,
}

/// A validated, public-only context. Construction never contacts a server.
pub(crate) struct Wallet<'a> {
    pub root: &'a Xpub,
    pub network: Network,
    pub local_dev: bool,
    pub origin: &'a str,
    pub rp_id: &'a str,
}

impl WalletContext {
    pub(crate) fn validate(&self) -> Result<Wallet<'_>> {
        let identity = &self.identity;
        ensure!(
            identity.protocol == "sapio-tee/program-oracle/1",
            "unsupported identity protocol"
        );
        ensure!(
            identity.signing.protocol == "SignProgramV1",
            "unsupported signing protocol"
        );
        ensure!(
            identity.signing.max_connections > 0 && identity.signing.request_timeout_secs > 0,
            "identity advertises unusable signing limits"
        );
        let mut v2 = identity
            .signing
            .inline_evaluators
            .iter()
            .filter(|entry| entry.id == EvaluatorId::wasm_v2());
        ensure!(
            v2.next().is_some_and(|entry| entry.wasm_version == 2) && v2.next().is_none(),
            "identity must advertise the exact inline WASM v2 evaluator"
        );
        ensure!(
            identity.xpub.depth <= MAX_PROGRAM_ROOT_DEPTH,
            "program root depth exceeds derivation limit"
        );
        let local_dev = identity.mode == "local-dev";
        let network = match identity.mode.as_str() {
            "local-dev" => {
                ensure!(
                    self.allow_local_dev && self.rp_id == "localhost",
                    "unattested regtest requires explicit localhost local-dev opt-in"
                );
                ensure!(
                    identity.settings.is_null(),
                    "local-dev settings must be null"
                );
                Network::Regtest
            }
            "nitro" => {
                ensure!(
                    identity.settings.is_object(),
                    "Nitro identity requires settings"
                );
                let network: Network = serde_json::from_value(identity.settings["network"].clone())
                    .context("Nitro identity settings need a named network")?;
                ensure!(network == Network::Signet, "Nitro wallet requires signet");
                network
            }
            _ => anyhow::bail!("unsupported identity mode"),
        };
        ensure!(
            identity.xpub.network == network.into(),
            "identity xpub does not match its Bitcoin network"
        );
        validate_origin(&self.origin, &self.rp_id, self.allow_local_dev)?;
        Ok(Wallet {
            root: &identity.xpub,
            network,
            local_dev,
            origin: &self.origin,
            rp_id: &self.rp_id,
        })
    }
}

fn validate_origin(origin: &str, rp_id: &str, allow_local_dev: bool) -> Result<()> {
    ensure!(
        !rp_id.is_empty() && rp_id.len() <= 253 && rp_id.is_ascii(),
        "invalid RP ID"
    );
    ensure!(origin.len() <= 256 && origin.is_ascii(), "invalid origin");
    ensure!(
        rp_id.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        }),
        "RP ID must be the canonical origin hostname"
    );
    let authority = if let Some(authority) = origin.strip_prefix("https://") {
        authority
    } else {
        ensure!(
            allow_local_dev && rp_id == "localhost",
            "wallet origin requires HTTPS (HTTP is localhost-development only)"
        );
        origin
            .strip_prefix("http://")
            .context("invalid wallet origin scheme")?
    };
    let suffix = authority
        .strip_prefix(rp_id)
        .context("origin hostname does not match RP ID")?;
    if !suffix.is_empty() {
        let port = suffix
            .strip_prefix(':')
            .context("origin must contain only its scheme, hostname and optional port")?;
        ensure!(
            !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()),
            "invalid origin port"
        );
        let number: u16 = port.parse().context("invalid origin port")?;
        ensure!(
            number > 0 && number.to_string() == port,
            "invalid origin port"
        );
        ensure!(
            !(origin.starts_with("https://") && number == 443)
                && !(origin.starts_with("http://") && number == 80),
            "origin must use canonical default-port omission"
        );
    }
    Ok(())
}
