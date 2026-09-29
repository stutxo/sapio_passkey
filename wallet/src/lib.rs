//! Browser-owned BDK wallet state with externally authorized Taproot signing.
mod authorization;
mod context;
#[path = "../../policy/contract.rs"]
pub mod contract;
mod engine;
#[cfg(target_arch = "wasm32")]
mod network;
pub mod wire;

use anyhow::{ensure, Context, Result};
pub use context::{Identity, InlineEvaluator, ProgramProfile, RegisteredEvaluator, WalletContext};
use engine::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

const MAX_JSON: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    public_key: String,
}

/// A session never holds a Bitcoin private key or a passkey private key.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct WalletSession {
    context: WalletContext,
    engine: Option<Engine>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl WalletSession {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
    pub fn new(context_json: &str) -> std::result::Result<Self, String> {
        let context = (|| -> Result<WalletContext> {
            ensure!(
                context_json.len() <= MAX_JSON,
                "context exceeds the JSON limit"
            );
            let context: WalletContext = serde_json::from_str(context_json)?;
            context.validate()?;
            Ok(context)
        })()
        .map_err(|error| error.to_string())?;
        Ok(Self {
            context,
            engine: None,
        })
    }

    /// Native and browser consumers use the same operations and error envelope.
    pub fn call(&mut self, operation: &str, body_json: &str, now: f64) -> String {
        envelope((|| {
            let now = checked_time(now)?;
            ensure!(
                body_json.len() <= MAX_JSON,
                "request exceeds the JSON limit"
            );
            let body: Value = serde_json::from_str(body_json).context("invalid request JSON")?;
            ensure!(body.is_object(), "request body must be an object");
            self.dispatch(operation, body, now)
        })())
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn sync(&mut self, esplora_url: String, now: f64) -> String {
        let result = async {
            let now = checked_time(now)?;
            let engine = self
                .engine
                .as_mut()
                .context("open a wallet before synchronizing")?;
            network::synchronize(engine, &esplora_url, self.context.allow_local_dev, now).await?;
            engine.snapshot(now)
        }
        .await;
        envelope(result)
    }
}

impl WalletSession {
    fn dispatch(&mut self, operation: &str, body: Value, now: u64) -> Result<Value> {
        let app = self.context.validate()?;
        match operation {
            "configure" | "login_challenge" | "login" => {
                authorization::dispatch(&app, operation, body)
            }
            "open" => {
                ensure!(
                    self.engine.is_none(),
                    "close the existing wallet before opening another"
                );
                let input: Open = serde_json::from_value(body)?;
                let engine = Engine::new(&app, &input.public_key)?;
                let wallet = authorization::dispatch(
                    &app,
                    "wallet",
                    json!({ "public_key": input.public_key }),
                )?;
                let snapshot = engine.snapshot(now)?;
                ensure!(
                    wallet["address"] == snapshot["address"],
                    "wallet descriptor does not match the policy"
                );
                self.engine = Some(engine);
                Ok(json!({ "wallet": wallet, "snapshot": snapshot }))
            }
            _ => {
                let engine = self.engine.as_mut().context("open a wallet first")?;
                match operation {
                    "snapshot" => {
                        empty_body(&body)?;
                        engine.snapshot(now)
                    }
                    "prepare" => engine.prepare(&app, body, now),
                    "bump" => engine.bump(&app, body, now),
                    "reauthorize" => engine.reauthorize(&app, body),
                    "request" => {
                        ensure!(
                            body["public_key"].as_str() == Some(engine.public_key()),
                            "signing key does not match the open wallet"
                        );
                        engine.assert_prepared(
                            body["psbt"].as_str().context("missing reviewed PSBT")?,
                        )?;
                        authorization::dispatch(&app, operation, body)
                    }
                    "finalize_passkey" => {
                        let result = authorization::dispatch(&app, operation, body)?;
                        engine.record_finalized(
                            result["transaction_hex"]
                                .as_str()
                                .context("missing finalized transaction")?,
                            now,
                        )?;
                        Ok(result)
                    }
                    "broadcast_result" => engine.broadcast_result(body, now),
                    "discard_result" => engine.discard_result(body, now),
                    "export_state" => {
                        empty_body(&body)?;
                        engine.export_state()
                    }
                    "import_state" => engine.import_state(body, now),
                    _ => anyhow::bail!("unknown wallet operation"),
                }
            }
        }
    }
}

fn empty_body(body: &Value) -> Result<()> {
    ensure!(
        body.as_object().is_some_and(|body| body.is_empty()),
        "operation requires an empty object"
    );
    Ok(())
}

fn checked_time(now: f64) -> Result<u64> {
    ensure!(
        now.is_finite() && now.fract() == 0.0 && (0.0..=9_007_199_254_740_991.0).contains(&now),
        "invalid Unix timestamp"
    );
    Ok(now as u64)
}

fn envelope(result: Result<Value>) -> String {
    let value = match result {
        Ok(value) => json!({ "ok": value }),
        Err(error) => json!({ "error": format!("{error:#}") }),
    };
    match serde_json::to_string(&value) {
        Ok(encoded) if encoded.len() <= MAX_JSON => encoded,
        Ok(_) => r#"{"error":"wallet result exceeds the JSON limit"}"#.to_owned(),
        Err(_) => r#"{"error":"wallet result cannot be serialized"}"#.to_owned(),
    }
}
