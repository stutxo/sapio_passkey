use crate::engine::Engine;
use anyhow::{ensure, Context, Result};
use bdk_esplora::EsploraAsyncExt;
use esplora_client::r#async::Sleeper;
use futures_channel::oneshot;
use futures_util::future::{select, Either};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use wasm_bindgen::{closure::Closure, JsCast};

/// BDK requires a Send sleeper even on its single-threaded WASM client. The
/// receiver contains no JS handles; the browser owns the one-shot callback.
#[derive(Clone)]
struct BrowserSleeper;

impl Sleeper for BrowserSleeper {
    type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn sleep(duration: Duration) -> Self::Sleep {
        let (sender, receiver) = oneshot::channel();
        let callback = Closure::once_into_js(move || {
            let _ = sender.send(());
        });
        web_sys::window()
            .expect("wallet synchronization requires a browser window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.unchecked_ref(),
                duration.as_millis().min(i32::MAX as u128) as i32,
            )
            .expect("browser timer unavailable");
        Box::pin(async move {
            let _ = receiver.await;
        })
    }
}

/// Unlike a detached Promise timeout, this timer is cancelled when sync wins.
struct Deadline {
    receiver: oneshot::Receiver<()>,
    handle: i32,
    _callback: Closure<dyn FnMut()>,
}

impl Deadline {
    fn new(milliseconds: i32) -> Result<Self> {
        let (sender, receiver) = oneshot::channel();
        let mut sender = Some(sender);
        let callback = Closure::wrap(Box::new(move || {
            if let Some(sender) = sender.take() {
                let _ = sender.send(());
            }
        }) as Box<dyn FnMut()>);
        let handle = web_sys::window()
            .context("wallet synchronization requires a browser window")?
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                milliseconds,
            )
            .map_err(|_| anyhow::anyhow!("browser timer unavailable"))?;
        Ok(Self {
            receiver,
            handle,
            _callback: callback,
        })
    }
}

impl Future for Deadline {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<()> {
        Pin::new(&mut self.receiver).poll(context).map(|_| ())
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        if let Some(window) = web_sys::window() {
            window.clear_timeout_with_handle(self.handle);
        }
    }
}

fn validate_url(value: &str, allow_local_dev: bool) -> Result<()> {
    let url = web_sys::Url::new(value).map_err(|_| anyhow::anyhow!("invalid Esplora API URL"))?;
    ensure!(
        url.username().is_empty()
            && url.password().is_empty()
            && url.search().is_empty()
            && url.hash().is_empty()
            && url.pathname() == "/esplora"
            && value == format!("{}/esplora", url.origin()),
        "Esplora URL must be a canonical API origin followed by /esplora"
    );
    ensure!(
        url.protocol() == "https:"
            || (allow_local_dev
                && url.protocol() == "http:"
                && matches!(url.hostname().as_str(), "localhost" | "127.0.0.1")),
        "Esplora requires HTTPS except explicit localhost development"
    );
    Ok(())
}

pub(crate) async fn synchronize(
    engine: &mut Engine,
    url: &str,
    allow_local_dev: bool,
    now: u64,
) -> Result<()> {
    validate_url(url, allow_local_dev)?;
    let client = esplora_client::Builder::new(url)
        .max_retries(0)
        .build_async_with_sleeper::<BrowserSleeper>()?;
    let wallet = engine.bdk();
    let request = wallet
        .start_sync_with_revealed_spks_at(now)
        .outpoints(wallet.list_unspent().map(|output| output.outpoint))
        .txids(
            wallet
                .transactions()
                .map(|transaction| transaction.tx_node.txid),
        )
        .build();
    let update = match select(
        Box::pin(client.sync(request, 3)),
        Box::pin(Deadline::new(90_000)?),
    )
    .await
    {
        Either::Left((result, _)) => result.context("Esplora synchronization failed")?,
        Either::Right(_) => {
            anyhow::bail!("Esplora synchronization exceeded its 90-second deadline")
        }
    };
    engine.apply_update(update.into(), now)
}
