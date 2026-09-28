"use strict";

let modulePromise;
let session;
let sessionContext;
let generation = 0;
let pending = Promise.resolve();

function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}

async function module() {
  if (!modulePromise) {
    modulePromise = import("./pkg/sapio_passkey_wallet.js").then(async (binding) => {
      await binding.default();
      requireThat(typeof binding.WalletSession === "function", "The wallet assets have an incompatible session binding.");
      return binding;
    }).catch((error) => {
      modulePromise = undefined;
      throw error;
    });
  }
  return modulePromise;
}

function result(value) {
  const envelope = JSON.parse(value);
  requireThat(envelope !== null && typeof envelope === "object" && !Array.isArray(envelope)
    && Object.keys(envelope).length === 1, "The wallet returned an invalid result envelope.");
  if (Object.hasOwn(envelope, "error")) {
    requireThat(typeof envelope.error === "string" && envelope.error.length > 0, "The wallet returned an invalid error.");
    throw new Error(envelope.error);
  }
  requireThat(Object.hasOwn(envelope, "ok"), "The wallet returned no result.");
  return envelope.ok;
}

function enqueue(work, signal) {
  const expectedGeneration = generation;
  const operation = pending.then(async () => {
    signal?.throwIfAborted();
    requireThat(expectedGeneration === generation, "This wallet session was closed.");
    const value = await work();
    signal?.throwIfAborted();
    requireThat(expectedGeneration === generation, "This wallet session was closed.");
    return value;
  });
  // Never release the mutation queue when only the caller's signal is aborted:
  // a BDK sync still owns its WASM session until its promise actually settles.
  pending = operation.catch(() => {});
  return operation;
}

export function walletCall(operation, context, body = {}, signal) {
  requireThat(typeof operation === "string" && context !== null && typeof context === "object"
    && !Array.isArray(context) && body !== null && typeof body === "object" && !Array.isArray(body), "Invalid wallet request.");
  const contextJson = JSON.stringify(context);
  const bodyJson = JSON.stringify(body);
  return enqueue(async () => {
    const binding = await module();
    signal?.throwIfAborted();
    if (!session) {
      session = new binding.WalletSession(contextJson);
      sessionContext = contextJson;
    }
    requireThat(sessionContext === contextJson, "Close the current wallet before changing its pinned context.");
    return result(session.call(operation, bodyJson, Math.floor(Date.now() / 1000)));
  }, signal);
}

export function syncWallet(esploraBaseUrl, signal) {
  return enqueue(async () => {
    requireThat(session, "Open a wallet before synchronizing it.");
    return result(await session.sync(esploraBaseUrl, Math.floor(Date.now() / 1000)));
  }, signal);
}

export function closeWalletModule() {
  generation += 1;
  const closing = pending.then(() => {
    session?.free();
    session = undefined;
    sessionContext = undefined;
  });
  pending = closing.catch(() => {});
  return closing;
}
