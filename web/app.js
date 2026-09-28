import { walletCall, syncWallet as syncSession, closeWalletModule } from "./wallet.js";

"use strict";

const ORIGIN = location.origin;
const RP_ID = location.hostname;
const MAX_JSON = 1000000;
const MAX_MONEY = 2100000000000000;
const MAX_INPUTS = 16;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const $ = (id) => document.getElementById(id);
const state = {
  config: null, context: null, apiUrl: null, signUrl: null, chainUrl: null, chain: null,
  identity: null, wallet: null, snapshot: null, syncReady: false, review: null, result: null,
  resultStatus: null, controller: null, busy: false, phase: null,
  requestSent: false, credentialCreated: false, feeEdited: false, sendMax: false,
  bumpTxid: null, historyLimit: 25, releaseLock: null, cacheKey: null,
};

function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}

function object(value, label) {
  requireThat(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object.`);
  return value;
}

function freeze(value) {
  if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
}

function integer(value, label, minimum = 0, maximum = MAX_MONEY) {
  requireThat(Number.isSafeInteger(value) && value >= minimum && value <= maximum, `${label} must be an integer from ${minimum} to ${maximum}.`);
  return value;
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function unhex(value, label, length, maximum = 1048576) {
  requireThat(typeof value === "string" && value.length > 0 && value.length % 2 === 0
    && value.length <= maximum * 2 && /^[0-9a-f]+$/.test(value), `${label} must be bounded, lowercase hex.`);
  requireThat(length === undefined || value.length === length * 2, `${label} has the wrong length.`);
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function concat(...parts) {
  const bytes = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  return bytes;
}

function equal(a, b) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function credentialBytes(credential) {
  requireThat(credential?.type === "public-key" && credential.rawId instanceof ArrayBuffer,
    "The authenticator did not return a public-key credential.");
  const bytes = new Uint8Array(credential.rawId);
  requireThat(bytes.length > 0 && bytes.length <= 1024 && credential.id === base64url(bytes),
    "The authenticator returned an invalid credential ID.");
  return bytes;
}

const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const signal = () => state.controller.signal;
const formatSats = (value) => `${value.toLocaleString("en-US")} sats`;
const setStatus = (message) => { $("status").textContent = message; };
const hasPendingResult = () => state.result && !["submitted", "confirmed", "replaced"].includes(resultState());

function showError(message) {
  $("error").textContent = message;
  $("error").hidden = false;
}

function checkContext() {
  signal().throwIfAborted();
  requireThat(state.config && state.context && location.origin === ORIGIN && location.hostname === RP_ID
    && window.isSecureContext && window.top === window.self, "The pinned context is unavailable or changed. Reload this exact origin in a top-level browser tab.");
}

async function readText(response, label, requestSignal, maximum = MAX_JSON) {
  const declared = response.headers.get("content-length");
  requireThat(declared === null || (/^[0-9]+$/.test(declared) && Number(declared) <= maximum), `${label} exceeds the response size limit.`);
  requireThat(response.body, `${label} returned no response body.`);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      requestSignal.throwIfAborted();
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      requireThat(size <= maximum, `${label} exceeds the response size limit.`);
      chunks.push(value);
    }
    requestSignal.throwIfAborted();
  } finally {
    try { await reader.cancel(); } catch { /* Preserve the original request error. */ }
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return decoder.decode(bytes);
}

async function readJson(response, label, requestSignal) {
  requireThat(response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() === "application/json", `${label} returned a non-JSON response.`);
  let value;
  try { value = JSON.parse(await readText(response, label, requestSignal)); }
  catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} returned invalid JSON.`);
    throw error;
  }
  if (!response.ok) throw new Error(typeof value?.error === "string" ? value.error.slice(0, 1000) : `${label} failed (HTTP ${response.status}).`);
  return object(value, label);
}

async function fetchResponse(url, label, options, consume) {
  const target = new URL(url);
  requireThat(target.origin === ORIGIN || target.origin === state.apiUrl, "Only this site's static assets and the pinned API origin may be requested.");
  const parent = signal();
  parent.throwIfAborted();
  const controller = new AbortController();
  const cancel = () => controller.abort(parent.reason);
  parent.addEventListener("abort", cancel, { once: true });
  const timeout = setTimeout(() => controller.abort(new DOMException(`${label} timed out.`, "TimeoutError")), 30000);
  try {
    const response = await fetch(target, {
      ...options, credentials: "omit", mode: target.origin === ORIGIN ? "same-origin" : "cors",
      cache: "no-store", redirect: "error", signal: controller.signal,
    });
    return await consume(response, controller.signal);
  } catch (error) {
    if (controller.signal.aborted) throw controller.signal.reason;
    throw error;
  } finally {
    clearTimeout(timeout);
    parent.removeEventListener("abort", cancel);
    controller.abort();
  }
}

function fetchJson(url, label, options = {}) {
  return fetchResponse(url, label, { ...options, headers: { Accept: "application/json", ...options.headers } },
    (response, requestSignal) => readJson(response, label, requestSignal));
}

function jsonBody(value) {
  const body = encoder.encode(JSON.stringify(value));
  requireThat(body.length > 0 && body.length <= MAX_JSON, "Request exceeds the transport limit. This wallet cannot handle these funding transactions.");
  return { method: "POST", headers: { "Content-Type": "application/json" }, body };
}

const chainGet = (path, label) => fetchJson(`${state.chainUrl}/${path}`, label);

async function loadConfiguration() {
  const config = await fetchJson(new URL("./wallet-config.json", import.meta.url), "Static configuration");
  const fields = ["version", "identity", "api_url", "chain", "allow_local_dev"];
  requireThat(Object.keys(config).length === fields.length && fields.every((field) => Object.hasOwn(config, field))
    && config.version === 1 && typeof config.allow_local_dev === "boolean", "Use an operator-supplied version-1 static configuration.");
  object(config.identity, "Pinned public identity");
  const localFrontend = RP_ID === "localhost" && config.allow_local_dev;
  requireThat(location.protocol === "https:" || (location.protocol === "http:" && localFrontend), "HTTPS is required, except explicitly configured localhost development.");
  requireThat(typeof config.api_url === "string", "The static configuration must specify its external API origin.");
  const api = new URL(config.api_url);
  requireThat(config.api_url === api.origin && !api.username && !api.password && !api.search && !api.hash && api.pathname === "/",
    "The API URL must be a canonical origin with no path, credentials, query, fragment or trailing slash.");
  requireThat(api.protocol === "https:" || (api.protocol === "http:" && localFrontend
    && ["localhost", "127.0.0.1"].includes(api.hostname)), "The API requires HTTPS except explicit loopback development.");
  const context = freeze({ identity: config.identity, origin: ORIGIN, rp_id: RP_ID, allow_local_dev: config.allow_local_dev });
  const validated = object(await walletCall("configure", context, {}, signal()), "Wallet configuration");
  requireThat(validated.origin === ORIGIN && validated.rp_id === RP_ID && typeof validated.local_dev === "boolean", "Wallet configuration does not match this origin.");
  requireThat((config.chain === "mutinynet" && validated.network === "signet" && config.identity.mode === "nitro" && !validated.local_dev)
    || (config.chain === "regtest" && localFrontend && validated.network === "regtest"
      && config.identity.mode === "local-dev" && validated.local_dev), "Only pinned Nitro Mutinynet wallets or explicit localhost regtest fixtures are supported.");
  unhex(validated.genesis_hash, "Network genesis", 32);
  unhex(validated.module_sha256, "Policy module hash", 32);
  signal().throwIfAborted();
  state.context = context;
  state.config = freeze(validated);
  state.apiUrl = api.origin;
  state.signUrl = `${api.origin}/api/sign`;
  state.chainUrl = `${api.origin}/esplora`;
  state.chain = config.chain;
  $("wallet-title").textContent = config.chain === "mutinynet" ? "Mutinynet wallet" : "Regtest wallet";
  $("network-badge").textContent = config.chain === "mutinynet" ? "Mutinynet · signet test coins" : "Regtest · local fixture only";
  $("environment-badge").textContent = validated.local_dev
    ? "Local software signer · not a hardware enclave"
    : "Pinned enclave identity · attestation not checked here";
  $("api-origin").textContent = api.origin;
}

function validateIdentity(value) {
  const identity = object(value, "Passkey identity");
  requireThat(Object.keys(identity).length === 2 && Object.hasOwn(identity, "public_key")
    && Object.hasOwn(identity, "credential_id"), "The wallet returned an invalid passkey identity.");
  unhex(identity.credential_id, "Passkey credential ID", undefined, 1024);
  const key = unhex(identity.public_key, "Passkey public key", 33);
  requireThat(key[0] === 2 || key[0] === 3, "Passkey public key is not compressed P-256.");
  return freeze(identity);
}

async function deriveWallet(publicKey) {
  checkContext();
  const opened = object(await walletCall("open", state.context, { public_key: publicKey }, signal()), "Opened wallet");
  const wallet = object(opened.wallet, "Wallet");
  const origin = encoder.encode(ORIGIN);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, origin.length, true);
  const parameters = concat(encoder.encode("SPK3"), unhex(state.config.genesis_hash, "Network genesis", 32),
    unhex(publicKey, "Passkey public key", 33), await sha256(encoder.encode(RP_ID)), length, origin);
  requireThat(wallet.parameters === hex(parameters), "The wallet module does not implement the pinned SPK3 passkey-only policy. Reload matching static assets.");
  unhex(wallet.program_id, "Program ID", 32);
  const prefix = state.chain === "mutinynet" ? "tb1p" : "bcrt1p";
  requireThat(typeof wallet.address === "string" && wallet.address.startsWith(prefix)
    && /^[a-z0-9]{10,90}$/.test(wallet.address), "The wallet returned an invalid receive address.");
  return { wallet: freeze(wallet), snapshot: opened.snapshot };
}

async function acceptWallet(identity, opened, note) {
  checkContext();
  const { wallet } = opened;
  const contextHash = hex(await sha256(encoder.encode(JSON.stringify([
    ORIGIN, RP_ID, state.config.network, state.config.genesis_hash,
    state.config.xpub, state.config.module_sha256, wallet.address,
  ]))));
  const key = `${contextHash}:${wallet.program_id}`;
  await acquireWalletLock(key);
  checkContext();
  state.wallet = wallet;
  state.cacheKey = key;
  state.syncReady = false;
  state.historyLimit = 25;
  applySnapshot(opened.snapshot);
  state.credentialCreated = false;
  resetNewWalletOffer();
  state.identity = identity;
  $("passkey-note").textContent = note;
  $("receive-address").value = wallet.address;
  $("passkey-panel").hidden = true;
  for (const id of ["wallet-panel", "payment-panel", "history-panel"]) $(id).hidden = false;
  $("balance-heading").focus();
  // Restoration above never consults storage. Only the reconstructed wallet
  // may import its context-bound public cache.
  try {
    const cached = await cacheOperation("read");
    checkContext();
    if (cached !== undefined) {
      applySnapshot(await walletCall("import_state", state.context, { state: cached }, signal()));
      const pending = state.snapshot.outbox.find((entry) => entry.state !== "accepted");
      if (pending) selectOutbox(pending.txid);
    }
  } catch (error) {
    if (signal().aborted) throw error;
    cacheWarning(`Public history could not be restored: ${explainError(error)} The wallet is open; refresh can still load chain history.`);
  }
}

async function acquireWalletLock(key) {
  requireThat(navigator.locks?.request, "This browser lacks Web Locks. Use a current browser to prevent conflicting tabs from writing the same opened wallet.");
  const requestSignal = signal();
  await new Promise((resolve, reject) => {
    navigator.locks.request(`sapio-passkey:${key}`, { mode: "exclusive", ifAvailable: true }, async (lock) => {
      requireThat(lock, "This wallet is already open in another tab on this origin. Log out there before logging in here.");
      requestSignal.throwIfAborted();
      await new Promise((release) => {
        state.releaseLock = release;
        resolve();
      });
    }).catch(reject);
  });
}

function cacheWarning(message) {
  $("cache-warning").textContent = message;
  $("cache-warning").hidden = false;
}

function cacheOperation(action, value) {
  requireThat(state.releaseLock && state.cacheKey, "Public history storage requires this wallet's exclusive tab lock.");
  const key = state.cacheKey;
  return new Promise((resolve, reject) => {
    let db;
    let transaction;
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      db?.close();
      if (error) reject(error);
      else resolve(result);
    };
    const timer = setTimeout(() => {
      try { transaction?.abort(); } catch { /* It may already have completed. */ }
      finish(new Error("Browser storage did not respond in time."));
    }, 5000);
    let opening;
    try { opening = indexedDB.open("sapio-passkey-public-history", 1); }
    catch (error) { finish(error); return; }
    opening.onupgradeneeded = () => {
      if (!opening.result.objectStoreNames.contains("wallets")) opening.result.createObjectStore("wallets");
    };
    opening.onerror = () => finish(opening.error || new Error("Public history storage could not be opened."));
    opening.onblocked = () => finish(new Error("Another tab is blocking public history storage."));
    opening.onsuccess = () => {
      db = opening.result;
      if (settled) { db.close(); return; }
      db.onversionchange = () => db.close();
      try {
        transaction = db.transaction("wallets", action === "read" ? "readonly" : "readwrite");
        const store = transaction.objectStore("wallets");
        const request = action === "read" ? store.get(key) : store.put(value, key);
        transaction.oncomplete = () => finish(null, request.result);
        transaction.onabort = () => finish(transaction.error || new Error("Public history storage was interrupted."));
        transaction.onerror = () => finish(transaction.error || new Error("Public history storage failed."));
      } catch (error) { finish(error); }
    };
  });
}

async function savePublicState() {
  if (!state.wallet) return;
  try {
    // Storage failure never drops signed bytes or the in-memory BDK session.
    const publicState = await walletCall("export_state", state.context);
    await cacheOperation("write", publicState);
  } catch (error) {
    cacheWarning(`Could not save public history: ${explainError(error)} This open wallet and any signed transaction remain in memory. Keep the tab open if you need its retry bytes.`);
  }
}

function applySnapshot(value) {
  const snapshot = object(value, "Wallet snapshot");
  requireThat(snapshot.address === state.wallet.address && typeof snapshot.synced === "boolean", "Wallet snapshot changed the receive address or sync state.");
  object(snapshot.chain_tip, "Chain tip");
  integer(snapshot.chain_tip.height, "Chain height", 0, 4294967295);
  unhex(snapshot.chain_tip.hash, "Chain tip hash", 32);
  object(snapshot.balance, "Wallet balance");
  for (const key of ["confirmed_sats", "pending_sats", "immature_sats", "total_sats", "spendable_sats"]) integer(snapshot.balance[key], key);
  requireThat(Array.isArray(snapshot.transactions) && Array.isArray(snapshot.outbox), "Wallet history or signed outbox is missing.");
  const seen = new Set();
  for (const tx of snapshot.transactions) {
    object(tx, "History transaction");
    unhex(tx.txid, "History transaction ID", 32);
    requireThat(!seen.has(tx.txid), "Wallet history contains a duplicate transaction.");
    seen.add(tx.txid);
    for (const key of ["received_sats", "sent_sats", "confirmations"]) integer(tx[key], key);
    if (tx.fee_sats !== null) integer(tx.fee_sats, "Transaction fee");
    if (tx.block_height !== null) integer(tx.block_height, "Block height", 0, 4294967295);
    if (tx.timestamp !== null) integer(tx.timestamp, "Transaction time", 0, 8640000000000);
    if (tx.replaced_by !== null) unhex(tx.replaced_by, "Replacement transaction ID", 32);
    requireThat(["confirmed", "pending", "replaced", "uncertain", "signed"].includes(tx.status)
      && typeof tx.outgoing === "boolean" && typeof tx.can_bump === "boolean", "Invalid transaction history state.");
  }
  const outboxIds = new Set();
  for (const entry of snapshot.outbox) {
    object(entry, "Signed transaction");
    unhex(entry.txid, "Signed transaction ID", 32);
    unhex(entry.transaction_hex, "Signed transaction bytes", undefined, MAX_JSON / 2);
    integer(entry.fee_sats, "Signed transaction fee");
    integer(entry.created_at, "Signed transaction time", 0, 8640000000000);
    if (entry.replaces !== null) unhex(entry.replaces, "Replaced transaction ID", 32);
    requireThat(!outboxIds.has(entry.txid) && ["signed", "accepted", "uncertain"].includes(entry.state), "Invalid signed outbox state.");
    outboxIds.add(entry.txid);
  }
  state.snapshot = freeze(snapshot);
  for (const [id, key] of [["balance-confirmed", "confirmed_sats"], ["balance-pending", "pending_sats"],
    ["balance-immature", "immature_sats"], ["balance-spendable", "spendable_sats"]]) $(id).textContent = formatSats(snapshot.balance[key]);
  renderHistory();
  renderResult();
}

function historyStatus(tx) {
  if (tx.status === "confirmed") return `${tx.confirmations.toLocaleString()} ${tx.confirmations === 1 ? "confirmation" : "confirmations"} · block ${tx.block_height}`;
  return { pending: "Pending · not confirmed", replaced: "Replaced / conflicted", uncertain: "Broadcast outcome uncertain", signed: "Signed locally · network outcome unknown" }[tx.status];
}

function renderHistory() {
  const transactions = state.snapshot?.transactions ?? [];
  const outbox = new Map((state.snapshot?.outbox ?? []).map((entry) => [entry.txid, entry]));
  const rows = transactions.slice(0, state.historyLimit).map((tx) => {
    const item = document.createElement("li");
    const heading = document.createElement("p");
    heading.className = "history-state";
    heading.textContent = `${tx.outgoing ? "Outgoing" : "Incoming"} · ${historyStatus(tx)}`;
    const id = document.createElement("p");
    id.className = "mono";
    id.textContent = tx.txid;
    const amounts = document.createElement("p");
    amounts.className = "approval-note";
    amounts.textContent = `Received ${formatSats(tx.received_sats)} · spent ${formatSats(tx.sent_sats)}${tx.fee_sats === null ? "" : ` · fee ${formatSats(tx.fee_sats)}`}${tx.timestamp === null ? "" : ` · ${new Date(tx.timestamp * 1000).toLocaleString()}`}`;
    item.append(heading, id, amounts);
    if (tx.replaced_by) {
      const replacement = document.createElement("p");
      replacement.className = "mono";
      replacement.textContent = `Replaced / conflicted by ${tx.replaced_by}`;
      item.append(replacement);
    }
    const actions = document.createElement("div");
    actions.className = "wallet-actions";
    if (tx.can_bump) {
      const bump = document.createElement("button");
      bump.type = "button";
      bump.className = "secondary";
      bump.textContent = "Increase fee";
      bump.dataset.bump = tx.txid;
      bump.disabled = state.busy || !state.syncReady || !!hasPendingResult();
      bump.addEventListener("click", () => beginBump(tx.txid));
      actions.append(bump);
    }
    if (outbox.has(tx.txid)) actions.append(outboxButton(tx.txid));
    item.append(actions);
    return item;
  });
  $("history-list").replaceChildren(...rows);
  $("history-note").textContent = transactions.length
    ? `Showing ${Math.min(state.historyLimit, transactions.length)} of ${transactions.length} transactions. History combines local signed transactions and indexer data. Only a block anchor indicates confirmation; unconfirmed conflicts can change.`
    : "No transactions in this wallet snapshot. Refresh to check the indexer.";
  $("history-more").hidden = transactions.length <= state.historyLimit;
  const known = new Set(transactions.map((tx) => tx.txid));
  const extra = [...outbox.keys()].filter((txid) => !known.has(txid));
  $("outbox-extra").replaceChildren(...extra.map(outboxButton));
  $("outbox-extra").hidden = extra.length === 0;
}

function outboxButton(txid) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "quiet";
  button.dataset.outbox = txid;
  button.textContent = `Show signed transaction · ${txid.slice(0, 8)}…`;
  button.setAttribute("aria-label", `Show signed transaction ${txid}`);
  button.disabled = state.busy || (!!hasPendingResult() && state.result.txid !== txid);
  button.addEventListener("click", () => {
    if (state.busy || (hasPendingResult() && state.result.txid !== txid)) return;
    invalidateReview();
    selectOutbox(txid);
    renderControls();
    $("result-heading").focus();
  });
  return button;
}

function selectOutbox(txid) {
  const entry = state.snapshot.outbox.find((candidate) => candidate.txid === txid);
  requireThat(entry, "That signed transaction is not available in this wallet session.");
  state.result = freeze({ txid: entry.txid, transaction_hex: entry.transaction_hex, signed_psbt: "", fee_sats: entry.fee_sats });
  // A cached 'signed' entry can be left by a crash after submission began.
  // Treat it as uncertain; an explicit retry still sends identical bytes.
  state.resultStatus = entry.state === "accepted" ? "submitted" : "uncertain";
  renderResult();
}

async function syncWallet() {
  checkContext();
  requireThat(state.identity && state.wallet && state.releaseLock, "Open a wallet before refreshing.");
  invalidateReview();
  state.syncReady = false;
  state.phase = "sync";
  $("sync-note").textContent = "Refreshing history. Displayed balances may be stale.";
  try {
    setStatus("Refreshing wallet history…");
    applySnapshot(await syncSession(state.chainUrl, signal()));
    checkContext();
    state.syncReady = state.snapshot.synced;
    $("sync-note").textContent = `Updated ${new Date().toLocaleTimeString()} · block ${state.snapshot.chain_tip.height.toLocaleString()}. Confirmations and spentness are indexer-reported, not SPV verified.`;
    await savePublicState();
  } catch (error) {
    $("sync-note").textContent = "Refresh did not complete. The displayed snapshot may be stale; refresh again before preparing a payment. Wallet and signed transaction bytes remain available.";
    // A cancelled caller may still have let BDK apply its completed update.
    // The session queue has settled here, so retain that state without
    // presenting a cancelled refresh as a successful one.
    await savePublicState();
    throw error;
  }
  try {
    const rates = await chainGet("fee-estimates", "Fee estimates");
    const entries = Object.entries(rates);
    requireThat(entries.length > 0 && entries.length <= 100 && entries.every(([target, rate]) => /^[1-9][0-9]{0,3}$/.test(target)
      && typeof rate === "number" && Number.isFinite(rate) && rate >= 0), "The indexer returned invalid fee estimates.");
    const estimate = rates["1"] ?? entries.sort((a, b) => Number(a[0]) - Number(b[0]))[0][1];
    const suggestion = Math.min(1000, Math.max(1, Math.ceil(estimate)));
    if (!state.feeEdited) $("fee-rate").value = String(suggestion);
    $("fee-note").textContent = `Indexer suggestion: ${suggestion} sat/vB (rounded up, capped at 1,000). Your editable rate is not a confirmation guarantee.`;
  } catch (error) {
    $("fee-note").textContent = "Fee estimates unavailable. The entered rate is unchanged. Choose a suitable rate yourself.";
    if (signal().aborted) throw error;
  }
  setStatus(state.result ? "History updated. Signed transaction retained below." : "Wallet ready.");
}

function paymentInteger(id, label, maximum) {
  const text = $(id).value;
  requireThat(/^[1-9][0-9]*$/.test(text), `${label} must be a positive whole number, without decimals or separators.`);
  return integer(Number(text), label, 1, maximum);
}

async function prepare(input, operation = "prepare") {
  checkContext();
  const nonce = hex(crypto.getRandomValues(new Uint8Array(32)));
  const proposal = object(await walletCall(operation, state.context, { ...input, nonce }, signal()), "Prepared payment");
  await validateProposal(proposal, nonce);
  const summary = proposal.summary;
  requireThat(summary.fee_rate_sat_vb === input.fee_rate_sat_vb, "Prepared payment changed your requested fee rate.");
  if (operation === "bump") {
    const original = state.snapshot.transactions.find((tx) => tx.txid === input.txid);
    requireThat(summary.replaces === input.txid && original?.can_bump
      && (original.fee_sats === null || summary.fee_sats > original.fee_sats), "The fee replacement changed its original transaction or did not increase its absolute fee.");
  } else {
    const recipientMatches = summary.recipient === input.recipient || (/^(TB1|BCRT1)[A-Z0-9]+$/.test(input.recipient)
      && summary.recipient === input.recipient.toLowerCase());
    requireThat(recipientMatches && summary.replaces === null
      && (input.amount_sats === null ? summary.change_sats === 0 : summary.amount_sats === input.amount_sats),
    "Prepared payment differs from the entered recipient or amount.");
  }
  return freeze(proposal);
}

async function validateProposal(proposal, nonce) {
  const wallet = state.wallet;
  requireThat(proposal.parameters === wallet.parameters && proposal.address === wallet.address
    && proposal.program_id === wallet.program_id && proposal.nonce === nonce, "Prepared payment changed the wallet policy or fresh nonce.");
  const summary = object(proposal.summary, "Payment summary");
  integer(summary.input_count, "Input count", 1, MAX_INPUTS);
  integer(summary.amount_sats, "Payment amount", 1);
  integer(summary.fee_sats, "Transaction fee", 1);
  integer(summary.fee_rate_sat_vb, "Fee rate", 1, 1000);
  integer(summary.change_sats, "Change");
  integer(summary.vsize, "Transaction size", 1, MAX_JSON);
  requireThat(summary.network === state.config.network && typeof summary.recipient === "string"
    && summary.recipient.length > 0 && summary.change_address === wallet.address, "Prepared payment changed the network or change address.");
  if (summary.replaces !== null) unhex(summary.replaces, "Original transaction ID", 32);
  requireThat(Array.isArray(summary.funding) && summary.funding.length === summary.input_count, "Prepared funding does not match the input count.");
  const seen = new Set();
  let total = 0;
  for (const funding of summary.funding) {
    object(funding, "Selected funding");
    const key = `${funding.txid}:${funding.vout}`;
    unhex(funding.txid, "Funding transaction ID", 32);
    integer(funding.vout, "Funding output index", 0, 4294967295);
    integer(funding.value_sats, "Funding value", 1);
    requireThat(!seen.has(key), "Prepared payment uses duplicate funding.");
    seen.add(key);
    total += funding.value_sats;
  }
  integer(total, "Selected funding total");
  requireThat(total === summary.amount_sats + summary.fee_sats + summary.change_sats
    && summary.fee_sats >= summary.vsize * summary.fee_rate_sat_vb, "Prepared payment amounts or fee do not balance.");
  unhex(summary.txid, "Prepared transaction ID", 32);
  requireThat(typeof proposal.psbt === "string" && proposal.psbt.length <= MAX_JSON && /^[A-Za-z0-9+/]+={0,2}$/.test(proposal.psbt), "Invalid prepared PSBT.");
  requireThat(Array.isArray(proposal.challenges) && Array.isArray(proposal.views)
    && proposal.challenges.length === summary.input_count && proposal.views.length === summary.input_count, "Each input must have its own challenge and view.");
  const parameterHash = await sha256(unhex(wallet.parameters, "Policy parameters", undefined, 4096));
  for (let index = 0; index < summary.input_count; index++) {
    const challenge = await sha256(concat(encoder.encode("sapio-passkey/v3\0"), parameterHash,
      await sha256(unhex(proposal.views[index], "Transaction view")), unhex(nonce, "Nonce", 32)));
    requireThat(proposal.challenges[index] === hex(challenge), "A passkey challenge does not commit to this exact input, transaction and nonce.");
  }
  checkContext();
}

async function reviewPayment() {
  checkContext();
  requireThat(state.identity && state.syncReady && state.releaseLock && !hasPendingResult(), "Open and refresh your wallet before reviewing a payment.");
  invalidateReview();
  clearResult();
  const recipient = $("recipient").value.trim();
  requireThat(recipient.length > 0 && recipient.length <= 128, "Enter a Bitcoin recipient address for this network.");
  const input = freeze({ recipient,
    amount_sats: state.sendMax ? null : paymentInteger("amount-sats", "Payment amount", MAX_MONEY),
    fee_rate_sat_vb: paymentInteger("fee-rate", "Fee rate", 1000) });
  const proposal = await prepare(input);
  state.review = freeze({ proposal });
  renderReview(proposal);
}

function beginBump(txid) {
  if (state.busy || !state.syncReady || hasPendingResult()) return;
  requireThat(state.snapshot.transactions.some((tx) => tx.txid === txid && tx.can_bump), "Only a known unconfirmed outgoing transaction can be replaced.");
  invalidateReview();
  clearResult();
  state.bumpTxid = txid;
  $("bump-txid").textContent = txid;
  $("bump-fee-rate").value = $("fee-rate").value;
  $("bump-panel").hidden = false;
  $("payment-panel").hidden = true;
  renderControls();
  $("bump-fee-rate").focus();
  setStatus("Choose a higher replacement fee rate. The original recipient and payment amount will be preserved.");
}

async function reviewBump() {
  checkContext();
  requireThat(state.bumpTxid && state.syncReady && !hasPendingResult(), "Refresh before reviewing a fee replacement.");
  invalidateReview();
  clearResult();
  const proposal = await prepare({ txid: state.bumpTxid,
    fee_rate_sat_vb: paymentInteger("bump-fee-rate", "Replacement fee rate", 1000) }, "bump");
  state.review = freeze({ proposal });
  renderReview(proposal);
}

function renderReview(proposal) {
  const summary = proposal.summary;
  for (const [id, value] of Object.entries({
    "review-recipient": summary.recipient, "review-amount": formatSats(summary.amount_sats),
    "review-fee": `${formatSats(summary.fee_sats)} · requested ${summary.fee_rate_sat_vb} sat/vB`,
    "review-size": `${summary.vsize} vB`, "review-total": formatSats(summary.amount_sats + summary.fee_sats),
    "review-change": formatSats(summary.change_sats),
    "review-change-address": summary.change_sats > 0 ? summary.change_address : "No change output",
    "review-inputs": `${summary.input_count} inputs · ${summary.input_count} passkey approvals`,
    "review-txid": summary.txid,
  })) $(id).textContent = value;
  $("review-heading").textContent = summary.replaces ? "Review fee replacement" : "Review payment";
  $("review-replaces").textContent = summary.replaces ?? "New payment";
  $("review-funding").replaceChildren(...summary.funding.map((funding) => {
    const item = document.createElement("li");
    item.textContent = `${funding.txid}:${funding.vout} · ${formatSats(funding.value_sats)}`;
    return item;
  }));
  $("review-details").hidden = false;
  $("review").hidden = false;
  $("send-payment").textContent = `Approve & sign · ${summary.input_count} ${summary.input_count === 1 ? "approval" : "approvals"}`;
  setStatus("Review the exact transaction. Approve & sign requests fresh passkey approvals; broadcast is a separate explicit action.");
  $("review-heading").focus();
}

function clientData(bytes, type, challenge) {
  requireThat(bytes.length > 0 && bytes.length <= 4096, "Authenticator client data exceeds the supported limit.");
  const value = object(JSON.parse(decoder.decode(bytes)), "Authenticator client data");
  requireThat(!Object.hasOwn(value, "topOrigin") && value.type === type && value.challenge === base64url(challenge)
    && value.origin === ORIGIN && (value.crossOrigin === undefined || value.crossOrigin === false),
  "Authenticator ceremony, challenge, or origin does not match this request.");
}

async function authenticatorData(bytes, registration = false) {
  requireThat(registration ? bytes.length >= 37 : bytes.length === 37, "Unsupported authenticator data or assertion extensions.");
  requireThat(equal(bytes.subarray(0, 32), await sha256(encoder.encode(RP_ID))), "Authenticator RP ID does not match this hostname.");
  const flags = bytes[32];
  requireThat((flags & 5) === 5, "The authenticator must verify both user presence and user verification.");
  requireThat((flags & 0x22) === 0 && (!(flags & 0x10) || (flags & 8)), "Unsupported authenticator flags.");
  if (!registration) requireThat((flags & 0xc0) === 0, "Assertion extensions or attestation data are not supported.");
}

function resetNewWalletOffer() {
  $("new-wallet-panel").hidden = true;
  $("new-wallet-note").textContent = "";
}

async function createPasskey() {
  checkContext();
  requireThat(!state.identity, "Log out before creating another passkey.");
  requireThat(!state.credentialCreated && !$("new-wallet-panel").hidden, "Log in with your passkey before choosing to create a new wallet.");
  resetNewWalletOffer();
  requireThat(typeof PublicKeyCredential !== "undefined" && navigator.credentials?.create, "This browser does not support passkey creation.");
  state.phase = "opening";
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({ publicKey: {
    rp: { id: RP_ID, name: `Sapio ${state.chain === "mutinynet" ? "Mutinynet" : "regtest"} wallet` },
    user: { id: userId, name: `sapio-${base64url(userId).slice(0, 12)}`, displayName: "Sapio test-coin wallet" },
    challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    extensions: { credProps: true }, attestation: "none", timeout: 60000,
  }, signal: signal() });
  state.credentialCreated = true;
  const id = credentialBytes(credential);
  checkContext();
  requireThat(credential.getClientExtensionResults().credProps?.rk !== false,
    "The authenticator did not create a discoverable passkey. This credential cannot be opened without saved metadata.");
  const response = credential.response;
  requireThat(typeof response.getPublicKey === "function" && typeof response.getPublicKeyAlgorithm === "function"
    && typeof response.getAuthenticatorData === "function", "Use a current browser that exposes WebAuthn ES256 public keys.");
  requireThat(response.getPublicKeyAlgorithm() === -7, "The authenticator did not create an ES256 passkey.");
  clientData(new Uint8Array(response.clientDataJSON), "webauthn.create", challenge);
  await authenticatorData(new Uint8Array(response.getAuthenticatorData()), true);
  const spki = response.getPublicKey();
  requireThat(spki !== null, "The browser did not supply the passkey public key.");
  const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const point = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  requireThat(point.length === 65 && point[0] === 4, "Unexpected ES256 public-key encoding.");
  const publicKey = hex(concat(Uint8Array.of(2 | (point[64] & 1)), point.subarray(1, 33)));
  const identity = validateIdentity({ public_key: publicKey, credential_id: hex(id) });
  setStatus("Passkey created. Deriving your receive address locally…");
  const wallet = await deriveWallet(publicKey);
  await acceptWallet(identity, wallet, "Use this passkey on this exact origin to log in again.");
  state.phase = "sync";
  await syncWallet();
}

async function assertion(challenge, expectedId) {
  checkContext();
  requireThat(typeof PublicKeyCredential !== "undefined" && navigator.credentials?.get,
    "This browser does not support passkey authentication.");
  const publicKey = { rpId: RP_ID, challenge, userVerification: "required", timeout: 60000 };
  if (expectedId) publicKey.allowCredentials = [{ type: "public-key", id: expectedId }];
  const credential = await navigator.credentials.get({ publicKey, signal: signal() });
  checkContext();
  const id = credentialBytes(credential);
  requireThat(!expectedId || equal(id, expectedId), "The authenticator returned a different credential.");
  const response = credential.response;
  const auth = new Uint8Array(response.authenticatorData);
  const json = new Uint8Array(response.clientDataJSON);
  const signature = new Uint8Array(response.signature);
  clientData(json, "webauthn.get", challenge);
  await authenticatorData(auth);
  requireThat(signature.length >= 8 && signature.length <= 72, "Unsupported ES256 signature length.");
  checkContext();
  return { credential_id: hex(id), authenticator_data: hex(auth), client_data_json: hex(json), signature: hex(signature) };
}

async function restorePasskey() {
  checkContext();
  requireThat(!state.identity, "Log out before opening another wallet.");
  resetNewWalletOffer();
  state.phase = "restoring";
  const nonce = hex(crypto.getRandomValues(new Uint8Array(32)));
  const result = object(await walletCall("restore_challenges", state.context, { nonce }, signal()), "Restoration challenges");
  requireThat(Object.keys(result).length === 1 && Array.isArray(result.challenges)
    && result.challenges.length === 2, "The wallet must return exactly two restoration challenges.");
  const challenges = result.challenges.map((value) => unhex(value, "Restoration challenge", 32));
  requireThat(!equal(challenges[0], challenges[1]), "Restoration requires two different challenges.");
  setStatus("Log in · 1 of 2: choose your passkey. No transaction is signed.");
  let first;
  try {
    first = await assertion(challenges[0]);
  } catch (error) {
    if (error?.name !== "NotAllowedError" || signal().aborted || state.credentialCreated) throw error;
    await closeWalletModule();
    checkContext();
    $("new-wallet-note").textContent = "No passkey was selected. Your browser cannot tell us whether you cancelled or have no passkey. Try logging in again, or create a new wallet if you are new here. A new passkey opens a different wallet.";
    $("new-wallet-panel").hidden = false;
    setStatus("No passkey selected. Try again, or create a new wallet.");
    return;
  }
  const id = unhex(first.credential_id, "Passkey credential ID", undefined, 1024);
  setStatus("Log in · 2 of 2: approve the same passkey again. No transaction is signed.");
  const second = await assertion(challenges[1], id);
  setStatus("Opening your wallet…");
  const identity = validateIdentity(await walletCall("restore", state.context, { nonce, assertions: [first, second] }, signal()));
  requireThat(identity.credential_id === first.credential_id, "The restored identity does not match the selected passkey.");
  const wallet = await deriveWallet(identity.public_key);
  await acceptWallet(identity, wallet, "Logged in with two approvals. No transaction was signed.");
  state.phase = "sync";
  await syncWallet();
}

function checkRequest(request, proposal, inputIndex) {
  const envelope = object(object(request, "Signing request").SignProgramV1, "Signing envelope");
  requireThat(envelope.input_index === inputIndex, "Signing request changed the approved input index.");
  const bytes = Uint8Array.from(atob(proposal.psbt), (char) => char.charCodeAt(0));
  const framed = envelope.psbt;
  requireThat(Array.isArray(framed) && framed.length === bytes.length + 4
    && framed.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255), "Invalid signing PSBT envelope.");
  requireThat(new DataView(Uint8Array.from(framed.slice(0, 4)).buffer).getUint32(0, false) === bytes.length
    && bytes.every((byte, index) => byte === framed[index + 4]), "Signing request changed the reviewed unsigned PSBT.");
}

async function sendPayment() {
  checkContext();
  const { identity, review } = state;
  requireThat(identity && review && !state.result, "Review a payment before approving and sending it.");
  state.phase = "signing";
  setStatus("Rechecking every selected output before asking for passkey approval…");
  for (const funding of review.proposal.summary.funding) {
    const status = await chainGet(`tx/${funding.txid}/outspend/${funding.vout}`, "Selected output spentness");
    requireThat(typeof status.spent === "boolean", "The indexer returned invalid spentness information.");
    if (status.spent && (!review.proposal.summary.replaces || status.txid !== review.proposal.summary.replaces)) {
      invalidateReview();
      state.syncReady = false;
      throw new Error("A selected output was spent by another transaction. Refresh and review again; nothing was signed. A replacement may spend only inputs spent by its exact original transaction.");
    }
  }
  // Freeze the payment, not the authorization: each attempt uses a fresh nonce.
  const nonce = hex(crypto.getRandomValues(new Uint8Array(32)));
  const proposal = object(await walletCall("reauthorize", state.context, { psbt: review.proposal.psbt, nonce }, signal()), "Fresh authorization");
  await validateProposal(proposal, nonce);
  for (const field of ["parameters", "address", "program_id", "psbt"]) {
    requireThat(proposal[field] === review.proposal[field], "The payment changed after review. Refresh and review again; nothing was signed.");
  }
  requireThat(JSON.stringify(proposal.views) === JSON.stringify(review.proposal.views)
    && JSON.stringify(proposal.summary) === JSON.stringify(review.proposal.summary), "The input views or payment summary changed after review. Nothing was signed.");
  const credentialId = unhex(identity.credential_id, "Passkey credential ID", undefined, 1024);
  const responses = [];
  let firstRequest;
  for (let inputIndex = 0; inputIndex < proposal.summary.input_count; inputIndex++) {
    setStatus(`Approve & sign · passkey approval ${inputIndex + 1}/${proposal.summary.input_count} for the reviewed transaction…`);
    const proof = await assertion(unhex(proposal.challenges[inputIndex], "Passkey challenge", 32), credentialId);
    const request = await walletCall("request", state.context, {
      public_key: identity.public_key, psbt: proposal.psbt, nonce: proposal.nonce, input_index: inputIndex,
      authenticator_data: proof.authenticator_data, client_data_json: proof.client_data_json, signature: proof.signature,
    }, signal());
    checkRequest(request, proposal, inputIndex);
    const options = jsonBody(request);
    checkContext();
    if (inputIndex === 0) firstRequest = request;
    setStatus(`Passkey approved · requesting signer response ${inputIndex + 1}/${proposal.summary.input_count}…`);
    state.requestSent = true;
    responses.push(await fetchJson(state.signUrl, "Signing endpoint", options));
  }
  setStatus("Verifying all signatures and finalizing the reviewed transaction locally in WASM…");
  checkContext();
  const result = object(await walletCall("finalize_passkey", state.context, { request: firstRequest, responses }), "Finalized transaction");
  requireThat(result.txid === review.proposal.summary.txid && result.fee_sats === review.proposal.summary.fee_sats,
    "Finalized transaction does not match the reviewed transaction and fee.");
  unhex(result.transaction_hex, "Finalized transaction bytes", undefined, MAX_JSON / 2);
  requireThat(typeof result.signed_psbt === "string" && result.signed_psbt.length <= MAX_JSON, "Invalid signed PSBT.");
  state.result = freeze(result);
  state.resultStatus = "ready";
  renderResult();
  invalidateReview();
  applySnapshot(await walletCall("snapshot", state.context));
  await savePublicState();
  setStatus("Transaction signed and reserved locally. Inspect its bytes, then explicitly choose Broadcast signed transaction.");
  $("result-heading").focus();
}

async function broadcastTransaction() {
  checkContext();
  const result = state.result;
  requireThat(result && ["ready", "uncertain", "submitted"].includes(resultState()), "There is no finalized transaction waiting for broadcast.");
  state.phase = "broadcast";
  state.resultStatus = "broadcasting";
  renderResult();
  setStatus("Submitting the exact verified transaction once. Cancellation cannot recall a submitted transaction…");
  try {
    const returnedTxid = await fetchResponse(`${state.chainUrl}/tx`, "Broadcast endpoint", {
      method: "POST", headers: { "Content-Type": "text/plain", Accept: "text/plain" }, body: result.transaction_hex,
    }, async (response, requestSignal) => {
      const text = await readText(response, "Broadcast endpoint", requestSignal, 4096);
      requireThat(response.ok, `Broadcast endpoint returned HTTP ${response.status}; the network outcome remains uncertain.`);
      return text.trim();
    });
    requireThat(returnedTxid === result.txid, "The broadcast response did not return the exact locally verified transaction ID.");
    checkContext();
    state.resultStatus = "submitted";
    applySnapshot(await walletCall("broadcast_result", state.context, { txid: result.txid, status: "accepted" }));
    renderResult();
    await savePublicState();
    $("result-heading").focus();
  } catch (error) {
    state.resultStatus = "uncertain";
    renderResult();
    try {
      applySnapshot(await walletCall("broadcast_result", state.context, { txid: result.txid, status: "uncertain" }));
      await savePublicState();
    } catch (recordError) {
      cacheWarning(`The broadcast outcome could not be recorded: ${explainError(recordError)} Exact signed bytes remain below.`);
    }
    throw error;
  }
  try {
    await syncWallet();
    setStatus("The endpoint returned the transaction ID. History refreshed; only an indexer-reported block anchor indicates confirmation.");
  } catch (error) {
    showError(`The endpoint returned the transaction ID, but the history refresh stopped: ${explainError(error)} This is not proof of mempool acceptance or confirmation. Exact signed bytes remain available.`);
    setStatus("Transaction submitted. History refresh incomplete; inspect the retained result below.");
  }
}

function resultState() {
  const history = state.snapshot?.transactions.find((tx) => tx.txid === state.result?.txid);
  return history && ["confirmed", "replaced"].includes(history.status) ? history.status : state.resultStatus;
}

function renderResult() {
  $("result").hidden = !state.result;
  if (!state.result) return;
  $("result-txid").value = state.result.txid;
  $("transaction-hex").value = state.result.transaction_hex;
  $("signed-psbt").value = state.result.signed_psbt;
  $("signed-psbt-field").hidden = !state.result.signed_psbt;
  const status = resultState();
  const messages = {
    ready: ["Signed · awaiting broadcast", "WASM verified every signature and finalized this exact transaction. This tab has not submitted it yet. You can explicitly broadcast these same bytes."],
    broadcasting: ["Broadcast in progress", "The exact signed transaction is being submitted. Cancelling stops this tab’s wait, not a transaction already received by the indexer."],
    uncertain: ["Broadcast outcome uncertain", "This transaction may already have been submitted, including before a reload, rejection, timeout or cancellation. Check its ID; retry submits only the same signed bytes, without signing again."],
    submitted: ["Submitted · confirmation not observed", "The endpoint returned the exact transaction ID verified locally by WASM. A returned ID is not proof of mempool acceptance or confirmation. Refresh history or inspect the explorer for indexer-reported evidence."],
    confirmed: ["Confirmed · indexer-reported", "BDK reports a block anchor for this transaction in the indexer's chain view. The history below shows its confirmation count. This is not SPV verification and a reorganization can change its status."],
    replaced: ["Replaced / conflicted · wallet view", "The wallet knows a conflicting or replacement transaction. Unconfirmed conflicts can change. These signed bytes are retained for inspection, but this page will not rebroadcast them. See history for the conflicting transaction ID."],
  };
  const [heading, note] = messages[status];
  $("result-heading").textContent = heading;
  $("result-note").textContent = note;
  $("broadcast-warning").hidden = ["confirmed", "replaced"].includes(status);
  $("result").classList.toggle("uncertain", status === "uncertain");
  $("retry-broadcast").hidden = !["ready", "uncertain", "submitted"].includes(status);
  $("retry-broadcast").textContent = status === "ready" ? "Broadcast signed transaction" : "Retry broadcast · same transaction";
  $("discard-result").hidden = status === "broadcasting";
  $("explorer-link").hidden = state.chain !== "mutinynet";
  if (state.chain === "mutinynet") $("explorer-link").href = `https://mutinynet.com/tx/${state.result.txid}`;
}

function clearResult() {
  state.result = null;
  state.resultStatus = null;
  $("result").hidden = true;
  $("result-details").open = false;
  for (const id of ["result-txid", "transaction-hex", "signed-psbt"]) $(id).value = "";
  $("explorer-link").removeAttribute("href");
}

function invalidateReview() {
  state.review = null;
  $("review-details").hidden = true;
  $("review").hidden = true;
  $("send-payment").textContent = "Approve & sign";
}

function renderControls() {
  const locked = state.busy || !!hasPendingResult();
  $("create-passkey").disabled = state.busy || !state.config || !!state.identity;
  $("login-passkey").disabled = state.busy || !state.config || !!state.identity;
  $("refresh-balance").disabled = state.busy || !state.wallet;
  $("copy-address").disabled = state.busy || !state.wallet;
  for (const id of ["recipient", "fee-rate", "send-max", "bump-fee-rate"]) $(id).disabled = locked || !state.wallet;
  $("amount-sats").disabled = locked || !state.wallet || state.sendMax;
  $("amount-sats").required = !state.sendMax;
  $("send-max").setAttribute("aria-pressed", String(state.sendMax));
  $("send-max").textContent = state.sendMax ? "Use specific amount" : "Send max";
  $("amount-note").textContent = state.sendMax ? "Send all eligible confirmed funds minus the exact reviewed fee. BDK's 16-input limit still applies." : "Whole satoshis. The network fee is added to this amount.";
  $("review-payment").disabled = locked || !state.syncReady;
  $("review-bump").disabled = locked || !state.syncReady || !state.bumpTxid;
  $("cancel-bump").disabled = state.busy;
  $("send-payment").disabled = locked || !state.review || !!state.result;
  $("retry-broadcast").disabled = state.busy || !["ready", "uncertain", "submitted"].includes(resultState());
  $("discard-result").disabled = state.busy;
  $("log-out").hidden = !state.identity;
  $("log-out").disabled = state.busy || !state.identity;
  $("history-more").disabled = state.busy;
  document.querySelectorAll("[data-bump]").forEach((button) => { button.disabled = locked || !state.syncReady; });
  document.querySelectorAll("[data-outbox]").forEach((button) => {
    button.disabled = state.busy || (!!hasPendingResult() && state.result.txid !== button.dataset.outbox);
  });
  $("cancel-operation").hidden = !state.busy;
  $("cancel-operation").disabled = state.controller?.signal.aborted ?? false;
  $("wallet-app").setAttribute("aria-busy", String(state.busy));
}

function explainError(error) {
  if (error?.name === "AbortError") return "Operation cancelled locally.";
  if (error?.name === "TimeoutError") return "The operation timed out.";
  if (error?.name === "NotAllowedError") return "Passkey approval was cancelled, timed out, or user verification was unavailable. Unlock your authenticator and try again.";
  if (error?.name === "SecurityError") return `WebAuthn rejected this context. Open exactly ${ORIGIN} in a top-level browser tab.`;
  if (error?.name === "NotSupportedError") return "This authenticator does not support the required discoverable ES256 passkey or user verification. Use a supported authenticator.";
  if (error instanceof TypeError && /fetch|network|load failed/i.test(error.message)) return "Could not reach a static asset or the pinned HTTPS API. Check connectivity and the gateway's exact frontend-origin CORS configuration.";
  return error instanceof Error ? error.message : "The operation failed.";
}

async function run(label, operation, deadline = 90000) {
  if (state.busy) return;
  state.busy = true;
  const controller = new AbortController();
  state.controller = controller;
  state.requestSent = false;
  state.phase = null;
  const timeout = setTimeout(() => controller.abort(new DOMException("Operation timed out.", "TimeoutError")), deadline);
  $("error").hidden = true;
  $("error").textContent = "";
  setStatus(label);
  renderControls();
  try { await operation(); }
  catch (error) {
    let message = explainError(controller.signal.aborted ? controller.signal.reason : error);
    if (state.resultStatus === "uncertain") {
      message += " Broadcast outcome is uncertain: this transaction may already be on the network. Its verified bytes and transaction ID are retained below. Retry broadcast only resubmits this same transaction; nothing is retried automatically.";
    } else if (state.resultStatus === "ready") {
      message += " The signed transaction is retained below and has not been submitted by this tab. Use Broadcast signed transaction to submit those exact bytes.";
    } else if (state.phase === "signing") {
      message += state.requestSent
        ? " A signer request may have completed, but this tab did not broadcast. Partial responses are discarded; retrying starts all approvals with a fresh nonce. No request is retried automatically."
        : " This tab did not broadcast. A new signing attempt requires fresh passkey approvals.";
    } else if (state.phase === "restoring" && !state.identity) {
      message += " No wallet was opened and no transaction was signed. Log in again to retry both approvals.";
    } else if (state.phase === "sync" || (state.wallet && operation === syncWallet)) {
      message += " Your wallet and receive address remain open. No payment was initiated by this refresh.";
    }
    if (state.credentialCreated && !state.identity) message += " A passkey may remain in your authenticator. Log in with that passkey to finish opening your wallet; do not create another.";
    if (!state.config) message += " Reload this page to load its configuration again.";
    if (!state.identity) {
      await closeWalletModule();
      state.releaseLock?.();
      state.releaseLock = null;
      state.wallet = null;
      state.snapshot = null;
      state.cacheKey = null;
    }
    showError(message);
    setStatus("Operation stopped. See the message below.");
  } finally {
    clearTimeout(timeout);
    state.busy = false;
    state.controller = null;
    state.phase = null;
    renderControls();
  }
}

$("create-passkey").addEventListener("click", () => run("Waiting for a new passkey with user verification…", createPasskey, 240000));
$("login-passkey").addEventListener("click", () => run("Preparing passkey login…", restorePasskey, 330000));
$("refresh-balance").addEventListener("click", () => run("Refreshing wallet history…", syncWallet, 180000));
$("payment-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run("Preparing a payment locally from verified funding…", reviewPayment);
});
$("send-payment").addEventListener("click", () => run("Rechecking the reviewed payment before approval…", sendPayment,
  180000 + (state.review?.proposal.summary.input_count ?? 1) * 90000));
$("retry-broadcast").addEventListener("click", () => run("Retrying only the same finalized transaction…", broadcastTransaction, 240000));
for (const id of ["recipient", "amount-sats", "fee-rate", "bump-fee-rate"]) $(id).addEventListener("input", () => {
  if (state.busy || hasPendingResult()) return;
  if (id === "fee-rate") state.feeEdited = true;
  invalidateReview();
  setStatus("Payment edited. Review again before approving and signing.");
  renderControls();
});
$("send-max").addEventListener("click", () => {
  if (state.busy || hasPendingResult()) return;
  state.sendMax = !state.sendMax;
  invalidateReview();
  renderControls();
  setStatus(state.sendMax ? "Send max selected. Review to see the exact recipient amount after fees." : "Enter a specific whole-satoshi amount.");
});
$("bump-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run("Building a BDK fee replacement with the original recipient unchanged…", reviewBump);
});
$("cancel-bump").addEventListener("click", () => {
  if (state.busy) return;
  state.bumpTxid = null;
  invalidateReview();
  $("bump-panel").hidden = true;
  $("payment-panel").hidden = false;
  renderControls();
  setStatus("Fee replacement review dismissed. The original transaction was not cancelled.");
});
$("history-more").addEventListener("click", () => {
  if (state.busy) return;
  state.historyLimit += 25;
  renderHistory();
  renderControls();
});
$("copy-address").addEventListener("click", () => run("Copying your receive address…", async () => {
  checkContext();
  requireThat(state.wallet, "Open your wallet first.");
  try {
    requireThat(navigator.clipboard?.writeText, "Clipboard unavailable.");
    await navigator.clipboard.writeText(state.wallet.address);
    checkContext();
    setStatus("Receive address copied. Check the pasted address before sending test coins.");
  } catch (error) {
    if (signal().aborted) throw error;
    $("receive-address").focus();
    $("receive-address").select();
    setStatus("Clipboard unavailable. The address is selected; copy it using your browser’s Copy action.");
  }
}));
$("cancel-operation").addEventListener("click", () => {
  state.controller?.abort();
  setStatus(state.resultStatus === "broadcasting"
    ? "Cancelling the local wait. The transaction may already have been submitted…"
    : state.phase === "sync" ? "Cancellation requested. Waiting for BDK's in-flight sync to settle safely; the wallet remains locked meanwhile…" : "Cancelling this operation locally…");
  renderControls();
});
$("discard-result").addEventListener("click", () => {
  if (state.busy || !state.result) return;
  if (!window.confirm("Dismissing this result cannot cancel a broadcast or release its reserved inputs. Save its transaction ID or signed bytes first if needed. Known outgoing transactions remain in wallet history. Dismiss the result and refresh before another payment?")) return;
  run("Dismissing the displayed result, not cancelling the transaction…", async () => {
    applySnapshot(await walletCall("discard_result", state.context, { txid: state.result.txid }, signal()));
    clearResult();
    invalidateReview();
    state.syncReady = false;
    await savePublicState();
    setStatus("Result dismissed. Known outgoing transactions and input reservations remain. Refresh history before reviewing another payment.");
  });
});
$("log-out").addEventListener("click", async () => {
  if (state.busy) return;
  if (hasPendingResult() && !window.confirm("Log out with a pending signed transaction? Signed bytes are saved only if browser storage succeeded. Logging out cannot cancel a transaction already submitted. Save its ID or bytes if needed.")) return;
  await run("Logging out…", async () => {
    await closeWalletModule();
    state.releaseLock?.();
    state.releaseLock = null;
    state.identity = null;
    state.wallet = null;
    state.snapshot = null;
    state.cacheKey = null;
    state.syncReady = false;
    state.feeEdited = false;
    state.sendMax = false;
    state.bumpTxid = null;
    state.historyLimit = 25;
    state.credentialCreated = false;
    state.requestSent = false;
    resetNewWalletOffer();
    invalidateReview();
    clearResult();
    $("passkey-panel").hidden = false;
    for (const id of ["wallet-panel", "payment-panel", "bump-panel", "history-panel"]) $(id).hidden = true;
    renderHistory();
    for (const id of ["cache-warning", "error"]) {
      $(id).textContent = "";
      $(id).hidden = true;
    }
    for (const id of ["balance-confirmed", "balance-pending", "balance-immature", "balance-spendable",
      "sync-note", "bump-txid", "review-recipient", "review-amount", "review-fee", "review-size",
      "review-total", "review-change", "review-change-address", "review-inputs", "review-txid",
      "review-replaces", "result-note"]) $(id).textContent = "";
    $("review-funding").replaceChildren();
    $("bump-fee-rate").value = "1";
    $("receive-address").value = "";
    $("recipient").value = "";
    $("amount-sats").value = "";
    $("fee-rate").value = "1";
    $("fee-note").textContent = "Manual starting rate: 1 sat/vB. Refresh asks the indexer for an editable suggestion.";
    $("passkey-note").textContent = "Use your passkey to log in. New here? Start with Log in with passkey.";
    setStatus("Logged out. Your passkey and saved history are kept.");
  });
  if (!state.identity) $("login-passkey").focus();
});

window.addEventListener("beforeunload", (event) => {
  if (state.busy || hasPendingResult()) {
    event.preventDefault();
    event.returnValue = "";
  }
});

run("Loading the pinned static configuration…", async () => {
  requireThat((location.protocol === "https:" || (location.protocol === "http:" && RP_ID === "localhost"))
    && window.isSecureContext && window.top === window.self, "Open this page in a top-level secure tab. HTTPS is required except explicitly configured localhost development.");
  requireThat(crypto.subtle && crypto.getRandomValues && typeof WebAssembly !== "undefined", "This wallet requires WebCrypto, WebAssembly, and WebAuthn.");
  requireThat(navigator.locks?.request, "This wallet requires Web Locks to prevent conflicting tabs. Use a current secure-context browser.");
  await loadConfiguration();
  setStatus("Ready to log in.");
});
