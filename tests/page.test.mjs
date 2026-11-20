// The page itself (unlock.js), run against a small double of the DOM and of
// WebAuthn: no browser, no passkey.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64urlEncode, confirmationCode } from "../unlock-core.js";

const owner = "em4v3kp5btra7jlggxhvl5y6uluymzk2ezcdjg4pnptnk5tygora";
const state = "Zaz8C5ywR4VKbNOX7dQHUg";
const pk = "EDUGNAoWiXZye3oZT1uexqCDj6g-_pOiwL6N01HzQX0";
const cred = b64urlEncode(new Uint8Array(20).fill(7));
let n = 0;

function element(id) {
  return { id, hidden: id === "request" || id === "status" || id === "tell", disabled: id === "go", checked: false,
           textContent: "", title: "", className: "", children: id === "steps" ? [{}, {}, {}] : [] };
}

// Runs the page with the address HASH (and QUERY), in a frame or not; returns
// what it did.
async function page({ hash = "", query = "", framed = false, x25519 = true, webauthn = {} } = {}) {
  const els = {};
  const went = [], replaced = [];
  const self = {};
  globalThis.window = { self, top: framed ? {} : self };
  globalThis.document = { getElementById: (id) => (els[id] ||= element(id)) };
  globalThis.location = { hash, search: query, pathname: "/", replace: (u) => went.push(u) };
  globalThis.history = { replaceState: (_s, _t, u) => { replaced.push(u); globalThis.location.hash = ""; globalThis.location.search = ""; } };
  globalThis.PublicKeyCredential = function () {};
  const subtle = globalThis.crypto.subtle;
  const realGenerate = subtle.generateKey.bind(subtle);
  globalThis.__x25519 = x25519;
  Object.defineProperty(globalThis, "navigator", { value: { credentials: webauthn }, configurable: true });
  subtle.generateKey = (alg, ...rest) => (alg.name === "X25519" && !globalThis.__x25519)
    ? Promise.reject(new Error("no X25519")) : realGenerate(alg, ...rest);
  await import(`../unlock.js?case=${++n}`);
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 1));
  subtle.generateKey = realGenerate;
  return { els, went, replaced };
}

const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((r) => setTimeout(r, 1)); };
const request = (o) => "#" + new URLSearchParams({ mode: "unlock", port: "49992", state, pk, owner, cred, ...o }).toString();

test("the request leaves the address at once", async () => {
  const p = await page({ hash: request() });
  assert.deepEqual(p.replaced, ["/"]);
  assert.equal(p.els.request.hidden, false);
  assert.equal(p.els.code.textContent, await confirmationCode(state, Uint8Array.from(atob(pk.replace(/-/g, "+").replace(/_/g, "/") + "="), (c) => c.charCodeAt(0))));
  assert.deepEqual(p.went, []);
});

test("in a frame, the page does nothing", async () => {
  let called = false;
  const p = await page({ hash: request(), framed: true, webauthn: { get: () => { called = true; } } });
  assert.match(p.els.status.textContent, /inside another page/);
  assert.ok(!p.els.request || p.els.request.hidden);
  assert.deepEqual(p.went, []);
  assert.equal(called, false);
});

test("a request of an older osheaf, in the query, is refused", async () => {
  const p = await page({ query: "?mode=unlock&port=49992" });
  assert.match(p.els.status.textContent, /update osheaf/);
  assert.deepEqual(p.went, []);
});

test("without X25519, nothing goes to osheaf until a click", async () => {
  const p = await page({ hash: request(), x25519: false });
  assert.match(p.els.status.textContent, /X25519.*known to work/);
  assert.deepEqual(p.went, []);
  assert.equal(p.els.tell.hidden, false);
  p.els.tell.onclick();
  assert.equal(p.went.length, 1);
  assert.match(p.went[0], /^http:\/\/127\.0\.0\.1:49992\/callback\?state=.*&error=x25519-unavailable$/);
});

test("the button waits for the code to be checked; then WebAuthn, and the answer", async () => {
  const calls = [];
  const assertion = { rawId: new Uint8Array(20).fill(7).buffer,
                      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(9).buffer } } }) };
  const p = await page({ hash: request(), webauthn: { get: async (o) => { calls.push(o); return assertion; } } });
  assert.equal(p.els.go.disabled, true);
  await p.els.go.onclick();
  assert.equal(calls.length, 0);
  p.els.same.checked = true;
  p.els.same.onchange();
  assert.equal(p.els.go.disabled, false);
  await p.els.go.onclick();
  await settle();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].publicKey.rpId, "unlock.opensheaf.org");
  assert.equal(p.went.length, 1);
  assert.match(p.went[0], /^http:\/\/127\.0\.0\.1:49992\/callback\?state=[^&]+&epk=[^&]+&ct=[^&]+&tag=[^&]+&cred=/);
});

test("enroll: the owner's passkeys are excluded, and PRF must be enabled", async () => {
  const created = [];
  const make = (enabled) => async (o) => {
    created.push(o);
    return { rawId: new Uint8Array(20).fill(8).buffer, getClientExtensionResults: () => ({ prf: enabled }) };
  };
  for (const prf of [undefined, {}, { enabled: false }]) {
    const p = await page({ hash: request({ mode: "enroll" }), webauthn: { create: make(prf), get: () => assert.fail() } });
    p.els.same.checked = true;
    await p.els.go.onclick();
    await settle();
    assert.match(p.els.status.textContent, /PRF/);
    assert.deepEqual(p.went, []);
  }
  assert.equal(created[0].publicKey.excludeCredentials.length, 1);
  assert.equal(created[0].publicKey.rp.id, "unlock.opensheaf.org");
  const p = await page({ hash: request({ mode: "enroll" }), webauthn: {
    create: async () => { const e = new Error("excluded"); e.name = "InvalidStateError"; throw e; } } });
  p.els.same.checked = true;
  await p.els.go.onclick();
  await settle();
  assert.match(p.els.status.textContent, /holds a passkey of this owner already/);
  assert.deepEqual(p.went, []);
});
