// The page itself (unlock.js), run against a small double of the DOM and of
// WebAuthn: no browser, no passkey.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64urlEncode, b64urlDecode, confirmationCode } from "../unlock-core.js";

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
async function page({ hash = "", query = "", framed = false, x25519 = true, webauthn = {}, opener = null } = {}) {
  const els = {};
  const went = [], replaced = [], listeners = [], closed = [];
  const self = {};
  globalThis.window = { self, top: framed ? {} : self, opener, addEventListener: (type, f) => listeners.push([type, f]),
                        close: () => closed.push(true) };
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
  const send = async (data, { origin = "https://opensheaf.org", source = opener } = {}) => {
    for (const [type, f] of listeners) if (type === "message") await f({ data, origin, source });
    await new Promise((r) => setTimeout(r, 5));
  };
  return { els, went, replaced, send, closed };
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

// The popup of the OpenSheaf manager: a double of the manager's window, which
// receives what the page posts, with the target origin.
function managerWindow() {
  const posted = [];
  return { posted, postMessage: (message, targetOrigin) => posted.push({ message, targetOrigin }) };
}

const POPUP_HASH = "#mode=popup&origin=" + encodeURIComponent("https://opensheaf.org");

test("a popup: ready, the request of its opener only, then WebAuthn and the answer to the opener's origin", async () => {
  const subtle = globalThis.crypto.subtle;
  const mine = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const myPk = b64urlEncode(new Uint8Array(await subtle.exportKey("raw", mine.publicKey)));
  const calls = [];
  const assertion = { rawId: new Uint8Array(20).fill(7).buffer,
                      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(9).buffer } } }) };
  const opener = managerWindow();
  const p = await page({ hash: POPUP_HASH, opener, webauthn: { get: async (o) => { calls.push(o); return assertion; } } });
  assert.deepEqual(p.replaced, ["/"]);
  assert.deepEqual(opener.posted, [{ message: { type: "opensheaf-unlock-ready" }, targetOrigin: "https://opensheaf.org" }]);
  const request = { type: "opensheaf-unlock-request", state, pk: myPk, owner, cred };
  await p.send(request, { origin: "https://evil.example" });
  await p.send(request, { source: {} });
  assert.ok(!p.els.request || p.els.request.hidden);
  await p.send(request);
  assert.equal(p.els.request.hidden, false);
  assert.equal(p.els.go.disabled, false);
  assert.equal(p.els["same-box"].hidden, true);
  assert.match(p.els.who.textContent, /manager \(https:\/\/opensheaf\.org\)/);
  const code = await confirmationCode(state, b64urlDecode(myPk));
  assert.equal(p.els.code.textContent, code);
  await p.send({ ...request, state: "another-state-of-the-tests" });
  assert.equal(p.els.code.textContent, code);
  await p.els.go.onclick();
  await settle();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].publicKey.rpId, "unlock.opensheaf.org");
  assert.equal(opener.posted.length, 2);
  const { message, targetOrigin } = opener.posted[1];
  assert.equal(targetOrigin, "https://opensheaf.org");
  assert.deepEqual(Object.keys(message).sort(), ["cred", "ct", "epk", "state", "tag", "type"]);
  assert.equal(message.type, "opensheaf-unlock-answer");
  assert.equal(message.cred, cred);
  // the manager's side: its private key opens the answer, sealed with the mode popup
  const peer = await subtle.importKey("raw", b64urlDecode(message.epk), { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: peer }, mine.privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const both = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256",
    salt: new TextEncoder().encode(state), info: new TextEncoder().encode("opensheaf unlock hand-off v2") }, ikm, 512));
  const ct = b64urlDecode(message.ct);
  assert.deepEqual(Uint8Array.from(ct, (b, i) => b ^ both[i]), new Uint8Array(32).fill(9));
  const mac = await subtle.importKey("raw", both.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const aad = new TextEncoder().encode(`popup|${owner}|${cred}|${myPk}|${message.epk}`);
  assert.ok(await subtle.verify("HMAC", mac, b64urlDecode(message.tag), new Uint8Array([...aad, ...ct])));
  assert.deepEqual(p.went, []);
  assert.deepEqual(p.closed, []);
  await p.send({ type: "opensheaf-unlock-done" }, { origin: "https://evil.example" });
  assert.deepEqual(p.closed, []);
  await p.send({ type: "opensheaf-unlock-done" });
  assert.deepEqual(p.closed, [true]);
});

test("a popup without its opener, or for a page not on the list, does nothing", async () => {
  const p = await page({ hash: POPUP_HASH });
  assert.match(p.els.status.textContent, /not by it/);
  const opener = managerWindow();
  const q = await page({ hash: "#mode=popup&origin=" + encodeURIComponent("https://evil.example"), opener });
  assert.match(q.els.status.textContent, /not a page that may ask/);
  assert.deepEqual(opener.posted, []);
});

test("a popup cancelled tells its opener, and closes", async () => {
  const opener = managerWindow();
  const p = await page({ hash: POPUP_HASH, opener, webauthn: { get: () => assert.fail() } });
  await p.send({ type: "opensheaf-unlock-request", state, pk, owner, cred });
  p.els.cancel.onclick();
  assert.deepEqual(opener.posted[1], { message: { type: "opensheaf-unlock-answer", state, error: "the user did not unlock" },
                                       targetOrigin: "https://opensheaf.org" });
  assert.deepEqual(p.closed, [true]);
});
