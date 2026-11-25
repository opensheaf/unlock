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
  const send = async (data, { origin = "https://manager.opensheaf.org", source = opener } = {}) => {
    for (const [type, f] of listeners) if (type === "message") await f({ data, origin, source });
    await new Promise((r) => setTimeout(r, 5));
  };
  const hide = () => { for (const [type, f] of listeners) if (type === "pagehide") f({}); };
  return { els, went, replaced, send, closed, hide };
}

const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((r) => setTimeout(r, 1)); };
const request = (o) => "#" + new URLSearchParams({ mode: "unlock", port: "49992", state, pk, owner, cred, ...o }).toString();

test("the request leaves the address at once", async () => {
  const p = await page({ hash: request() });
  assert.deepEqual(p.replaced, ["/"]);
  assert.equal(p.els.request.hidden, false);
  assert.equal(p.els.code.textContent, await confirmationCode(state, Uint8Array.from(atob(pk.replace(/-/g, "+").replace(/_/g, "/") + "="), (c) => c.charCodeAt(0))));
  assert.equal(p.els.port.textContent, "49992");   // the port the secret would go to, shown
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

test("enroll: the owner's passkeys are excluded, and PRF must be there, said at creation or at the assertion", async () => {
  const created = [], asserted = [];
  const make = (enabled) => async (o) => {
    created.push(o);
    return { rawId: new Uint8Array(20).fill(8).buffer, getClientExtensionResults: () => ({ prf: enabled }) };
  };
  const noSecret = async (o) => { asserted.push(o); return { rawId: new Uint8Array(20).fill(8).buffer, getClientExtensionResults: () => ({}) }; };
  // PRF said to be off at creation: no assertion
  const off = await page({ hash: request({ mode: "enroll" }), webauthn: { create: make({ enabled: false }), get: () => assert.fail() } });
  off.els.same.checked = true;
  await off.els.go.onclick();
  await settle();
  assert.match(off.els.status.textContent, /does not support the PRF extension.*Safari 18/);
  assert.deepEqual(off.went, []);
  // not said at creation: the assertion is tried, and tells
  for (const prf of [undefined, {}]) {
    const p = await page({ hash: request({ mode: "enroll" }), webauthn: { create: make(prf), get: noSecret } });
    p.els.same.checked = true;
    await p.els.go.onclick();
    await settle();
    assert.match(p.els.status.textContent, /the passkey was made, but this browser or passkey gave no PRF secret \(.*Safari 18/);
    assert.deepEqual(p.went, []);
  }
  assert.equal(asserted.length, 2);
  const yes = await page({ hash: request({ mode: "enroll" }), webauthn: { create: make(undefined),
    get: async () => ({ rawId: new Uint8Array(20).fill(8).buffer,
                        getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(3).buffer } } }) }) } });
  yes.els.same.checked = true;
  await yes.els.go.onclick();
  await settle();
  assert.equal(yes.went.length, 1);
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

const MANAGER = "https://manager.opensheaf.org";
const POPUP_HASH = "#mode=popup&origin=" + encodeURIComponent(MANAGER);

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
  assert.deepEqual(opener.posted, [{ message: { type: "opensheaf-unlock-ready" }, targetOrigin: MANAGER }]);
  const request = { type: "opensheaf-unlock-request", state, pk: myPk, owner, cred };
  await p.send(request, { origin: "https://evil.example" });
  await p.send(request, { source: {} });
  assert.ok(!p.els.request || p.els.request.hidden);
  await p.send(request);
  assert.equal(p.els.request.hidden, false);
  assert.equal(p.els.go.disabled, false);
  assert.equal(p.els["same-box"].hidden, true);
  assert.match(p.els.who.textContent, /manager \(https:\/\/manager\.opensheaf\.org\)/);
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
  assert.equal(targetOrigin, MANAGER);
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
                                       targetOrigin: MANAGER });
  assert.deepEqual(p.closed, [true]);
});

// The answer of a popup, opened as the manager opens it: returns the secret,
// or throws if the tag is not that of MODE.
async function openAnswer(mine, myPk, message, mode) {
  const subtle = globalThis.crypto.subtle;
  const peer = await subtle.importKey("raw", b64urlDecode(message.epk), { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: peer }, mine.privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const both = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256",
    salt: new TextEncoder().encode(state), info: new TextEncoder().encode("opensheaf unlock hand-off v2") }, ikm, 512));
  const ct = b64urlDecode(message.ct);
  const mac = await subtle.importKey("raw", both.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const aad = new TextEncoder().encode(`${mode}|${owner}|${message.cred}|${myPk}|${message.epk}`);
  if (!(await subtle.verify("HMAC", mac, b64urlDecode(message.tag), new Uint8Array([...aad, ...ct])))) throw new Error("tag");
  return Uint8Array.from(ct, (b, i) => b ^ both[i]);
}

test("a popup that enrolls: a new passkey, its passkeys excluded, its secret sealed with the mode popup-enroll", async () => {
  const subtle = globalThis.crypto.subtle;
  const mine = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const myPk = b64urlEncode(new Uint8Array(await subtle.exportKey("raw", mine.publicKey)));
  const made = [], asked = [];
  const fresh = new Uint8Array(24).fill(5);
  const webauthn = {
    create: async (o) => { made.push(o); return { rawId: fresh.buffer, getClientExtensionResults: () => ({ prf: { enabled: true } }) }; },
    get: async (o) => { asked.push(o); return { rawId: fresh.buffer,
      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(4).buffer } } }) }; },
  };
  const opener = managerWindow();
  const p = await page({ hash: "#mode=popup-enroll&origin=" + encodeURIComponent(MANAGER), opener, webauthn });
  assert.deepEqual(opener.posted, [{ message: { type: "opensheaf-unlock-ready" }, targetOrigin: MANAGER }]);
  await p.send({ type: "opensheaf-unlock-request", state, pk: myPk, owner, cred });
  assert.equal(p.els.request.hidden, false);
  assert.equal(p.els.go.textContent, "Create the passkey");
  assert.match(p.els.what.textContent, /create a passkey for unlock\.opensheaf\.org/);
  await p.els.go.onclick();
  await settle();
  assert.equal(made.length, 1);
  assert.equal(made[0].publicKey.rp.id, "unlock.opensheaf.org");
  assert.deepEqual(made[0].publicKey.excludeCredentials.map((c) => b64urlEncode(c.id)), [cred]);
  assert.equal(asked.length, 1);
  assert.deepEqual(asked[0].publicKey.allowCredentials.map((c) => b64urlEncode(c.id)), [b64urlEncode(fresh)]);
  const { message, targetOrigin } = opener.posted[1];
  assert.equal(targetOrigin, MANAGER);
  assert.equal(message.cred, b64urlEncode(fresh));
  assert.deepEqual(await openAnswer(mine, myPk, message, "popup-enroll"), new Uint8Array(32).fill(4));
  await assert.rejects(openAnswer(mine, myPk, message, "popup"), /tag/);
  await assert.rejects(openAnswer(mine, myPk, message, "enroll"), /tag/);
  assert.deepEqual(p.went, []);
  await p.send({ type: "opensheaf-unlock-done" });
  assert.deepEqual(p.closed, [true]);
});

test("a popup that enrolls takes a request with no passkey to exclude; cancelled, it says so", async () => {
  const opener = managerWindow();
  const p = await page({ hash: "#mode=popup-enroll&origin=" + encodeURIComponent(MANAGER), opener,
                         webauthn: { create: () => assert.fail(), get: () => assert.fail() } });
  await p.send({ type: "opensheaf-unlock-request", state, pk, owner, cred: "" });
  assert.equal(p.els.request.hidden, false);
  p.els.cancel.onclick();
  assert.deepEqual(opener.posted[1], { message: { type: "opensheaf-unlock-answer", state, error: "the user did not create a passkey" },
                                       targetOrigin: MANAGER });
});

test("the old opener, opensheaf.org, may no longer open the popup", async () => {
  const opener = managerWindow();
  const p = await page({ hash: "#mode=popup&origin=" + encodeURIComponent("https://opensheaf.org"), opener });
  assert.match(p.els.status.textContent, /not a page that may ask/);
  assert.deepEqual(opener.posted, []);
});

test("a popup tells its opener what failed, and, closed after a failure, why", async () => {
  const opener = managerWindow();
  const webauthn = { create: async () => { const e = new Error("The operation either timed out or was not allowed.");
                                           e.name = "NotAllowedError"; throw e; }, get: () => assert.fail() };
  const p = await page({ hash: "#mode=popup-enroll&origin=" + encodeURIComponent(MANAGER), opener, webauthn });
  await p.send({ type: "opensheaf-unlock-request", state, pk, owner, cred: "" });
  await p.els.go.onclick();
  await settle();
  const error = "NotAllowedError: The operation either timed out or was not allowed.";
  assert.deepEqual(opener.posted[1], { message: { type: "opensheaf-unlock-status", state, error }, targetOrigin: MANAGER });
  assert.equal(p.els.go.disabled, false);
  p.hide();
  assert.deepEqual(opener.posted[2], { message: { type: "opensheaf-unlock-answer", state,
                                                  error: `the window was closed after: ${error}` }, targetOrigin: MANAGER });
  p.hide();
  assert.equal(opener.posted.length, 3);
});

test("a popup closed with no failure says only that; one that answered says nothing more", async () => {
  const opener = managerWindow();
  const p = await page({ hash: "#mode=popup-enroll&origin=" + encodeURIComponent(MANAGER), opener,
                         webauthn: { create: () => assert.fail(), get: () => assert.fail() } });
  await p.send({ type: "opensheaf-unlock-request", state, pk, owner, cred: "" });
  p.hide();
  assert.deepEqual(opener.posted[1].message, { type: "opensheaf-unlock-answer", state, error: "the window was closed" });
  const q = await page({ hash: "#mode=popup-enroll&origin=" + encodeURIComponent(MANAGER), opener: managerWindow(),
                         webauthn: { create: () => assert.fail(), get: () => assert.fail() } });
  await q.send({ type: "opensheaf-unlock-request", state, pk, owner, cred: "" });
  q.els.cancel.onclick();
  q.hide();
});

test("a popup of version 2: two owners, one assertion with both salts, a secret sealed for each", async () => {
  const subtle = globalThis.crypto.subtle;
  const owner2 = "b".repeat(51) + "a";
  const mine = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const myPk = b64urlEncode(new Uint8Array(await subtle.exportKey("raw", mine.publicKey)));
  const calls = [];
  const assertion = { rawId: new Uint8Array(20).fill(7).buffer,
                      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(9).buffer,
                                                                            second: new Uint8Array(32).fill(8).buffer } } }) };
  const opener = managerWindow();
  const p = await page({ hash: POPUP_HASH, opener, webauthn: { get: async (o) => { calls.push(o); return assertion; } } });
  await p.send({ type: "opensheaf-unlock-request", v: 2, state, pk: myPk, owners: `${owner},${owner2}`, cred });
  assert.equal(p.els.request.hidden, false);
  assert.match(p.els.owner.textContent, / and /);
  assert.match(p.els.what.textContent, /two owners/);
  await p.els.go.onclick();
  await settle();
  assert.equal(calls.length, 1);
  const salt = async (o) => new Uint8Array(await subtle.digest("SHA-256", new TextEncoder().encode("opensheaf wallet unlock v1 " + o)));
  assert.deepEqual(calls[0].publicKey.extensions.prf.eval, { first: await salt(owner), second: await salt(owner2) });
  const { message } = opener.posted[1];
  assert.deepEqual(Object.keys(message).sort(), ["cred", "sealed", "state", "type", "v"]);
  assert.equal(message.v, 2);
  assert.deepEqual(message.sealed.map((s) => s.owner), [owner, owner2]);
  const open = async (s, o) => {
    const peer = await subtle.importKey("raw", b64urlDecode(s.epk), { name: "X25519" }, false, []);
    const shared = await subtle.deriveBits({ name: "X25519", public: peer }, mine.privateKey, 256);
    const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    const both = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256",
      salt: new TextEncoder().encode(state), info: new TextEncoder().encode("opensheaf unlock hand-off v2") }, ikm, 512));
    const ct = b64urlDecode(s.ct);
    const mac = await subtle.importKey("raw", both.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const aad = new TextEncoder().encode(`popup|${o}|${message.cred}|${myPk}|${s.epk}`);
    if (!(await subtle.verify("HMAC", mac, b64urlDecode(s.tag), new Uint8Array([...aad, ...ct])))) throw new Error("tag");
    return Uint8Array.from(ct, (b, i) => b ^ both[i]);
  };
  assert.deepEqual(await open(message.sealed[0], owner), new Uint8Array(32).fill(9));
  assert.deepEqual(await open(message.sealed[1], owner2), new Uint8Array(32).fill(8));
  await assert.rejects(open(message.sealed[1], owner), /tag/);
});

test("a popup of version 2 whose passkey gives one secret only says so, and sends nothing", async () => {
  const owner2 = "b".repeat(51) + "a";
  const assertion = { rawId: new Uint8Array(20).fill(7).buffer,
                      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(9).buffer } } }) };
  const opener = managerWindow();
  const p = await page({ hash: POPUP_HASH, opener, webauthn: { get: async () => assertion } });
  await p.send({ type: "opensheaf-unlock-request", v: 2, state, pk, owners: `${owner},${owner2}`, cred });
  await p.els.go.onclick();
  await settle();
  assert.match(p.els.status.textContent, /one at a time/);
  assert.deepEqual(opener.posted.map((x) => x.message.type), ["opensheaf-unlock-ready", "opensheaf-unlock-status"]);
});
