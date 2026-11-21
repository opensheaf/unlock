import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { parseParams, expectedSalt, confirmationCode, callbackUrl, createOptions, getOptions, prfSecret,
         prfEnabled, prfSupported, answerUrl, seal, shortName, x25519Available, b64urlEncode, b64urlDecode,
         associatedData, RP_ID, parseRequest, openerAllowed, MESSAGES, POPUP_OPENERS } from "../unlock-core.js";

const owner = "em4v3kp5btra7jlggxhvl5y6uluymzk2ezcdjg4pnptnk5tygora";
const cred = b64urlEncode(new Uint8Array(20).fill(7));
const state = "Zaz8C5ywR4VKbNOX7dQHUg";
const pk = "EDUGNAoWiXZye3oZT1uexqCDj6g-_pOiwL6N01HzQX0";
const fragment = (o) => "#" + new URLSearchParams(o).toString();
const unlock = { mode: "unlock", port: "49992", state, pk, owner, cred };

// The test vector of the hand-off, the same as in tests/test_wallets.py of
// opensheaf-py (HAND_OFF), which plays the side of osheaf.
const HAND_OFF = {
  sk: "3MnQ1WVJ9j-gIHW04onidnPAdXBkj8Ex38awjc_xIFU", pk: "EDUGNAoWiXZye3oZT1uexqCDj6g-_pOiwL6N01HzQX0",
  esk: "XsIioGnOBETGr9GuOkvzh0s9Mnee8lz8KkfLHClLxGc", epk: "wz_hpV5NNJh92Eqb4TE6dA7IVbA2LrWBmV8GisGgjBE",
  state: "Zaz8C5ywR4VKbNOX7dQHUg", mode: "unlock",
  owner: "em4v3kp5btra7jlggxhvl5y6uluymzk2ezcdjg4pnptnk5tygora", cred: "ZmFrZS1wYXNza2V5LWNyZWRlbnRpYWw",
  secret: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  ct: "715olE38lfUKZdHslhzg2vWDWtGo88nSvuZNo4v-Hrc", tag: "2MlYwfCCb9AS4OVAMHXml-cxWi4HCPyd34BNYNVGeyU",
  code: "371 704",
};

test("base64url both ways", () => {
  const b = Uint8Array.from({ length: 33 }, (_, i) => i * 7);
  assert.deepEqual(b64urlDecode(b64urlEncode(b)), b);
  assert.throws(() => b64urlDecode("a+b/"));
});

test("a request of osheaf is read from the fragment", () => {
  const p = parseParams(fragment(unlock));
  assert.equal(p.mode, "unlock");
  assert.equal(p.port, 49992);
  assert.deepEqual(p.credIds, [cred]);
  assert.equal(p.creds[0].length, 20);
  assert.equal(b64urlEncode(p.pk), pk);
  const e = parseParams(fragment({ mode: "enroll", port: "1024", state, pk, owner }));
  assert.deepEqual(e.creds, []);
  // to enroll, the credentials the owner has, to exclude
  assert.equal(parseParams(fragment({ mode: "enroll", port: "1024", state, pk, owner, cred })).creds.length, 1);
  assert.equal(parseParams(fragment({ ...unlock, cred: cred + "," + cred })).creds.length, 2);
  assert.equal(parseParams(fragment(unlock).slice(1)).owner, owner);
});

test("anything else is refused", () => {
  const bad = [
    { ...unlock, mode: "steal" }, { ...unlock, port: "80" }, { ...unlock, port: "65536" }, { ...unlock, port: "8e3" },
    { ...unlock, port: "" }, { ...unlock, state: "short" }, { ...unlock, state: "x".repeat(65) },
    { ...unlock, state: "a b c d e f g h i j" }, { ...unlock, owner: owner.toUpperCase() },
    { ...unlock, owner: owner.slice(1) }, { ...unlock, cred: "" },
    { ...unlock, cred: "AAAA" }, { ...unlock, cred: "not base64!" }, { ...unlock, extra: "1" },
    { ...unlock, salt: b64urlEncode(new Uint8Array(32)) },
    { mode: "unlock", port: "49992", state, pk, owner },
    { ...unlock, pk: "" }, { ...unlock, pk: "AAAA" }, { ...unlock, pk: pk + "AA" },
    { mode: "unlock", port: "49992", state, owner, cred },
    { ...unlock, cred: Array(17).fill(cred).join(",") },
  ];
  for (const o of bad) assert.throws(() => parseParams(fragment(o)), Error, JSON.stringify(o));
  assert.throws(() => parseParams(fragment(unlock) + "&port=5000"), /twice/);
});

test("the salt is computed from the owner", async () => {
  assert.deepEqual(await expectedSalt(owner),
                   new Uint8Array(createHash("sha256").update("opensheaf wallet unlock v1 " + owner).digest()));
});

test("the answer goes to the listener of osheaf on 127.0.0.1 only", () => {
  assert.equal(callbackUrl(49992), "http://127.0.0.1:49992/callback");
  assert.throws(() => callbackUrl(80));
  assert.throws(() => callbackUrl("49992/../evil"));
  const epk = new Uint8Array(32).fill(1), ct = new Uint8Array(32).fill(2), tag = new Uint8Array(32).fill(3);
  const url = answerUrl(49992, state, { cred: "AQID", epk, ct, tag });
  assert.equal(url, `http://127.0.0.1:49992/callback?state=${state}&epk=${b64urlEncode(epk)}&ct=${b64urlEncode(ct)}`
                    + `&tag=${b64urlEncode(tag)}&cred=AQID`);
  assert.equal(answerUrl(49992, state, { cred: new Uint8Array([1, 2, 3]), epk, ct, tag }), url);
  assert.equal(answerUrl(49992, state, { error: "x25519-unavailable" }),
               `http://127.0.0.1:49992/callback?state=${state}&error=x25519-unavailable`);
  assert.ok(!url.includes("secret"));
});

test("the hand-off: the test vector shared with osheaf", async () => {
  const subtle = globalThis.crypto.subtle;
  assert.ok(await x25519Available());
  const v = HAND_OFF;
  const bytes = (k) => b64urlDecode(v[k]);
  assert.deepEqual(bytes("secret"), Uint8Array.from({ length: 32 }, (_, i) => i));
  const privateKey = await subtle.importKey("jwk", { kty: "OKP", crv: "X25519", d: v.esk, x: v.epk },
                                            { name: "X25519" }, false, ["deriveBits"]);
  const publicKey = await subtle.importKey("raw", bytes("epk"), { name: "X25519" }, true, []);
  const sealed = await seal(bytes("secret"), bytes("pk"), v.state, v.mode, v.owner, v.cred, { privateKey, publicKey });
  assert.equal(b64urlEncode(sealed.epk), v.epk);
  assert.equal(b64urlEncode(sealed.ct), v.ct);
  assert.equal(b64urlEncode(sealed.tag), v.tag);
  assert.equal(await confirmationCode(v.state, bytes("pk")), v.code);
  // the tag covers mode|owner|cred|pk|epk and the ciphertext
  for (const [mode, own, c] of [["enroll", v.owner, v.cred], [v.mode, "a".repeat(52), v.cred], [v.mode, v.owner, "b3RoZXI"]]) {
    const other = await seal(bytes("secret"), bytes("pk"), v.state, mode, own, c, { privateKey, publicKey });
    assert.equal(b64urlEncode(other.ct), v.ct);
    assert.notEqual(b64urlEncode(other.tag), v.tag);
  }
  const otherState = await seal(bytes("secret"), bytes("pk"), "another state", v.mode, v.owner, v.cred,
                                { privateKey, publicKey });
  assert.notEqual(b64urlEncode(otherState.ct), v.ct);
  // a new one-time key each time, its private key not extractable
  const fresh = await seal(bytes("secret"), bytes("pk"), v.state, v.mode, v.owner, v.cred);
  assert.equal(fresh.epk.length, 32);
  assert.notEqual(b64urlEncode(fresh.ct), v.ct);
  // osheaf's side, with its private key: the same keys open it, and the tag checks
  const sk = await subtle.importKey("jwk", { kty: "OKP", crv: "X25519", d: v.sk, x: v.pk },
                                    { name: "X25519" }, false, ["deriveBits"]);
  const peer = await subtle.importKey("raw", fresh.epk, { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: peer }, sk, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const both = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256",
    salt: new TextEncoder().encode(v.state), info: new TextEncoder().encode("opensheaf unlock hand-off v2") }, ikm, 512));
  assert.deepEqual(Uint8Array.from(fresh.ct, (b, i) => b ^ both[i]), bytes("secret"));
  const aad = associatedData(v.mode, v.owner, v.cred, bytes("pk"), fresh.epk);
  const tag = createHmac("sha256", both.slice(32)).update(aad).update(fresh.ct).digest();
  assert.deepEqual(new Uint8Array(tag), fresh.tag);
});

test("the confirmation code", async () => {
  const d = createHash("sha256").update("opensheaf unlock code v1" + state).update(b64urlDecode(pk)).digest();
  const n = String(d.readUInt32BE(0) % 1000000).padStart(6, "0");
  assert.equal(await confirmationCode(state, b64urlDecode(pk)), `${n.slice(0, 3)} ${n.slice(3)}`);
  assert.match(await confirmationCode("x".repeat(22), new Uint8Array(32)), /^[0-9]{3} [0-9]{3}$/);
});

test("short owner names", () => {
  assert.equal(shortName(owner), "em4v3kp5…gora");
  assert.equal(shortName("abc"), "abc");
});

test("the WebAuthn options", async () => {
  assert.equal(RP_ID, "unlock.opensheaf.org");
  const c = await createOptions(owner, new Uint8Array(32), [new Uint8Array(20).fill(7)]);
  assert.equal(c.rp.id, "unlock.opensheaf.org");
  assert.equal(c.user.name, "OpenSheaf em4v3kp5");
  assert.equal(c.user.displayName, "OpenSheaf owner " + owner);
  assert.deepEqual(c.user.id, new Uint8Array(createHash("sha256").update("opensheaf owner " + owner).digest().subarray(0, 16)));
  assert.equal(c.authenticatorSelection.residentKey, "required");
  assert.equal(c.authenticatorSelection.userVerification, "required");
  assert.deepEqual(c.excludeCredentials, [{ type: "public-key", id: new Uint8Array(20).fill(7) }]);
  assert.deepEqual((await createOptions(owner, new Uint8Array(32))).excludeCredentials, []);
  assert.ok(c.extensions.prf);
  const p = parseParams(fragment(unlock));
  const g = getOptions(await expectedSalt(owner), p.creds, new Uint8Array(32));
  assert.equal(g.rpId, "unlock.opensheaf.org");
  assert.deepEqual(g.allowCredentials, [{ type: "public-key", id: p.creds[0] }]);
  assert.deepEqual(g.extensions.prf.eval.first, await expectedSalt(owner));
});

test("PRF support and the PRF secret (WebAuthn mocked)", async () => {
  const ok = { getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(9).buffer } } }) };
  assert.deepEqual(prfSecret(ok), new Uint8Array(32).fill(9));
  assert.throws(() => prfSecret({ getClientExtensionResults: () => ({}) }), /PRF/);
  assert.throws(() => prfSecret({ getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(16) } } }) }));
  const created = (prf) => ({ getClientExtensionResults: () => prf });
  assert.equal(prfEnabled(created({ prf: { enabled: true } })), true);
  assert.equal(prfEnabled(created({ prf: { enabled: false } })), false);
  // not said (Chrome with iCloud Keychain, for one): the assertion tells
  for (const r of [{}, { prf: {} }, { prf: { enabled: "yes" } }])
    assert.equal(prfEnabled(created(r)), null, JSON.stringify(r));
  assert.equal(await prfSupported(undefined), null);
  assert.equal(await prfSupported({}), null);
  assert.equal(await prfSupported({ getClientCapabilities: async () => ({ "extension:prf": false }) }), false);
  assert.equal(await prfSupported({ getClientCapabilities: async () => ({ "extension:prf": true }) }), true);
  assert.equal(await prfSupported({ getClientCapabilities: async () => ({}) }), null);
  assert.equal(await prfSupported({ getClientCapabilities: async () => { throw new Error("x"); } }), null);
});

// The popup of the OpenSheaf manager: the vector shared with the tests of
// opensheaf-js (tests/github.test.js, VECTOR), which plays the manager's side.
const POPUP = {
  sk: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", pk: "E75P6uryBMf9M1j8nAByGIHRdCeBKCJ-xnTzf3_pe20",
  esk: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk", epk: "V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE",
  state: "popup-state-of-the-tests", owner: "a".repeat(52), cred: "Y3JlZGVudGlhbC1vZi10aGUtdGVzdHM",
  secret: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  ct: "5G1AcynkQgGMF4zDTK5jAHzpINvJJpVIKW_a172XDTY", tag: "x9nebDAtOsMhfeqtGvRgbjU2r828_nAI4qzFA4JSt6U",
  code: "329 875",
  enrollTag: "lTxj4rxHKf2zYq2Z6qJP-tfFeHEIEhvDgxiGvgR9zCI",
};

test("a popup is asked for by a page of the list only, by its origin", () => {
  assert.deepEqual(POPUP_OPENERS, ["https://manager.opensheaf.org"]);
  const M = "https%3A%2F%2Fmanager.opensheaf.org";
  assert.deepEqual(parseParams("#mode=popup&origin=" + M), { mode: "popup", origin: "https://manager.opensheaf.org" });
  assert.deepEqual(parseParams("#mode=popup-enroll&origin=" + M), { mode: "popup-enroll", origin: "https://manager.opensheaf.org" });
  for (const bad of ["#mode=popup&origin=https%3A%2F%2Fevil.example", "#mode=popup&origin=https%3A%2F%2Fmanager.opensheaf.org.evil.example",
                     "#mode=popup&origin=http%3A%2F%2Fmanager.opensheaf.org", "#mode=popup", "#mode=popup&origin=" + M + "%2F",
                     "#mode=popup&origin=" + M + "&state=" + state,
                     // the site of the specification and of archives on opensheaf.org: no longer
                     "#mode=popup&origin=https%3A%2F%2Fopensheaf.org", "#mode=popup-enroll&origin=https%3A%2F%2Fopensheaf.org",
                     "#mode=popup-unlock&origin=" + M, "#mode=popup-enroll&origin=" + M + "&cred=" + cred,
                     "#mode=popup&origin=http%3A%2F%2Flocalhost%3A8000"]) {
    assert.throws(() => parseParams(bad, "https://unlock.opensheaf.org"), Error, bad);
  }
  // a page served from this computer, to try the manager out, from this computer only
  assert.equal(parseParams("#mode=popup&origin=http%3A%2F%2Flocalhost%3A8000", "http://127.0.0.1:8001").origin, "http://localhost:8000");
  assert.equal(openerAllowed("https://evil.example", "http://localhost:8001"), false);
});

test("the request of the popup, by a window message, is checked as osheaf's", () => {
  const good = { type: MESSAGES.request, state, pk, owner, cred };
  const r = parseRequest(good);
  assert.equal(r.mode, "popup");
  assert.equal(r.creds.length, 1);
  for (const bad of [null, "x", { ...good, type: "other" }, { ...good, port: "1024" }, { ...good, cred: "" },
                     { ...good, owner: owner.slice(1) }, { ...good, pk: "AAAA" }, { ...good, state: "short" },
                     { type: MESSAGES.request, state, pk, owner }, { ...good, cred: ["a"] }]) {
    assert.throws(() => parseRequest(bad), Error, JSON.stringify(bad));
  }
  assert.throws(() => parseRequest(good, "unlock"), /not a mode of a popup/);
});

test("the request of a popup that enrolls: the passkeys to exclude, possibly none", () => {
  const good = { type: MESSAGES.request, state, pk, owner, cred: "" };
  const r = parseRequest(good, "popup-enroll");
  assert.equal(r.mode, "popup-enroll");
  assert.deepEqual(r.creds, []);
  assert.equal(parseRequest({ ...good, cred }, "popup-enroll").creds.length, 1);
  assert.throws(() => parseRequest({ ...good, cred: "AAAA" }, "popup-enroll"), /not a credential/);
});

test("the hand-off of a popup: the test vector shared with opensheaf-js", async () => {
  const subtle = globalThis.crypto.subtle;
  const v = POPUP;
  const bytes = (k) => b64urlDecode(v[k]);
  const privateKey = await subtle.importKey("jwk", { kty: "OKP", crv: "X25519", d: v.esk, x: v.epk },
                                            { name: "X25519" }, false, ["deriveBits"]);
  const publicKey = await subtle.importKey("raw", bytes("epk"), { name: "X25519" }, true, []);
  const sealed = await seal(bytes("secret"), bytes("pk"), v.state, "popup", v.owner, v.cred, { privateKey, publicKey });
  assert.deepEqual([b64urlEncode(sealed.epk), b64urlEncode(sealed.ct), b64urlEncode(sealed.tag)], [v.epk, v.ct, v.tag]);
  assert.equal(await confirmationCode(v.state, bytes("pk")), v.code);
  const asUnlock = await seal(bytes("secret"), bytes("pk"), v.state, "unlock", v.owner, v.cred, { privateKey, publicKey });
  assert.notEqual(b64urlEncode(asUnlock.tag), v.tag);
  // the same secret sealed by a popup that enrolls: the same ciphertext, another tag
  const asEnroll = await seal(bytes("secret"), bytes("pk"), v.state, "popup-enroll", v.owner, v.cred, { privateKey, publicKey });
  assert.deepEqual([b64urlEncode(asEnroll.ct), b64urlEncode(asEnroll.tag)], [v.ct, v.enrollTag]);
});

// Version 2, two owners at one touch: the second secret of the vector
// shared with opensheaf-js (tests/github.test.js, VECTOR2), sealed for the
// second owner with a one-time key of its own.
const POPUP2 = {
  esk: "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws", epk: "c7LYt2qptTZgAyvI9di-46OuTjs6f9Sa3oH3NHo0qmg",
  owner: "b".repeat(51) + "a", secret: "__79_Pv6-fj39vX08_Lx8O_u7ezr6uno5-bl5OPi4eA",
  ct: "ib0GOq8sfUobf__9-Vwwot4zM6T82n9r9ZVdnlGLulo", tag: "_4P3d-XwSi0QXm8oB8raCpbh75XwRwI3xmIjap7vlYI",
};

test("a request of version 2: two owners at one touch, to unlock only", () => {
  const owner2 = "b".repeat(51) + "a";
  const good = { type: MESSAGES.request, v: 2, state, pk, owners: `${owner},${owner2}`, cred };
  const r = parseRequest(good);
  assert.deepEqual([r.v, r.owners, r.owner, r.creds.length], [2, [owner, owner2], owner, 1]);
  for (const bad of [{ ...good, v: 3 }, { ...good, v: "2" }, { ...good, owners: owner }, { ...good, owners: `${owner},${owner}` },
                     { ...good, owners: `${owner},${owner2},${"c".repeat(51)}a` }, { ...good, owners: `${owner},x` },
                     { ...good, owner }, { ...good, cred: "" }, { type: MESSAGES.request, v: 2, state, pk, cred }]) {
    assert.throws(() => parseRequest(bad), Error, JSON.stringify(bad));
  }
  assert.throws(() => parseRequest(good, "popup-enroll"), /one owner at a time/);
  // a request of version 1 has no v, and an owner
  assert.equal(parseRequest({ type: MESSAGES.request, state, pk, owner, cred }).v, undefined);
});

test("version 2: two salts at one assertion, and the vector of the second owner", async () => {
  const subtle = globalThis.crypto.subtle;
  const [a, b] = [await expectedSalt(owner), await expectedSalt("b".repeat(51) + "a")];
  const o = getOptions(a, [new Uint8Array(20)], new Uint8Array(32), b);
  assert.deepEqual(o.extensions, { prf: { eval: { first: a, second: b } } });
  assert.deepEqual(getOptions(a, [], new Uint8Array(32)).extensions, { prf: { eval: { first: a } } });
  const both = { getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(1).buffer,
                                                                        second: new Uint8Array(32).fill(2).buffer } } }) };
  assert.deepEqual(prfSecret(both, "second"), new Uint8Array(32).fill(2));
  const one = { getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).buffer } } }) };
  assert.throws(() => prfSecret(one, "second"), /secret of one owner only/);
  const v = POPUP2, bytes = (x) => b64urlDecode(x);
  const privateKey = await subtle.importKey("jwk", { kty: "OKP", crv: "X25519", d: v.esk, x: v.epk },
                                            { name: "X25519" }, false, ["deriveBits"]);
  const publicKey = await subtle.importKey("raw", bytes(v.epk), { name: "X25519" }, true, []);
  const sealed = await seal(bytes(v.secret), bytes(POPUP.pk), POPUP.state, "popup", v.owner, POPUP.cred, { privateKey, publicKey });
  assert.deepEqual([b64urlEncode(sealed.epk), b64urlEncode(sealed.ct), b64urlEncode(sealed.tag)], [v.epk, v.ct, v.tag]);
});
