// Passkey unlock for osheaf key enroll / osheaf key unlock: the parts that
// need no browser, tested with node --test. The page (index.html, unlock.js)
// is opened by osheaf at
//   https://unlock.opensheaf.org/#mode=enroll|unlock&port=&state=&pk=&owner=[&cred=id,id...]
// with everything in the fragment, which the browser sends to no server and
// which the page takes out of the address at once. To unlock, cred names the
// passkeys the page may use; to enroll, those the owner has already, which
// WebAuthn is asked to exclude. The page creates a passkey for RP_ID or
// derives the PRF secret of one, and goes to http://127.0.0.1:<port>/callback,
// a one-time listener of osheaf, with ?state=&epk=&ct=&tag=&cred= (or
// ?state=&error=).
//
// The hand-off (v2): pk is a one-time X25519 public key of osheaf. The page
// makes a one-time X25519 key pair of its own (epk is its public key; the
// private key is not extractable), derives the shared secret with pk, and
// HKDF-SHA256 of it (salt: the state in UTF-8, info: "opensheaf unlock
// hand-off v2") gives 64 bytes: an encryption key and a MAC key. ct is the
// PRF secret XOR the encryption key; tag is HMAC-SHA256 under the MAC key of
// the UTF-8 of "mode|owner|cred|pk|epk" (base64url) followed by ct
// (encrypt-then-MAC: HMAC and HKDF are in WebCrypto and in Python's standard
// library, where AES-GCM would need a new dependency of osheaf). Not a form:
// Safari warns of "a non-secure form" posted from https to
// http://127.0.0.1. The address stays in the history, but holds only a
// ciphertext that the private key of osheaf alone opens, which is forgotten
// when osheaf ends.

// A page (the OpenSheaf manager) opens it as a popup instead, at
//   https://unlock.opensheaf.org/#mode=popup|popup-enroll&origin=<the page's origin>
// and the request and the answer go by window messages, never through an
// address: see POPUP_OPENERS below. The answer is sealed as for osheaf, with
// the mode ("popup" to unlock, "popup-enroll" to create a passkey) in the
// authenticated data.
//
// The relying party of the passkeys is the origin of this page, which serves
// nothing else. Passkeys made earlier for "opensheaf.org" (from
// opensheaf.org/manager/unlock.html) are not used here: osheaf asks the
// owner to enroll a new one.
export const RP_ID = "unlock.opensheaf.org";
export const RP = { id: RP_ID, name: "OpenSheaf" };
export const SALT_PREFIX = "opensheaf wallet unlock v1 ";
export const USER_ID_PREFIX = "opensheaf owner ";
export const HAND_OFF_INFO = "opensheaf unlock hand-off v2";
export const CODE_LABEL = "opensheaf unlock code v1";
const OWNER = /^[a-z2-7]{52}$/;
const STATE = /^[A-Za-z0-9_-]{16,64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const PARAMS = new Set(["mode", "port", "state", "pk", "owner", "cred"]);
const MAX_CREDS = 16;

// The popup of a page (the OpenSheaf manager): the page opens this one in a
// window of its own at #mode=popup&origin=<its origin>, and the two talk by
// window messages, each checking the origin of what it receives and naming
// the origin of what it sends. Only the origins below may open it so; a page
// served from this computer (localhost, 127.0.0.1), for trying the page
// out, may be opened by another page of this computer. The manager has an
// origin of its own, so that no other page of the project's sites (the
// archives served from opensheaf.org, for instance) may open this one.
export const POPUP_OPENERS = ["https://manager.opensheaf.org"];
// The modes of a popup: "popup" unlocks (cred: the passkeys that may
// answer), "popup-enroll" creates a passkey (cred: those the owner has
// already, excluded, possibly none) and derives its secret.
export const POPUP_MODES = ["popup", "popup-enroll"];
export const MESSAGES = { ready: "opensheaf-unlock-ready", request: "opensheaf-unlock-request",
                          answer: "opensheaf-unlock-answer", done: "opensheaf-unlock-done" };
const LOCAL = /^http:\/\/(localhost|127\.0\.0\.1)(:[0-9]{1,5})?$/;

export function openerAllowed(origin, pageOrigin = "") {
  if (POPUP_OPENERS.includes(origin)) return true;
  return LOCAL.test(pageOrigin) && LOCAL.test(origin);
}

export function b64urlEncode(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text) {
  if (typeof text !== "string" || !B64URL.test(text) || text.length % 4 === 1) throw new Error("not base64url");
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

// The request of osheaf, from the fragment of the page ("#..." or "...");
// throws an Error that says what is wrong, and then the page does nothing
// else.
export function parseParams(fragment, pageOrigin = "") {
  const q = new URLSearchParams(String(fragment).replace(/^#/, ""));
  const seen = new Set();
  const mode = q.get("mode");
  const popup = POPUP_MODES.includes(mode);
  for (const k of q.keys()) {
    if (!(popup ? ["mode", "origin"].includes(k) : PARAMS.has(k))) throw new Error(`unknown parameter: ${k}`);
    if (seen.has(k)) throw new Error(`parameter given twice: ${k}`);
    seen.add(k);
  }
  if (popup) {
    const origin = q.get("origin") || "";
    if (!openerAllowed(origin, pageOrigin)) throw new Error("not a page that may ask for the keys: " + origin.slice(0, 80));
    return { mode, origin };
  }
  if (mode !== "enroll" && mode !== "unlock") throw new Error("mode must be enroll, unlock, popup or popup-enroll");
  const port = q.get("port") || "";
  if (!/^[0-9]{4,5}$/.test(port) || +port < 1024 || +port > 65535) throw new Error("not a port of osheaf: " + port);
  return { ...checkRequest(mode, q.get("state"), q.get("pk"), q.get("owner"), q.has("cred") ? q.get("cred") : null), port: +port };
}

// The request of a page that opened this one as a popup: a window message
// {type, state, pk, owner, cred}, checked as the fragment of osheaf is, for
// the mode of the popup's address.
export function isEnroll(mode) {
  return mode === "enroll" || mode === "popup-enroll";
}

export function parseRequest(data, mode = "popup") {
  if (!POPUP_MODES.includes(mode)) throw new Error("not a mode of a popup");
  if (!data || typeof data !== "object" || data.type !== MESSAGES.request) throw new Error("not a request");
  const known = new Set(["type", "state", "pk", "owner", "cred"]);
  for (const k of Object.keys(data)) if (!known.has(k)) throw new Error(`unknown field: ${k}`);
  for (const k of ["state", "pk", "owner", "cred"]) if (typeof data[k] !== "string") throw new Error(`no ${k}`);
  return checkRequest(mode, data.state, data.pk, data.owner, data.cred);
}

function checkRequest(mode, stateGiven, pkGiven, ownerGiven, credGiven) {
  const state = stateGiven || "";
  if (!STATE.test(state)) throw new Error("not a state of osheaf");
  let pk;
  try { pk = b64urlDecode(pkGiven || ""); } catch (_) { pk = null; }
  if (!pk || pk.length !== 32) throw new Error("not a public key of osheaf");
  const owner = ownerGiven || "";
  if (!OWNER.test(owner)) throw new Error("not an owner name");
  const credIds = credGiven !== null && credGiven !== "" ? credGiven.split(",") : [];
  if (!isEnroll(mode) && credIds.length === 0) throw new Error("no passkey to unlock with");
  if (credIds.length > MAX_CREDS) throw new Error("too many passkeys");
  const creds = credIds.map((c) => {
    let b;
    try { b = b64urlDecode(c); } catch (_) { b = null; }
    if (!b || b.length < 16 || b.length > 1023) throw new Error("not a credential: " + c.slice(0, 40));
    return b;
  });
  return { mode, state, pk, owner, credIds, creds };
}

async function sha256(subtle, bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

const utf8 = (text) => new TextEncoder().encode(text);

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}

// The PRF salt, the same for every key of an owner: computed here, never
// taken from the address, so that a link cannot have the page derive a
// secret for another salt.
export async function expectedSalt(owner, subtle = globalThis.crypto.subtle) {
  return sha256(subtle, utf8(SALT_PREFIX + owner));
}

// The six digits that osheaf prints and the page shows, "123 456": the first
// four bytes of SHA-256(CODE_LABEL || state || pk), big-endian, modulo 10^6.
export async function confirmationCode(state, pk, subtle = globalThis.crypto.subtle) {
  const d = await sha256(subtle, concat(utf8(CODE_LABEL), utf8(state), pk));
  const n = ((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3];
  const digits = String(n % 1000000).padStart(6, "0");
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}

export function callbackUrl(port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("not a port");
  return `http://127.0.0.1:${port}/callback`;
}

// One passkey per owner on a provider: its user handle is derived from the
// owner name, and the passkeys the owner has already are excluded, so that
// enrolling again on a provider that holds one fails rather than replace it.
export async function createOptions(owner, challenge, exclude = [], subtle = globalThis.crypto.subtle) {
  const id = (await sha256(subtle, utf8(USER_ID_PREFIX + owner))).slice(0, 16);
  return {
    rp: RP,
    user: { id, name: `OpenSheaf ${owner.slice(0, 8)}`, displayName: `OpenSheaf owner ${owner}` },
    challenge,
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    excludeCredentials: exclude.map((id) => ({ type: "public-key", id })),
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    extensions: { prf: {} },
  };
}

export function getOptions(salt, creds, challenge) {
  return {
    rpId: RP_ID,
    challenge,
    allowCredentials: creds.map((id) => ({ type: "public-key", id })),
    userVerification: "required",
    extensions: { prf: { eval: { first: salt } } },
  };
}

// Whether the browser says it supports PRF: true, false, or null when it
// does not say (no getClientCapabilities, or no such entry).
export async function prfSupported(pkc = globalThis.PublicKeyCredential) {
  if (!pkc || typeof pkc.getClientCapabilities !== "function") return null;
  try {
    const caps = await pkc.getClientCapabilities();
    return typeof caps["extension:prf"] === "boolean" ? caps["extension:prf"] : null;
  } catch (_) {
    return null;
  }
}

// A passkey just created is used only if the browser says that PRF is
// enabled for it: anything but true is a failure.
export function prfEnabled(created) {
  const prf = created.getClientExtensionResults().prf;
  return !!prf && prf.enabled === true;
}

// The PRF secret of an assertion, 32 bytes, or an Error.
export function prfSecret(assertion) {
  const prf = assertion.getClientExtensionResults().prf;
  const first = prf && prf.results && prf.results.first;
  if (!first) throw new Error("this browser or passkey does not support the PRF extension");
  const bytes = new Uint8Array(first);
  if (bytes.length !== 32) throw new Error("the PRF secret is not 32 bytes");
  return bytes;
}

// An owner name, shortened for a person: its first 8 and last 4 characters.
export function shortName(name) {
  return name.length <= 14 ? name : `${name.slice(0, 8)}…${name.slice(-4)}`;
}

// Whether this browser has X25519 in WebCrypto; without it, the page hands
// nothing over.
export async function x25519Available(subtle = globalThis.crypto && globalThis.crypto.subtle) {
  try {
    await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return true;
  } catch (_) {
    return false;
  }
}

export function associatedData(mode, owner, cred, pk, epk) {
  return utf8(`${mode}|${owner}|${cred}|${b64urlEncode(pk)}|${b64urlEncode(epk)}`);
}

// {epk, ct, tag}: SECRET encrypted and authenticated to the X25519 public key
// PK of osheaf, for the request (STATE, MODE, OWNER) and the credential CRED
// (base64url), with the one-time key pair EPHEMERAL (a new one by default,
// its private key not extractable).
export async function seal(secret, pk, state, mode, owner, cred, ephemeral = null, subtle = globalThis.crypto.subtle) {
  ephemeral = ephemeral || await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const peer = await subtle.importKey("raw", pk, { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: peer }, ephemeral.privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const both = new Uint8Array(await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: utf8(state), info: utf8(HAND_OFF_INFO) }, ikm, 512));
  const enc = both.slice(0, 32);
  const mac = await subtle.importKey("raw", both.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  both.fill(0);
  const ct = Uint8Array.from(secret, (b, i) => b ^ enc[i]);
  enc.fill(0);
  const epk = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
  const tag = new Uint8Array(await subtle.sign("HMAC", mac, concat(associatedData(mode, owner, cred, pk, epk), ct)));
  return { epk, ct, tag };
}

// The address of the answer to osheaf: {cred, epk, ct, tag} or {error}.
export function answerUrl(port, state, { cred, epk, ct, tag, error }) {
  const q = new URLSearchParams({ state });
  if (error !== undefined) {
    q.set("error", String(error).slice(0, 200));
  } else {
    q.set("epk", b64urlEncode(epk));
    q.set("ct", b64urlEncode(ct));
    q.set("tag", b64urlEncode(tag));
    q.set("cred", typeof cred === "string" ? cred : b64urlEncode(cred));
  }
  return callbackUrl(port) + "?" + q.toString();
}
