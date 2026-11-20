// The page of passkey unlock (see unlock-core.js): it takes the request of
// osheaf out of the address, explains it, shows the confirmation code, waits
// until the user has checked the code and clicked, calls WebAuthn, encrypts
// the secret to the one-time key of osheaf, and goes to osheaf on 127.0.0.1
// with it. It never goes there without a click, and sends nothing anywhere
// else.

// First of all: the request leaves the address bar and the history.
const FRAGMENT = location.hash;
const QUERY = location.search;
if (FRAGMENT || QUERY) history.replaceState(null, "", location.pathname);

import { parseParams, expectedSalt, confirmationCode, createOptions, getOptions, prfSupported, prfEnabled,
         prfSecret, seal, answerUrl, shortName, x25519Available, b64urlEncode, RP_ID } from "./unlock-core.js";

const $ = (id) => document.getElementById(id);
const KNOWN_GOOD = "known to work: Safari 17+, Chrome 133+, Firefox 130+";

function say(text, kind) {
  const el = $("status");
  el.textContent = text;
  el.className = "notice" + (kind ? " " + kind : "");
  el.hidden = false;
}

// The steps of the page, one after the other: the current one is marked.
function step(n) {
  [...$("steps").children].forEach((li, i) => {
    li.className = i < n ? "done" : i === n ? "now" : "";
  });
}

// To osheaf on this computer, after a click only; replace, so that the page
// of the answer does not lead back here.
function answer(params, a) {
  location.replace(answerUrl(params.port, params.state, a));
}

// A button that tells osheaf, on a click, that the page gives no key.
function offerPassphrase(params, error) {
  const b = $("tell");
  b.hidden = false;
  b.onclick = () => answer(params, { error });
}

const challenge = () => crypto.getRandomValues(new Uint8Array(32));

async function derive(params, salt, creds) {
  const assertion = await navigator.credentials.get({ publicKey: getOptions(salt, creds, challenge()) });
  return { cred: b64urlEncode(new Uint8Array(assertion.rawId)), secret: prfSecret(assertion) };
}

async function run(params) {
  const salt = await expectedSalt(params.owner);
  if (params.mode === "enroll") {
    if ((await prfSupported()) === false) throw new Error("this browser does not support the PRF extension of passkeys");
    let created;
    try {
      created = await navigator.credentials.create({
        publicKey: await createOptions(params.owner, challenge(), params.creds) });
    } catch (e) {
      if (e && e.name === "InvalidStateError") {
        throw new Error("this passkey provider holds a passkey of this owner already: use that one (osheaf key "
                        + "enroll, without --new-passkey), or choose another provider");
      }
      throw e;
    }
    if (!prfEnabled(created)) throw new Error("this passkey does not support the PRF extension");
    say("The passkey is made. Once more, to derive its secret…");
    return derive(params, salt, [new Uint8Array(created.rawId)]);
  }
  return derive(params, salt, params.creds);
}

async function main() {
  if (window.top !== window.self) {
    say("This page does not run inside another page. Open it on its own, from osheaf.", "bad");
    return;
  }
  let params;
  try {
    if (QUERY && !FRAGMENT) throw new Error("its request is in the query, as older versions of osheaf sent it: "
                                            + "update osheaf");
    if (!FRAGMENT) throw new Error("it was opened without a request");
    if (typeof PublicKeyCredential !== "function") throw new Error("this browser has no passkeys (WebAuthn)");
    params = parseParams(FRAGMENT);
  } catch (e) {
    say("This page was not opened by osheaf as expected, and does nothing: " + e.message + ".", "bad");
    return;
  }
  if (!(await x25519Available())) {
    say("This browser has no X25519 in WebCrypto, and cannot hand the key to osheaf securely ("
        + KNOWN_GOOD + "). Use the passphrase.", "bad");
    offerPassphrase(params, "x25519-unavailable");
    return;
  }
  const enroll = params.mode === "enroll";
  const owner = $("owner");
  owner.textContent = shortName(params.owner);
  owner.title = params.owner;
  $("what").textContent = enroll
    ? `create a passkey for ${RP_ID}, named after this owner, which will unlock its keys with Touch ID`
    : "unlock the keys of this owner with your passkey";
  $("code").textContent = await confirmationCode(params.state, params.pk);
  const label = enroll ? "Create the passkey" : "Unlock";
  $("go").textContent = label;
  $("step-click").textContent = `Check the code, then click ${label}.`;
  $("request").hidden = false;
  step(0);
  const go = $("go"), cancel = $("cancel"), same = $("same");
  go.disabled = true;
  same.checked = false;
  same.onchange = () => { go.disabled = !same.checked; };
  go.onclick = async () => {
    if (!same.checked) return;
    go.disabled = cancel.disabled = same.disabled = true;
    $("status").hidden = true;
    step(1);
    try {
      const got = await run(params);
      step(2);
      const sealed = await seal(got.secret, params.pk, params.state, params.mode, params.owner, got.cred);
      got.secret.fill(0);
      answer(params, { cred: got.cred, ...sealed });
    } catch (e) {
      step(0);
      say(`${e.name || "Error"}: ${e.message}. Try again, or let osheaf ask for the passphrase.`, "bad");
      cancel.disabled = same.disabled = false;
      go.disabled = !same.checked;
    }
  };
  cancel.onclick = () => answer(params, { error: "the user chose the passphrase" });
}

main();
