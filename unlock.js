// The page of passkey unlock (see unlock-core.js). For osheaf, it takes the request of
// osheaf out of the address, explains it, shows the confirmation code, waits
// until the user has checked the code and clicked, calls WebAuthn, encrypts
// the secret to the one-time key of osheaf, and goes to osheaf on 127.0.0.1
// with it. It never goes there without a click, and sends nothing anywhere
// else. For the OpenSheaf manager, it runs as a popup (popup() below), to
// unlock or to create a passkey.

// First of all: the request leaves the address bar and the history.
const FRAGMENT = location.hash;
const QUERY = location.search;
if (FRAGMENT || QUERY) history.replaceState(null, "", location.pathname);

import { parseParams, parseRequest, expectedSalt, confirmationCode, createOptions, getOptions, prfSupported, prfEnabled,
         prfSecret, seal, answerUrl, shortName, x25519Available, b64urlEncode, isEnroll, RP_ID, MESSAGES,
         POPUP_MODES, PRF_HELP } from "./unlock-core.js";

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

// Two owners at one touch (a request of version 2): one assertion, the
// secret of each owner's salt, in the order of the request.
async function deriveTwo(request) {
  const [first, second] = await Promise.all(request.owners.map((o) => expectedSalt(o)));
  const assertion = await navigator.credentials.get({ publicKey: getOptions(first, request.creds, challenge(), second) });
  const secrets = [prfSecret(assertion, "first")];
  try {
    secrets.push(prfSecret(assertion, "second"));
  } catch (e) {
    secrets[0].fill(0);
    throw e;
  }
  return { cred: b64urlEncode(new Uint8Array(assertion.rawId)), secrets };
}

async function run(params) {
  const salt = await expectedSalt(params.owner);
  if (isEnroll(params.mode)) {
    if ((await prfSupported()) === false) {
      throw new Error(`this browser does not support the PRF extension of passkeys (${PRF_HELP})`);
    }
    let created;
    try {
      created = await navigator.credentials.create({
        publicKey: await createOptions(params.owner, challenge(), params.creds) });
    } catch (e) {
      if (e && e.name === "InvalidStateError") {
        throw new Error(params.mode === "enroll"
          ? "this passkey provider holds a passkey of this owner already: use that one (osheaf key "
            + "enroll, without --new-passkey), or choose another provider"
          : "this passkey provider holds a passkey of this owner already: use that one (unlock with it in the "
            + "manager), or choose another provider");
      }
      throw e;
    }
    if (prfEnabled(created) === false) {
      throw new Error(`this passkey provider does not support the PRF extension (${PRF_HELP}); delete the passkey ` +
                      `just made for ${RP_ID} in your passwords, and try another browser or provider`);
    }
    say("The passkey is made. Once more, to derive its secret…");
    try {
      return await derive(params, salt, [new Uint8Array(created.rawId)]);
    } catch (e) {
      e.message = `the passkey was made, but ${e.message}`;
      throw e;
    }
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
    params = parseParams(FRAGMENT, location.origin);
  } catch (e) {
    say("This page was not opened by osheaf as expected, and does nothing: " + e.message + ".", "bad");
    return;
  }
  if (POPUP_MODES.includes(params.mode)) {
    popup(params.origin, params.mode);
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
  $("port").textContent = String(params.port);
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

// The popup of a page (the OpenSheaf manager): the request comes from the
// window that opened this one, from the origin the address names (which
// parseParams has checked against the list), by a window message; the
// answer goes back to that window, to that origin only. Nothing is taken
// from another window or origin, and nothing is sent before a click. MODE
// is that of the address: "popup" to unlock, "popup-enroll" to create a
// passkey; it is in the authenticated data of the answer.
function popup(origin, mode) {
  const opener = window.opener;
  if (!opener) {
    say("This page was opened for the OpenSheaf manager, but not by it, and does nothing: open it from the manager.", "bad");
    return;
  }
  const post = (message) => opener.postMessage(message, origin);
  let request = null;
  window.addEventListener("message", async (event) => {
    if (event.source !== opener || event.origin !== origin) return;
    const data = event.data;
    if (request && data && data.type === MESSAGES.done) {
      say("The manager has the key. This window closes.");
      window.close();
      return;
    }
    if (request) return;
    try {
      request = parseRequest(data, mode);
    } catch (e) {
      say(`The manager sent a request this page does not take (${e.message}), and nothing is done.`, "bad");
      return;
    }
    await showPopup(request, origin, post);
  });
  post({ type: MESSAGES.ready });
}

async function showPopup(request, origin, post) {
  let answered = false, lastError = "";
  const failed = (error) => { answered = true; post({ type: MESSAGES.answer, state: request.state, error }); };
  // what failed is told to the manager as it happens (the person may try
  // again here), and, if the window is closed without an answer, as the
  // final answer: the manager then says why, not only that it was closed
  const status = (error) => { lastError = error; post({ type: MESSAGES.status, state: request.state, error }); };
  window.addEventListener("pagehide", () => {
    if (!answered) failed(lastError ? `the window was closed after: ${lastError}` : "the window was closed");
  });
  if (!(await x25519Available())) {
    say("This browser has no X25519 in WebCrypto, and cannot hand the key to the manager securely ("
        + KNOWN_GOOD + ").", "bad");
    failed("x25519-unavailable");
    return;
  }
  const owner = $("owner");
  const two = request.v === 2;
  owner.textContent = two ? request.owners.map(shortName).join(" and ") : shortName(request.owner);
  owner.title = two ? request.owners.join("\n") : request.owner;
  const enroll = isEnroll(request.mode);
  $("who").textContent = `The OpenSheaf manager (${origin})`;
  $("what").textContent = enroll
    ? `create a passkey for ${RP_ID}, named after this owner, which will unlock its keys in the key wallet`
    : two ? "sign with the keys of these two owners, which your passkey unlocks with one touch"
      : "sign with the keys of this owner, which your passkey unlocks";
  const code = await confirmationCode(request.state, request.pk);
  $("code").textContent = code;
  $("same-box").hidden = true;
  $("cli-note").hidden = true;
  $("popup-note").hidden = false;
  if (enroll) {
    $("popup-note").textContent = "If you did not just ask the manager to set up a passkey, close this window. The "
      + "passkey is made here, then used once more to derive its secret (Touch ID twice). Type this code in the "
      + "manager: it opens the secret only with it. The secret goes only to the manager's page, at the address "
      + "above, encrypted to a one-time key of that page, never to a server.";
  }
  const label = enroll ? "Create the passkey" : "Unlock";
  $("step-click").textContent = `Click ${label}, then use your passkey.`;
  $("step-send").textContent = `Sending the key to the manager: type ${code} there.`;
  $("request").hidden = false;
  step(0);
  const go = $("go"), cancel = $("cancel");
  go.textContent = label;
  go.disabled = false;
  cancel.textContent = "Cancel";
  go.onclick = async () => {
    go.disabled = cancel.disabled = true;
    $("status").hidden = true;
    step(1);
    try {
      if (two) {
        const got = await deriveTwo(request);
        step(2);
        const sealed = [];
        for (let k = 0; k < got.secrets.length; k++) {
          const s = await seal(got.secrets[k], request.pk, request.state, request.mode, request.owners[k], got.cred);
          got.secrets[k].fill(0);
          sealed.push({ owner: request.owners[k], epk: b64urlEncode(s.epk), ct: b64urlEncode(s.ct), tag: b64urlEncode(s.tag) });
        }
        answered = true;
        post({ type: MESSAGES.answer, v: 2, state: request.state, cred: got.cred, sealed });
        say(`Done here. Type the code ${code} in the manager; this window closes once it has the keys.`);
        return;
      }
      const got = await run(request);
      step(2);
      const sealed = await seal(got.secret, request.pk, request.state, request.mode, request.owner, got.cred);
      got.secret.fill(0);
      answered = true;
      post({ type: MESSAGES.answer, state: request.state, cred: got.cred, epk: b64urlEncode(sealed.epk),
             ct: b64urlEncode(sealed.ct), tag: b64urlEncode(sealed.tag) });
      say(`Done here. Type the code ${code} in the manager; this window closes once it has the ${enroll ? "secret" : "key"}.`);
    } catch (e) {
      step(0);
      say(`${e.name || "Error"}: ${e.message}. Try again, or cancel.`, "bad");
      status(`${e.name || "Error"}: ${e.message}`);
      go.disabled = cancel.disabled = false;
    }
  };
  cancel.onclick = () => {
    failed(enroll ? "the user did not create a passkey" : "the user did not unlock");
    window.close();
  };
}
