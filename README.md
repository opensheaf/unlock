# OpenSheaf unlock

The passkey unlock page of [`osheaf`](https://github.com/opensheaf/opensheaf-py),
served at <https://unlock.opensheaf.org/>, an origin that serves this page
and nothing else. It is also the relying party of the passkeys it makes
(`RP_ID` in `unlock-core.js`), so that no other page of the project's sites
can ask these passkeys for their secrets.

`osheaf key enroll` and `osheaf key unlock` let a passkey, with Touch ID,
open the keys of an owner kept in a key wallet, instead of the passphrase.
`osheaf` starts a one-time listener on `127.0.0.1`, prints a confirmation
code, and opens

    https://unlock.opensheaf.org/#mode=enroll|unlock&port=…&state=…&pk=…&owner=…[&cred=…]

The request is in the fragment, which the browser sends to no server; the
page takes it out of the address at once, checks every parameter and
refuses anything else (and refuses to run inside a frame). It computes the
PRF salt from the owner, SHA-256 of `opensheaf wallet unlock v1 ` and the
owner name, and shows the confirmation code, the first four bytes of
SHA-256(`opensheaf unlock code v1` ‖ state ‖ pk) modulo 10⁶. Its button stays
disabled until the user ticks "The terminal shows the same code". Then it
creates a passkey for `unlock.opensheaf.org` named after the owner
(excluding the passkeys the owner has already, `cred=`, and refusing a
passkey whose PRF extension is not enabled), or uses one of those named,
and derives its secret with the WebAuthn PRF extension.

It hands the secret back by going to
`http://127.0.0.1:<port>/callback?state=…&epk=…&ct=…&tag=…&cred=…` (with
`location.replace`, and only after a click), or `?state=…&error=…`, with
which `osheaf` asks for the passphrase instead. The hand-off: an ephemeral
X25519 key pair of the page (private key not extractable), HKDF-SHA256 of
the shared secret with `pk` (salt: the state; info: `opensheaf unlock
hand-off v2`) giving an encryption key and a MAC key; `ct` is the secret
XOR the encryption key, `tag` HMAC-SHA256 of `mode|owner|cred|pk|epk` and
`ct` (encrypt-then-MAC, so that `osheaf` needs no AES-GCM). A test vector
is shared with the tests of opensheaf-py.

## The popup of the OpenSheaf manager

The [manager](https://manager.opensheaf.org/) writes archives from the
browser, signing with the owner's current keys from its key wallet, which
a passkey opens. A page of another origin cannot use these passkeys, so
the manager opens this page in a window of its own:

    https://unlock.opensheaf.org/#mode=popup&origin=https%3A%2F%2Fmanager.opensheaf.org

and the two talk by window messages (`postMessage`), never through an
address. The origin must be on the list `POPUP_OPENERS` of
`unlock-core.js` (`https://manager.opensheaf.org`; a page served from
`localhost` or `127.0.0.1` may be opened by another such page, for
trying it out). The manager has an origin of its own so that no other
page of the project's sites, such as the archives and collections served
under `https://opensheaf.org/`, can open this page and ask for the
passkey. The page then:

1. tells its opener it is ready, `{type: "opensheaf-unlock-ready"}`,
   with that origin as the target: a page of another origin that opened
   it hears nothing;
2. takes one request, `{type: "opensheaf-unlock-request", state, pk,
   owner, cred}`, from its opener only (`event.source`) and from that
   origin only (`event.origin`), checked as the fragment of `osheaf` is;
3. shows the code of six digits, asks for the passkey on a click, and
   seals its secret as for `osheaf` (the same X25519, HKDF and
   encrypt-then-MAC), with the mode `popup` in the authenticated data, so
   that an answer for a popup is never one for `osheaf`, nor the other
   way round;
4. posts `{type: "opensheaf-unlock-answer", state, epk, ct, tag, cred}`
   (or `{..., error}`) to its opener, to that origin only, and waits; the
   person types the code into the manager, which opens the answer only
   with it, and then sends `{type: "opensheaf-unlock-done"}`, upon which
   the page closes.

To set up a key wallet from the browser, the manager opens the page with
`#mode=popup-enroll&origin=...` instead. The exchange is the same, but the
request's `cred` names the passkeys the owner has already (possibly none),
which WebAuthn is asked to exclude; the page creates a passkey for
`unlock.opensheaf.org` named after the owner, as for `osheaf key enroll`
(refusing a passkey whose PRF extension is not enabled), derives its
secret, and seals it with the mode `popup-enroll` in the authenticated
data: an answer of one mode is never taken for another. The manager then
adds the passkey's lock to the keys of the wallet, which it opens with the
passphrase. When the owner has a passkey already, the manager uses the
mode `popup` to unlock with it, as `osheaf key enroll` without
`--new-passkey` does.

A test vector of the popup's answer, in both modes, is shared with the
tests of opensheaf-js (`tests/github.test.js`), which play the manager's
side.

Its content security policy lets it load nothing from another origin,
reach no server (`connect-src 'none'`) and send no form
(`form-action 'none'`). It uses the system's fonts.

## Tests

    node --test tests/

`tests/unlock.test.mjs` tests `unlock-core.js` (no browser needed), and
`tests/page.test.mjs` runs `unlock.js` against a double of the DOM and of
WebAuthn, and, for the popup, of the manager's window: no browser, no
passkey.

## Licence

GPL-3.0-or-later.
