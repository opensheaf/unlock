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

Its content security policy lets it load nothing from another origin,
reach no server (`connect-src 'none'`) and send no form
(`form-action 'none'`). It uses the system's fonts.

## Tests

    node --test tests/

`tests/unlock.test.mjs` tests `unlock-core.js` (no browser needed), and
`tests/page.test.mjs` runs `unlock.js` against a double of the DOM and of
WebAuthn: no browser, no passkey.

## Licence

GPL-3.0-or-later.
