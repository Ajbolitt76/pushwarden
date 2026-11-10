# L2 protocol, version 1

Normative spec shared by the Android fork, the browser extension fork and the relay.
Reference implementation: `protocol/src` (TypeScript). Test vectors: `protocol/vectors`.
Both forks must pass the vectors.

Encoding rules for the whole document:
- `b64` = standard base64 with padding (RFC 4648 §4).
- Strings are UTF-8. JSON is RFC 8259; key order does not matter.
- `‖` = byte concatenation. All lengths are in bytes.
- Crypto is libsodium: `crypto_pwhash` (Argon2id 1.3), `crypto_secretbox_easy`
  (XSalsa20-Poly1305), `crypto_box_easy` (X25519 + XSalsa20-Poly1305), SHA-256.

## 1. L2 key item

One Bitwarden **Secure Note** with a **hidden** custom field named exactly `l2key`. The note's
name is `PushWarden key – do not edit` (only a hint for humans; clients find the item by the field,
so items created as `L2 key – do not edit` by earlier builds keep working).

Field value:
```json
{"v":1,"kdf":"argon2id","ops":3,"memMiB":256,"salt":"<b64, 16 bytes>","wrappedKey":"<b64>"}
```

- `KEK = crypto_pwhash(32, utf8(L2 password), salt, ops, memMiB·1024·1024, ARGON2ID13)`
- `wrappedKey = nonce(24) ‖ crypto_secretbox_easy(L2key(32), nonce, KEK)` (72 bytes)
- `L2key` is 32 random bytes, created once.

Readers must reject the item unless: `v == 1`, `kdf == "argon2id"`, `3 ≤ ops ≤ 10`,
`64 ≤ memMiB ≤ 1024`, salt is 16 bytes, wrappedKey is 72 bytes. The bounds stop a forged
key item from making unlock trivially cheap or exhausting memory.

If the vault holds more than one item with an `l2key` field, clients refuse L2 setup and
tell the user. A phone that already holds the L2 key never re-reads the key item.

Changing the L2 password re-wraps the same `L2key` with a new salt; items stay as they are.

## 2. L2 field value

Used for a login's `password` and `totp` fields:

```
l2:v1:<b64(nonce(24) ‖ crypto_secretbox_easy(payload, nonce, L2key))>
```

`payload` is UTF-8 JSON:
```json
{"f":"password","i":"<cipher id>","u":"alice@example.com","v":"<the secret>","h":["github.com"]}
```
Keys in this order (vectors depend on the exact bytes).
- `f`: `"password"` or `"totp"`. Decryptors must check it equals the field they read, so a
  TOTP ciphertext can't be pasted into the password field.
- `i`: the Bitwarden cipher id of the item. Decryptors must check it equals the id of the item
  they read it from. Items get L2 only after they exist on the server, so the id is known.
- `u`: the login's username when it was sealed (`""` if none). The phone shows this, not the
  L1 username, when asking to approve a fill.
- `v`: the plaintext secret.
- `h`: allowed hosts, lowercased hostnames taken from the item's URIs when it was encrypted
  (no scheme, port or path; IDNs in punycode). Fills on a PC are allowed only on these hosts.
  May be empty: the item can then only be used on the phone.

Why `i`, `u` and `h` are inside the ciphertext: URIs, names and usernames are L1, so malware
on a PC can change them, and it can copy ciphertext between items. It can't change `i`, `u` or
`h` without the L2 key. A ciphertext pasted into another item fails the `i` check, a renamed
username doesn't change what the phone shows, and an `evil.com` URI added to the real item
fails the `h` check.

`u` and `h` change only by an explicit "Move to level 2" on the phone, which shows the hosts
being authorized and re-seals with the item's current URIs and username. Any other save keeps
the `u` and `h` of the stored value, so a URI synced from a compromised PC is never authorized
by an unrelated edit on the phone. Every field is checked on its own: a TOTP value is released
only if its own `i`, `f` and `h` pass.

### Host match

An origin may be filled when its scheme is `https` (or `http` with host `localhost` or
`127.0.0.1`) and its host `o`, lowercased, satisfies for some `x` in `h`:
`o == x` or `o` ends with `"." + x`.

So `h = ["github.com"]` allows `github.com` and `gist.github.com`, not `evilgithub.com`.

### Plaintext detection

A field is L2 if and only if it starts with `l2:v1:`. Any other value is L1 plaintext.
A value starting with `l2:` but with an unknown version is an error, not plaintext: clients
must not fill it.

## 3. Relay

The relay forwards opaque ciphertext between devices and wakes phones with FCM. It is not
trusted with content: everything it routes is end-to-end encrypted (§4) and pairing is
verified by the user (§5).

### Devices

Each device (phone or browser extension) has a long-term X25519 keypair
(`crypto_box_keypair`). It registers once:

```
POST /v1/devices
{"publicKey":"<b64, 32 bytes>","kind":"phone"|"ext","pushToken":"<FCM token>"?}
→ 201 {"id":"<device id>","token":"<b64 secret>"}
```
- `id`: 8 characters of Crockford base32 (lowercase, no `i l o u`) split as `xxxx-xxxx`, e.g.
  `ab12-cd34`. The phone's id is the handle the user types into the extension.
- `token`: 32 random bytes; the relay keeps only its SHA-256. Authenticates the device
  to the relay; it is not a content key.
- `pushToken` is accepted only for `kind: "phone"`.

Other HTTP calls (`Authorization: Bearer <token>`):
```
GET    /v1/devices/<id>      → 200 {"id","kind","publicKey"}   (no auth; public info)
PUT    /v1/devices/me        {"pushToken":"..."} → 204
DELETE /v1/devices/me        → 204
```

### WebSocket

`GET /v1/ws`. The first client frame must be `{"t":"auth","token":"..."}` within 10 s
(browsers can't set headers on WebSockets). The relay answers `{"t":"ready","id":"..."}` and
then delivers queued messages. A second connection for the same device replaces the first.

Client → relay:
```json
{"t":"send","to":"<device id>","body":"<b64>"}
{"t":"ping"}
```
Clients send `ping` every 20 s (the relay answers `{"t":"pong"}`): message traffic keeps a
Chrome MV3 service worker alive, protocol-level pings don't.
Relay → client:
```json
{"t":"msg","from":"<device id>","fromPk":"<b64>","body":"<b64>","at":<unix ms>}
{"t":"error","code":"unknown_device"|"rate_limited"|"too_large"|"bad_request"|"auth_failed"}
```

Rules:
- `body` decodes to at most 8 KiB.
- If the recipient is online, deliver now. Otherwise queue it for 120 s (max 20 per
  recipient, oldest dropped) and, if the recipient is a phone with a push token, send an FCM
  high-priority data message `{"t":"wake"}`. No content goes to FCM.
- Delivery is at most once: a queued message is deleted when handed to a socket.
- `fromPk` is the sender's registered public key. Recipients must not trust it beyond §5:
  after pairing they compare it to the stored key and drop anything else.
- Limits: 60 `send` per device per minute; 10 registrations per IP per hour.

## 4. End-to-end messages

`body = b64(nonce(24) ‖ crypto_box_easy(utf8(JSON), nonce, recipientPk, senderSk))`

Every message JSON has `"v":1` and a `"type"`. Unknown types are ignored.

| type | direction | fields |
|---|---|---|
| `pairRequest` | ext → phone | `name` (PC label, ≤ 64 chars), `commit` (b64, 32) |
| `pairChallenge` | phone → ext | `nonce` (b64, 32) |
| `pairReveal` | ext → phone | `nonce` (b64, 32) |
| `pairAccept` | phone → ext | `nonce` (b64, 32): the `nExt` of this attempt |
| `pairReject` | phone → ext | `nonce` (b64, 32): the `nExt` of this attempt, if known |
| `qrPair` | phone → ext | `proof` (b64, 32), `name` (phone label, ≤ 64 chars) |
| `fillRequest` | ext → phone | `requestId` (b64, 16), `itemId`, `origin`, `time` (unix ms) |
| `fillResult` | phone → ext | `requestId`, `status`, `password`?, `totp`? |
| `unpair` | either | — |

`status` is one of `approved`, `denied`, `expired`, `rejected` (rule failure), `error`.
`password` (string, required) and `totp` (string of 6–8 digits, optional) appear only with
`approved`; `totp` is the current code, never the seed.

Limits, counted in UTF-16 code units after JSON decoding: `name` ≤ 64, `itemId` ≤ 64,
`origin` ≤ 2048, `password` ≤ 4096. Senders check them before sealing; receivers reject
messages that break them.

`pairAccept` and `pairReject` echo `nExt`, so the relay can't replay one from an earlier
attempt. `unpair` is not bound to a pairing: a malicious relay could replay an old one, but it
can drop all traffic anyway, so the only effect is the same denial of service.

## 5. Pairing

Commit-then-reveal, so a relay that swaps keys gets one guess at the phrase instead of an
offline search.

1. Phone, on the "PC autofill" screen, shows its id. **The phone accepts `pairRequest` only
   while this screen is open.** Requests at other times are dropped without notification.
2. Extension: user enters relay URL + phone id. The extension fetches
   `GET /v1/devices/<id>` → `phonePk` (must be `kind: "phone"`), picks a random 32-byte
   `nExt`, and sends `pairRequest{name, commit = SHA-256("l2-commit-v1" ‖ extPk ‖ nExt)}`.
3. Phone takes `extPk` = the message's `fromPk`, picks a random 32-byte `nPhone`, sends
   `pairChallenge{nonce: nPhone}`.
4. Extension sends `pairReveal{nonce: nExt}`.
5. Phone checks the commitment; on mismatch it sends `pairReject{nonce: nExt}` and stops.
6. Both compute the phrase over the keys **they** see:
   `H = SHA-256("l2-pair-v1" ‖ phonePk ‖ extPk ‖ nExt ‖ nPhone)`; for `i` in 0..4,
   `word[i] = wordlist[uint32_be(H[4i..4i+4]) mod 7776]`. Wordlist: EFF large wordlist,
   `protocol/wordlist/eff_large_wordlist.txt` (7,776 words, line `n` = index `n−1`).
   Shown as words joined by `-`.
7. User checks both screens show the same phrase, then approves on the phone with
   biometrics (→ `pairAccept{nonce: nExt}`, phone stores `{id, extPk, name}`) **and** confirms
   on the extension. The extension stores `{relayUrl, phoneId, phonePk}` only after both the
   user's confirmation and a `pairAccept` from `phonePk` echoing this attempt's `nExt`.

Each side drops a pairing attempt after 120 s or on any out-of-order message, and allows one
attempt at a time.

### 5b. Pairing by QR code (preferred)

The extension shows a QR code; the phone scans it. The QR code is the authenticated channel,
so no words need comparing.

1. Extension (registered with the relay, WebSocket open) picks a random 32-byte secret `s`
   and shows:
   ```
   pushwarden://pair?v=1&r=<relay URL>&e=<ext device id>&k=<extPk>&s=<s>&n=<PC name>
   ```
   `k` and `s` are base64url without padding; `r` and `n` are percent-encoded. `s` is valid
   for one pairing and at most 120 s.
2. Phone parses it, registers with relay `r` if it isn't registered there, asks the user to
   confirm "Pair with <n>?" with biometrics, stores `{e, extPk = k, n}` and sends
   `qrPair{proof, name}` to `e`, where
   `proof = HMAC-SHA256(key = s, "l2-qr-v1" ‖ phonePk ‖ extPk)`.
3. Extension accepts the first `qrPair` whose `proof` matches for the message's `fromPk`, stores
   `{relayUrl, phoneId = from, phonePk = fromPk}`, and forgets `s`.

A relay that swaps keys can't produce `proof` without `s`, which only crossed the screen.
Someone who photographs the QR code within its lifetime could pair instead of the user; the
extension shows which phone paired, and the user can unpair.

## 6. Fill

Extension, when the user fills an item whose password starts with `l2:v1:`:
1. Sends `fillRequest{requestId: random 16 bytes, itemId, origin, time: now}` to the
   paired phone. `origin` is the tab's origin (`https://host[:port]`).
2. Waits up to 60 s for `fillResult` with that `requestId`, from the paired phone id and
   public key. Anything else is dropped. Each `requestId` is accepted once.

Phone, on `fillRequest`:
1. Drop unless `fromPk` is a paired extension key.
2. `rejected` if `|now − time| > 60 s`, `requestId` was seen in the last 10 minutes, or
   that extension already has 3 requests waiting for the user.
3. Look up `itemId` in the phone's vault. Decrypt its L2 password (§2, including the `i`
   check). `rejected` if `origin` fails the host match against `h`. The L1 URIs are not
   consulted.
4. Notify: "Fill **<host>** as <`u` from the payload> on <PC name>?". Approve needs
   biometrics.
5. Reply `approved` with `password`, plus `totp` when the account may use TOTP
   (`isPremium || organizationUseTotp`) and either the TOTP is L2 and passes its own `i`,
   `f` and host checks, or it is L1. Otherwise `denied`, or `expired` if 60 s passed since
   `time`.

## 7. Versioning

Breaking changes bump `v` in the affected structure (`l2:v2:`, key item `"v":2`, message
`"v":2`) and the relay path (`/v2/`). Readers reject versions they don't know.
