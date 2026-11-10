# Two-level Bitwarden vault with phone-approved fills

Status: phase 1 and 2 implemented, not yet tested on devices. Last updated 2026-11-09.
The wire format is normative in [protocol/PROTOCOL.md](protocol/PROTOCOL.md).

## Goal

Two secrecy levels in one normal Bitwarden vault (Bitwarden cloud or Vaultwarden,
server protocol unchanged):

| Level | Synced | Decrypted on PC | How the PC gets the password |
|---|---|---|---|
| **L1** (most items) | Yes | Yes, as today | Our forked Bitwarden extension, unchanged behaviour |
| **L2** (sensitive items) | Yes | Only if you type the L2 password on the PC | Same extension: approve on phone (default), or type the L2 password |

If the PC is compromised, L1 is lost (as with plain Bitwarden today), but L2 items are not,
unless they were approved or the L2 password was typed on that PC while it was infected.

## Threat model

| Device | Trust | Has |
|---|---|---|
| Phone (Android, forked Bitwarden app) | Trusted | Vault key + L2 key (wrapped by an Android Keystore key) |
| PC | Untrusted | Vault key (L1 plaintext), L2 **ciphertext** only |
| Relay (ours) | Untrusted | Routing ids, push tokens, ciphertext |
| Bitwarden cloud / Vaultwarden | As today | Encrypted vault; L2 is encrypted twice |

Not protected:
- L2 passwords approved or decrypted on an infected PC (malware reads the form).
- **Typing the L2 password on an infected PC exposes all L2 items** (keylogger). Use the
  PC-password path only on a PC you trust; use the phone path otherwise.
- **Offline guessing:** an attacker with L1 access has the L2 ciphertext and can guess the L2
  password offline. It must be strong (at least 5 random words) and is stretched with
  Argon2id.
- Session cookies stolen after login.
- Passkeys stored in Bitwarden are always L1 (decrypted on the PC). For L2 accounts keep
  passkeys outside Bitwarden (hardware key or a phone-bound passkey).

## L2 storage format (Bitwarden-compatible)

Only standard Bitwarden fields are used, so every official client and server keeps working.
Official clients just show L2 values as ciphertext.

**Key item**: one Secure Note named `PushWarden key – do not edit`, with a hidden custom field `l2key`:
```json
{"v":1,"kdf":"argon2id","ops":3,"memMiB":256,"salt":"<b64>","wrappedKey":"<b64>"}
```
- L2 password → Argon2id(salt) → KEK. KEK decrypts `wrappedKey` → random 32-byte **L2 key**.
- Changing the L2 password re-wraps the L2 key; items are not re-encrypted.

**L2 login item**:
- `password` = `l2:v1:<b64(nonce ‖ secretbox(payload, L2 key))>`, where `payload` is JSON
  `{"f":"password","i":<item id>,"u":<username>,"v":<password>,"h":[allowed hosts]}`
  (PROTOCOL.md §2).
- `totp` (if any) = same format, so the TOTP seed is protected too.
- `i`, `u` and `h` are sealed inside: malware on the PC can edit the L1 URIs and username or
  paste ciphertext into another item, but fills only go to hosts in `h`, only for the item
  named by `i`, and the phone's approval prompt shows the sealed `u`.
- `u` and `h` change only by an explicit "Move to level 2" on the phone, which lists the hosts
  first. Ordinary saves keep the sealed values, so a URI synced from an infected PC is never
  authorized by an unrelated edit.
- Username, name, URIs and notes stay L1: the PC sees which sites are L2 and the usernames.
- URIs and match settings are untouched, so our extension suggests L2 items like any other.
  An **official** Bitwarden client would fill the ciphertext into the site; to stop that on
  machines running official clients, set the item's URI match to Never (optional).

We use the password field plus one key item instead of the notes field: notes are free text
the user edits, and a per-item marker isn't needed because the `l2:v1:` prefix is the marker.

Crypto: libsodium on both sides. `crypto_pwhash` (Argon2id) and `crypto_secretbox`
(XSalsa20-Poly1305). Same library for the relay channel below.

## Components

```
Bitwarden cloud / Vaultwarden (unchanged)
   ▲ sync                                   ▲ sync
   │                                        │
Phone: forked Bitwarden Android app     PC: forked Bitwarden browser extension
   │  ▲ FCM push                               │  (thin patch: L2 hook in the fill path)
   ▼  │                                        │
Relay (ours) ◄─── WebSocket, E2E-encrypted ────┘
```

1. **Android fork** (`bitwarden/android`, own name and `applicationId`):
   - L2 setup: create or unlock the key item; the L2 key is stored wrapped by an Android
     Keystore key and is usable while the vault is unlocked. PC fill approvals and pairing ask
     for biometrics (or the device credential) each time.
   - Shows and autofills L2 items as normal on the phone: the item screen and phone autofill
     get decrypted copies; every save goes through a guard that re-encrypts, so plaintext never
     replaces an L2 value (a save fails instead if the L2 key isn't on this phone).
   - "Move to L2" / "Move to L1" per item and in bulk.
   - Pairing, paired-PC list, fill approval screen, relay client.
2. **Forked Bitwarden browser extension** (`bitwarden/clients`, `apps/browser`), kept as a
   thin patch so it rebases easily:
   - Fill hook: next to the existing master-password re-prompt check
     (`AutofillService.isPasswordRepromptRequired`), an `l2:v1:` password opens a popout:
     "Approve on phone" or "Enter L2 password". The fill continues with the plaintext.
     Covers every fill path (inline menu, popup, keyboard shortcut, context menu).
   - Save/update prompts: never offer to save or update a password on a site with an L2
     item, so a filled L2 password is never written back as plaintext L1.
   - Phase 2: pairing screen and relay client.
3. **Relay** (new, small): forwards E2E-encrypted messages, wakes the phone with FCM.

Why a fork and not a second extension next to the official one: two extensions on one page
fight. Both draw inline menus on login fields, and the official one would offer to save the
L2 password we just filled as a new plaintext login. The repo is busy (1,097 commits in 90
days), but the files we patch are quiet: `autofill.service.ts` 9 commits,
`overlay.background.ts` 6, `notification.background.ts` 3.

Do not run the official Bitwarden extension on the same browser.

## Flows

### 1. L2 setup (once, on the phone)
1. Settings → "Level 2" → choose a strong L2 password.
2. Phone creates the L2 key, writes the key item, keeps the L2 key in Keystore (biometric).
3. On a second phone: enter the L2 password once to unlock the existing key item.

### 2. Moving an item to L2 (phone)
1. Encrypt password and TOTP with the L2 key.
2. **Remove the plaintext from password history.** Bitwarden normally saves the old password
   in history on change, which would leave it readable on the PC.
3. Save through the normal Bitwarden API.

Moving back to L1 reverses this.

### 3. Pairing a PC (once per browser, no QR)
Modelled on Bitwarden's "Log in with device".
1. Phone: Settings → Vault → Level 2 → PC autofill → enter the relay URL. Phone registers and
   shows a short handle, e.g. `ab12-cd34`. Tap "Pair a computer".
2. Extension: Settings → Autofill → Phone approval: enter relay URL + handle.
3. Commit-then-reveal exchange (PROTOCOL.md §5), then both screens show the same 5 words.
   Confirm on the extension and approve on the phone with biometrics. A relay that swaps keys
   gets one guess at the words, not an offline search.

No item list is sent: the extension already has the synced vault.

We don't use Bitwarden's own login-request API for pairing: approving it sends the vault key.

### 4. Fill an L2 item on the PC
1. User fills the item the usual Bitwarden way (inline menu, popup, shortcut). The L2 hook
   opens a popout.
2. Choose:
   - **Approve on phone** (default): extension sends
     `FillRequest{requestId, itemId, origin, time}` via the relay. Phone notification:
     "Fill **github.com** as alice@example.com on Home PC?". Approve with biometrics. Phone
     replies with `{requestId, password, totp?}` encrypted to the extension's key.
   - **Enter L2 password**: extension derives the key with Argon2id, decrypts locally, fills,
     and forgets the key and password. No caching.
3. Extension fills the form and drops the secret from memory.

TOTP is returned only when allowed today (`isPremium || organizationUseTotp`, as in
`AutofillTotpManagerImpl`).

### Request rules (phone)
- The origin must match one of the item's hosts. Mismatch → rejected, no override.
- Requests expire after 60 s; each `requestId` is answered once.
- At most 3 pending requests per PC; more → auto-deny and a warning.
- Unknown or revoked extension keys are dropped.

## Relay channel crypto

- Each device has a long-term X25519 keypair, exchanged at pairing.
- Payloads are libsodium `crypto_box` between the two known keys (encrypts and authenticates
  the sender), with `requestId` + timestamp against replay.
- Fingerprint phrase: words from SHA-256 over both public keys.
- No forward secrecy in v1. Upgrade path: ephemeral X25519 per message.

## Push

The fork has its own `applicationId`, so Bitwarden's pushes don't reach it; vault sync happens
on app open and pull-to-refresh (like upstream's F-Droid build). Relay → phone wake-ups use our
own Firebase project.

## Known limitations

- Editing an L2 password in an official client (web vault, PC extension) saves it as
  plaintext, silently downgrading it to L1.
- In our extension, an L2 item can't be edited or cloned (the editor shows a notice instead of
  the form, and the save path still refuses plaintext over L2 values), and its password or TOTP
  can't be copied; viewing it shows the ciphertext. Change L2
  values on the phone. Official clients aren't guarded: see the first point above.
- The forked extension is not in the Chrome/Firefox stores: load it unpacked in Chrome,
  and sign it as unlisted on Firefox's add-on site.
- Only login password and TOTP are L2 in v1, not cards, identities, notes or custom fields.
- No key id in the `l2:v1:` format: rotating the L2 key itself (not the password) needs all
  L2 items re-encrypted.
- **v1 phone has no push and no notification**: fill requests are shown while the phone's
  PC autofill screen is open; the relay keeps a request for 120 s and the extension waits
  60 s. FCM wake-ups and a notification for the `standard` flavor are the next step.
- An item becomes L2 only after it exists on the server (create it, then "Move to level 2"),
  because `i` needs its id. Moving purges its plaintext password history.
- The phone's "Verification codes" list reads TOTP seeds through the SDK, so an L2 TOTP seed
  shows no code there; the item screen and PC fills do work.
- `steam://` TOTP seeds give no code on a PC fill.

## Licensing and naming

| Part | License |
|---|---|
| Android fork | GPL-3.0 (required); `sdk-internal` under its GPL option |
| Browser extension fork | GPL-3.0. Build without `bitwarden_license/` code (the OSS build) |
| Relay | MIT |

Own names and icons. Each repo gets a NOTICE: "Not affiliated with Bitwarden, Inc."

## User-facing names

The docs and code say L1/L2; the apps never do. Same words on every platform:

| Internal | Shown to users |
|---|---|
| L1 item | Standard |
| L2 item | Protected |
| L2 password | Protection password |
| Security level selector | Protection |
| Phone: L2 settings | Settings → Vault → Protected items |
| Phone: pairing and approvals | … → Protected items → Computer approvals |
| Extension: pairing | Settings → Phone approval |
| Key item | "PushWarden key – do not edit" |

## Assumptions and open questions

- Phone is Android or iPhone. The iOS app pairs by QR code only. iPhones get a visible push
  alert (fixed text, no item or site) instead of Android's silent wake-up.
- Bitwarden's terms don't clearly cover modified clients on their cloud. Fallback: Vaultwarden.
- Argon2id at 256 MiB must run acceptably on the phone. Tune once on real hardware.
- Related upstream proposal: https://community.bitwarden.com/t/102490
