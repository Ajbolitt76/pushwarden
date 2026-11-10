# Manual test plan (PushWarden)

Use a **separate test Bitwarden account** (free is enough; TOTP checks need Premium), not your
real vault: moving items to level 2 rewrites them on the server.

## Setup

1. **Relay** (WSL): `cd relay && PORT=8080 DB_PATH=/tmp/relay.sqlite go run .`
2. **Phone → relay**: `adb.exe reverse tcp:8080 tcp:8080` (Windows adb). The phone now reaches
   the relay as `http://localhost:8080`, which the clients allow without TLS.
3. **Phone app**: `adb.exe install -r <apk>`; the debug APK is
   `upstream/android/app/build/outputs/apk/fdroid/debug/com.corex.pushwarden.dev-fdroid.apk`.
   Log in with the test account.
4. **Extension**: Chrome → `chrome://extensions` → Developer mode → Load unpacked →
   `\\wsl.localhost\Ubuntu\home\ajbolit76\work\offline-password-manager\upstream\clients\apps\browser\build`.
   Disable the official Bitwarden extension in this profile. Log in with the test account.
   Chrome on Windows reaches the WSL relay as `http://localhost:8080`.
5. Test site: any login form, e.g. https://github.com/login (don't submit) or a local page.

## Phase 1: level 2 format

| # | Do | Expect |
|---|---|---|
| 1 | Phone: Settings → Vault → Level 2 → enter a 20+ char password → Set up | "set up" status; a secure note "L2 key – do not edit" appears in the vault |
| 2 | Phone: open a GitHub login → ⋮ → Move to level 2 | dialog lists `github.com`; after confirm, snackbar "moved to level 2" |
| 3 | Phone: open the item | password shown in clear (decrypted on the phone) |
| 4 | Web vault / PC: open the item | password is `l2:v1:…`; password history empty |
| 5 | Phone: edit the item's notes, save; check the web vault | password still `l2:v1:…` |
| 6 | Phone: change the password, save | web vault shows a new `l2:v1:…` value, not plaintext |
| 7 | PC extension: fill the item on github.com | dialog "Protected item" |
| 8 | Enter wrong L2 password | "Wrong level 2 password" |
| 9 | Enter right L2 password | form filled with the real password |
| 10 | PC: try the same item on another site (add `evil.example` URI in the web vault) | "can't be filled on this website" |
| 11 | PC extension: Copy password on the L2 item | refused with a message |
| 12 | PC extension: open the L2 item; try Edit and Clone from the ⋮ menu | no Edit button on the view page; Edit/Clone show "edit it on your phone", no form, no Save |
| 13 | PC: submit a login form on github.com | no "save/update password" prompt |
| 14 | Phone: autofill the GitHub login in Chrome on the phone | real password filled |
| 15 | Phone: Move to level 1 | web vault shows plaintext again |

## Phase 2: phone approval

| # | Do | Expect |
|---|---|---|
| 16 | Phone: Level 2 → PC autofill → relay `http://localhost:8080` → Register | phone ID like `ab12-cd34`, "Connected" |
| 17 | Phone: Pair a computer. PC: Settings → Autofill → Phone approval → relay URL + phone ID + name → Pair | both show the same 5 words |
| 18 | PC: Words match; phone: Words match, pair (biometrics) | PC shows "Paired with phone …"; phone lists the PC |
| 19 | Repeat 17 but press "Words don't match" on the phone | PC shows pairing failed; nothing stored |
| 20 | Phone: keep PC autofill screen open. PC: fill L2 item → Approve on phone | phone shows "Fill github.com as <user> on <PC>?" |
| 21 | Approve with biometrics | PC fills; with an L2 TOTP the code is copied to the clipboard |
| 22 | Deny instead | PC: "denied on your phone" |
| 23 | Don't answer for 60 s | PC: "didn't answer in time" |
| 24 | Phone screen closed (app in background), PC: Approve on phone, then open the screen within 60 s | request appears and can be approved (relay queued it) |
| 25 | Phone: Unpair | PC fill via phone fails with "not paired"/timeout |
| 26 | Stop the relay, PC: Approve on phone | "Couldn't reach the relay server" |

Record failures with the step number, what happened, and `adb.exe logcat | grep -i l2` output.
