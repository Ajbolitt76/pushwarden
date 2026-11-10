# PushWarden

A Bitwarden-compatible password manager for people who don't fully trust their computers.

Your vault stays on your Bitwarden account and keeps working with the official apps. On top of
that, PushWarden lets you mark your most important logins as **Protected**: their password and
verification code are encrypted a second time, with a key that never leaves your phone. A
computer can fill a protected login only after you approve it on your phone (or type your
separate protection password), and only on the websites the item was protected for. Malware on
a computer that reads your vault sees only ciphertext.

PushWarden is not affiliated with Bitwarden, Inc.

## How it works

1. **Phone**: Settings → Vault → Protected items → choose a protection password. This creates
   a "PushWarden key – do not edit" note in your vault holding the protection key, wrapped with
   Argon2id.
2. **Pair a computer**: in the browser extension, Settings → Phone approval → show the QR code;
   on the phone, Protected items → Computer approvals → scan it.
3. **Protect a login**: on the phone, edit it and set Protection to Protected. The sealed value
   is bound to the item, its username and its websites.
4. **Fill**: the extension asks the phone through the relay. The phone shows which site, account
   and computer are asking; you approve with your fingerprint or face, and the password goes
   back end-to-end encrypted.

The relay only forwards encrypted messages between your devices and wakes your phone with a
push notification that carries no item, site or computer name. The wire format is specified in
[protocol/PROTOCOL.md](protocol/PROTOCOL.md).

## Repositories

| Part | Repository | Branch |
|---|---|---|
| Protocol, relay, branding (this repo) | https://github.com/Ajbolitt76/pushwarden | `main` |
| Android app | https://github.com/Ajbolitt76/pushwarden-android | `pushwarden` |
| Browser extension (Chrome, Firefox) | https://github.com/Ajbolitt76/pushwarden-clients | `pushwarden` |
| iOS app (in progress) | https://github.com/Ajbolitt76/pushwarden-ios | `pushwarden` |

```
protocol/   spec, TypeScript reference implementation (libsodium), test vectors, wordlist   MIT
relay/      relay server in Go (WebSocket, SQLite, FCM/APNs wake-ups)                        MIT
branding/   PushWarden logo and icon renderer
```

The app forks are GPL-3.0, like Bitwarden's clients, and are built without any code under the
Bitwarden License.

## Run the relay

```sh
cd relay && go build -o pushwarden-relay . && PORT=8080 DB_PATH=relay.sqlite ./pushwarden-relay
# or: docker build -f relay/Dockerfile -t pushwarden-relay . && docker run -p 8080:8080 -v pw:/data pushwarden-relay
```

Put it behind TLS: the apps only accept `https://` relays (plain `http://` only for localhost).
Set `FCM_SERVICE_ACCOUNT=<service account JSON>` to wake phones with push notifications, and
`TRUST_PROXY=1` behind a reverse proxy.

## Build the apps

Check the forks out next to this repo, under `upstream/`:

```sh
git clone --filter=blob:none -b pushwarden https://github.com/Ajbolitt76/pushwarden-android.git upstream/android
git clone --filter=blob:none -b pushwarden https://github.com/Ajbolitt76/pushwarden-clients.git upstream/clients
git clone -b pushwarden https://github.com/Ajbolitt76/pushwarden-ios.git upstream/ios
```

- **Android** (JDK 21, Android SDK): `./gradlew :app:assembleFdroidDebug`. The `standard` flavor
  adds push and needs `app/src/standard/google-services.json` from your own Firebase project.
- **Browser extension** (Node 24): `npm ci`, then `cd apps/browser && npm run build:chrome`, and
  load `apps/browser/build` unpacked in Chrome.
- **iOS** (macOS, Xcode 27, paid Apple Developer account for push): put your
  `DEVELOPMENT_TEAM` in `Configs/Local-bwpm.xcconfig`, run `./Scripts/bootstrap.sh` and open
  `Bitwarden.xcworkspace`. Push needs an APNs key uploaded to your Firebase project and its
  `GoogleService-Info.plist`.

`protocol/scripts/sync-to-*.sh` copy the shared test vectors and wordlist into the forks.

## Test

```sh
(cd protocol && npm ci && npm test)
(cd relay && go test -race ./...)
(cd upstream/clients/apps/browser && npx jest src/autofill/l2)
(cd upstream/android && ./gradlew :app:testFdroidDebugUnitTest --tests "*.l2.*")
(cd upstream/ios/PushWardenL2 && swift test)   # macOS, or Linux with libsodium-dev
```

## Limitations

- Official Bitwarden apps don't know about protected items: editing a protected password there
  saves it as plaintext, which quietly makes it a standard item again.
- Protected items are edited on the phone only; the extension can't edit, clone or copy them.
- Only a login's password and verification code can be protected, not cards, notes or custom
  fields. Items in organization vaults can't be protected.
- The phone's "Verification codes" list shows no code for a protected seed; the item itself and
  computer fills do. `steam://` codes aren't filled on a computer.
- The extension isn't in the browser stores yet; load it unpacked.
- The iOS app is not finished: the shared core and branding are done, the screens are not.
