# PushWarden (two-level, Bitwarden-compatible vault)

L1 items work like normal Bitwarden. L2 items are encrypted a second time: the PC gets them
only by approving on the phone or typing a separate L2 password.

- [DESIGN.md](DESIGN.md): agreed flow, threat model, known limits
- [protocol/PROTOCOL.md](protocol/PROTOCOL.md): normative wire format, shared test vectors
- [ESTIMATE.md](ESTIMATE.md): work estimate per component
- [TESTING.md](TESTING.md): manual test plan on a phone + PC
- `branding/`: logo (`pushwarden.svg`), PNG renderer (`render.mjs`)

## Layout

```
protocol/          spec, TypeScript reference (libsodium), vectors, wordlist   MIT
relay/             relay server (Go, gorilla/websocket, pure-Go SQLite, FCM)   MIT
upstream/android   bitwarden/android fork: app/.../data/vault/l2, ui/.../settings/level2   GPL-3.0
upstream/clients   bitwarden/clients fork: apps/browser/src/autofill/l2                 GPL-3.0
upstream/ios       bitwarden/ios fork: PushWardenL2/ (Swift package), app wiring in progress   GPL-3.0
env.sh             JDK 21 + Android SDK paths
branding/          PushWarden logo and icon renderer
```

Android package id: `com.corex.pushwarden` (`.dev` for debug builds). Firefox add-on id:
`pushwarden@corex`. Both forks carry a `NOTICE.md` (GPL-3.0, not affiliated with Bitwarden).

`protocol/scripts/sync-to-clients.sh`, `sync-to-android.sh` and `sync-to-ios.sh` copy the reference code,
wordlist and vectors into the forks; re-run them after changing `protocol/`.

## Test

```sh
(cd protocol && npm test)            # vectors + unit tests
(cd relay && go test -race ./...)    # routing, queue, wake-ups, limits, hostile input
(cd upstream/clients/apps/browser && npx jest src/autofill/l2)
source env.sh && (cd upstream/android && ./gradlew :app:testFdroidDebugUnitTest --tests "*.l2.*")
(cd upstream/ios/PushWardenL2 && swift test)   # macOS, or Linux with libsodium-dev
```
Add `PW_RELAY_URL=http://localhost:8080` to the Swift tests to also run them against a live
relay. The WebSocket test needs macOS (Ubuntu's libcurl has no WebSocket support).

## Run the relay

```sh
cd relay && go build -o pushwarden-relay . && PORT=8080 DB_PATH=relay.sqlite ./pushwarden-relay
# or: docker build -f relay/Dockerfile -t pushwarden-relay . && docker run -p 8080:8080 -v pw:/data pushwarden-relay
```
Put it behind TLS (the clients require `https://`). `FCM_SERVICE_ACCOUNT=<file>` enables
phone wake-ups once the app supports them.

`upstream/` is a partial clone (`--filter=blob:none`): full history, file contents fetched on demand.

## Build the Android app

```sh
source env.sh
cd upstream/android
# needs user.properties with: gitHubToken=<GitHub token with read:packages>
./gradlew :app:assembleFdroidDebug
```

The `standard` flavor (FCM push) also needs `app/src/standard/google-services.json` from your own
Firebase project; it is git-ignored. The `fdroid` flavor builds without it.

## Build the iOS app (macOS + Xcode)

Needs a paid Apple Developer account (push notifications), Homebrew and Xcode 27
(`.xcode-version`).

```sh
cd upstream/ios
cat > Configs/Local-bwpm.xcconfig <<'X'
DEVELOPMENT_TEAM = <your Team ID, from developer.apple.com > Membership>
X
./Scripts/bootstrap.sh          # Mint tools + XcodeGen project generation
open Bitwarden.xcworkspace      # scheme Bitwarden, your iPhone, Run
```

The bundle ID is `com.corex.pushwarden`. The only entitlement removed from upstream is
associated domains: it claims `bitwarden.com`, which only Bitwarden's own app can use.

Push, one-time setup (the same Firebase project as the Android app):
1. developer.apple.com > Keys: create a key with "Apple Push Notifications service", download
   the `.p8`.
2. Firebase console > Project settings > add an iOS app `com.corex.pushwarden`; download
   `GoogleService-Info.plist` over `Bitwarden/Application/Support/GoogleService-Info.plist`
   (the checked-in one is a blank placeholder).
3. Firebase > Project settings > Cloud Messaging > Apple app configuration: upload the `.p8`
   with its Key ID and your Team ID.

The relay needs no change: every wake-up carries an Android data part and a fixed iOS alert
("A computer is asking to fill a password"), no item or site.

iOS status:
- done and tested on Linux: `PushWardenL2` (L2 crypto against the shared vectors, relay
  messages and push token, QR parsing, write guard, move to L1/L2, the approval engine),
  rebrand, icon, relay iOS alert;
- to do on the Mac: Keychain-backed L2 key and relay config stores, `VaultRepository` hooks
  (write guard on add/update, decrypt for view/edit/copy/AutoFill), L2 setup screen, PC autofill
  screen with QR scan (reuse `ScanCodeView`), full-screen approval with Face ID, Security level
  picker in the editor, lock marker in lists, FirebaseMessaging (token to
  `L2PcEngine.onPushToken`; tapping the alert opens the app, which then connects). Manual
  (phrase) pairing is not ported yet: iOS pairs by QR code only.

## Repositories

| Part | Repository | Branch |
|---|---|---|
| protocol, relay, docs (this repo) | https://github.com/Ajbolitt76/pushwarden | `main` |
| Android app | https://github.com/Ajbolitt76/pushwarden-android | `pushwarden` |
| Browser extension | https://github.com/Ajbolitt76/pushwarden-clients | `pushwarden` |
| iOS app (in progress) | https://github.com/Ajbolitt76/pushwarden-ios | `pushwarden` |

Check the forks out under `upstream/` (git-ignored here):

```sh
git clone --filter=blob:none -b pushwarden git@github.com:Ajbolitt76/pushwarden-android.git upstream/android
git clone --filter=blob:none -b pushwarden git@github.com:Ajbolitt76/pushwarden-clients.git upstream/clients
git clone -b pushwarden git@github.com:Ajbolitt76/pushwarden-ios.git upstream/ios
# each: git remote add upstream https://github.com/bitwarden/<repo>.git  (to pull Bitwarden updates)
```

PushWarden is not affiliated with Bitwarden, Inc.
