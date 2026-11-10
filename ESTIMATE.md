# Work estimate

Based on reading `bitwarden/android` (tag v2026.11.0-bwpm) and `bitwarden/clients` on
2026-11-09. One experienced developer, full time. See [DESIGN.md](DESIGN.md).

## Summary

| Phase | Delivers | Effort |
|---|---|---|
| **1. L2 format** | Phone: L2 setup, move items to/from L2, use L2 items on the phone. PC: forked Bitwarden extension fills L2 items after you type the L2 password. No relay yet. | **~8 weeks** |
| **2. Phone approval** | Relay, pairing, "Approve on phone" in the fill popout. | **+7 weeks** |
| Total |  | **~15 weeks** |
| Upkeep | Rebase both forks on upstream | ~1.5 days/month |

Phase 1 delivers the security gain on its own. Phase 2 adds the convenience.

## Android fork: ~6.5 weeks

Reusable code that already exists:
- Approval screens: `ui/platform/feature/settings/accountsecurity/loginapproval` (~800 lines)
  and `pendingrequests` (~850 lines).
- URI → item matching: `CipherMatchingManager.filterCiphersForMatches`.
- TOTP and premium check: `VaultRepository.generateTotp`, `AutofillTotpManagerImpl`.
- Biometric-bound Keystore keys: existing biometric vault unlock.
- Push plumbing: `PushManagerImpl`, `standard` flavor `BitwardenFirebaseMessagingService`.

| Task | Phase | Days |
|---|---|---|
| Rebrand: `applicationId`, name, icon, own Firebase project, NOTICE | 1 | 2 |
| L2 crypto (libsodium), key item create/unlock, Keystore + biometrics | 1 | 4 |
| Decrypt L2 on read, re-encrypt on save, purge password history | 1 | 4 |
| Move to L2 / L1, single and bulk | 1 | 3 |
| Relay client, FCM handling, device keys | 2 | 4 |
| Pairing with fingerprint phrase, paired-PC list, unpair | 2 | 5 |
| Fill request notification + approval screen + request rules | 2 | 5 |
| Tests (repo convention: unit tests per view model / manager) | 1+2 | 6 |

The riskiest task is "decrypt on read, re-encrypt on save". Any save path that bypasses it
writes plaintext back to the server. Every write path to the vault needs a test.

## Browser extension fork: ~4.5 weeks

A thin patch on `bitwarden/clients` `apps/browser`. Hook points:
- `AutofillService.isPasswordRepromptRequired` (`autofill.service.ts`): every fill path
  passes here; the existing master-password re-prompt already opens a popout from it.
- `notification.background.ts`: save/update password prompts.

Churn on these files is low: 9 and 3 commits in the last 90 days (the whole repo: 1,097).

| Task | Phase | Days |
|---|---|---|
| Monorepo build (Node 24, `npm ci`, OSS browser build for Chrome + Firefox), rebrand | 1 | 3 |
| L2 hook + popout ("Enter L2 password"), modelled on the re-prompt popout (Angular) | 1 | 5 |
| L2 crypto: key item parsing, Argon2id + secretbox (libsodium) | 1 | 2 |
| No save/update prompts on sites with an L2 item | 1 | 2 |
| Pairing screen, key storage | 2 | 3 |
| Relay WebSocket in the service worker (keep-alive, reconnect) | 2 | 2 |
| "Approve on phone" option in the popout | 2 | 2 |
| Tests (Jest, repo convention) | 1+2 | 4 |

## Relay: 1 week (phase 2)

Go, WebSocket, FCM HTTP v1, SQLite routing table, Dockerfile. ~400–600 lines.

## Shared format spec + test vectors: 4 days (phase 1)

L2 key item and `l2:v1:` format, relay messages, fingerprint phrase. Kotlin and TypeScript
code must both pass the same vectors.

## Integration and dogfooding: 2 weeks (one per phase)

Real phone + browsers; failure cases (phone offline, vault locked, relay down, item edited
in an official client).

## Risks

- **Plaintext leaks back to the server** through a save path the forks don't intercept.
  Mitigated by tests on every write path, on both forks.
- **Upstream churn**: Android ~195 commits / 90 days; clients 1,097 but low on the patched
  files. Keep each fork's changes in new files with few hook points.
- **Angular / monorepo learning curve** for the extension fork if you haven't used them.
- **Argon2id cost on the phone**: may need lower memory settings, which weakens resistance
  to offline guessing.
- **Firefox MV3** background lifetime differs from Chrome; may need polling.
- **Bitwarden terms** for modified clients are unclear (Vaultwarden fallback).
