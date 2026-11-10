// Pairing commitment and fingerprint phrase. Spec: PROTOCOL.md §5.
import { concat } from "./l2.ts";
import { getSodium } from "./sodium.ts";
import { WORDLIST } from "./wordlist.ts";

const enc = new TextEncoder();

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const s = await getSodium();
  return s.crypto_hash_sha256(concat(...parts));
}

export async function randomNonce(): Promise<Uint8Array> {
  return (await getSodium()).randombytes_buf(32);
}

export function commitment(extPk: Uint8Array, nExt: Uint8Array): Promise<Uint8Array> {
  return sha256(enc.encode("l2-commit-v1"), extPk, nExt);
}

export async function checkCommitment(commit: Uint8Array, extPk: Uint8Array, nExt: Uint8Array): Promise<boolean> {
  const s = await getSodium();
  return s.memcmp(commit, await commitment(extPk, nExt));
}

/** `HMAC-SHA256(s, "l2-qr-v1" ‖ phonePk ‖ extPk)`: the phone's proof it scanned the QR code (§5b). */
export async function qrProof(secret: Uint8Array, phonePk: Uint8Array, extPk: Uint8Array): Promise<Uint8Array> {
  const s = await getSodium();
  if (secret.length !== 32) throw new Error("QR secret must be 32 bytes");
  return s.crypto_auth_hmacsha256(concat(enc.encode("l2-qr-v1"), phonePk, extPk), secret);
}

export async function checkQrProof(
  proof: Uint8Array,
  secret: Uint8Array,
  phonePk: Uint8Array,
  extPk: Uint8Array,
): Promise<boolean> {
  const s = await getSodium();
  const expected = await qrProof(secret, phonePk, extPk);
  return proof.length === expected.length && s.memcmp(proof, expected);
}

/** The 5 words both screens show, joined by "-". */
export async function fingerprintPhrase(
  phonePk: Uint8Array,
  extPk: Uint8Array,
  nExt: Uint8Array,
  nPhone: Uint8Array,
): Promise<string> {
  for (const [k, n] of [[phonePk, 32], [extPk, 32], [nExt, 32], [nPhone, 32]] as const) {
    if (k.length !== n) throw new Error("pairing inputs must be 32 bytes");
  }
  const h = await sha256(enc.encode("l2-pair-v1"), phonePk, extPk, nExt, nPhone);
  const view = new DataView(h.buffer, h.byteOffset, h.byteLength);
  const words: string[] = [];
  for (let i = 0; i < 5; i++) words.push(WORDLIST[view.getUint32(4 * i) % WORDLIST.length]);
  return words.join("-");
}
