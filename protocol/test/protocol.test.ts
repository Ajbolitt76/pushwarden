import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  checkCommitment, checkQrProof, commitment, qrProof, createKey, decryptField, encryptField, fingerprintPhrase, getSodium,
  hostsFromUris, isL2Value, open, originAllowed, seal, unwrapKey, wrapKey, WrongPasswordError,
} from "../src/index.ts";

const v = JSON.parse(readFileSync(new URL("../vectors/v1.json", import.meta.url), "utf8"));
const s = await getSodium();
const unhex = (h: string) => s.from_hex(h);
const FAST = { ops: 3, memMiB: 64 };

test("vectors: key item", async () => {
  const k = v.keyItem;
  const out = await wrapKey(unhex(k.keyHex), k.password, FAST, { salt: unhex(k.saltHex), nonce: unhex(k.nonceHex) });
  assert.equal(out, k.fieldValue);
  assert.deepEqual(await unwrapKey(k.fieldValue, k.password), unhex(k.keyHex));
});

test("vectors: fields", async () => {
  for (const f of v.fields) {
    const binding = { itemId: f.itemId, username: f.username, hosts: f.hosts };
    assert.equal(await encryptField(unhex(f.keyHex), f.field, binding, f.secret, unhex(f.nonceHex)), f.value);
    assert.deepEqual(await decryptField(unhex(f.keyHex), f.field, f.itemId, f.value), {
      secret: f.secret,
      username: f.username,
      hosts: f.hosts,
    });
  }
});

test("vectors: box, pairing, host match", async () => {
  const b = v.box;
  const sender = s.crypto_box_seed_keypair(unhex(b.senderSeedHex));
  const recipient = s.crypto_box_seed_keypair(unhex(b.recipientSeedHex));
  assert.equal(s.to_hex(sender.publicKey), b.senderPkHex);
  assert.equal(await seal(b.message, recipient.publicKey, sender.privateKey, unhex(b.nonceHex)), b.body);
  assert.deepEqual(await open(b.body, sender.publicKey, recipient.privateKey), b.message);

  const p = v.pairing;
  assert.equal(s.to_hex(await commitment(unhex(p.extPkHex), unhex(p.nExtHex))), p.commitHex);
  assert.equal(await fingerprintPhrase(unhex(p.phonePkHex), unhex(p.extPkHex), unhex(p.nExtHex), unhex(p.nPhoneHex)), p.phrase);
  assert.match(p.phrase, /^[a-z-]+(-[a-z-]+){4}$/);
  assert.equal(s.to_hex(await qrProof(unhex(p.qrSecretHex), unhex(p.phonePkHex), unhex(p.extPkHex))), p.qrProofHex);
  assert.ok(await checkQrProof(unhex(p.qrProofHex), unhex(p.qrSecretHex), unhex(p.phonePkHex), unhex(p.extPkHex)));
  // A swapped phone key (relay MITM) fails without the secret.
  assert.ok(!(await checkQrProof(unhex(p.qrProofHex), unhex(p.qrSecretHex), s.randombytes_buf(32), unhex(p.extPkHex))));

  const expected = [true, true, false, false, false, true, true, false, false];
  assert.deepEqual(v.hostMatch.map((h: any) => h.allowed), expected);
  for (const h of v.hostMatch) assert.equal(originAllowed(h.origin, h.hosts), h.allowed, h.origin);
});

test("key item: wrong password, bounds, re-wrap", async () => {
  const { key, fieldValue } = await createKey("pw one", FAST);
  await assert.rejects(unwrapKey(fieldValue, "pw two"), WrongPasswordError);
  const j = JSON.parse(fieldValue);
  for (const bad of [{ memMiB: 1 }, { ops: 1 }, { memMiB: 4096 }, { v: 2 }, { kdf: "pbkdf2" }]) {
    await assert.rejects(unwrapKey(JSON.stringify({ ...j, ...bad }), "pw one"));
  }
  const rewrapped = await wrapKey(key, "pw two", FAST);
  assert.deepEqual(await unwrapKey(rewrapped, "pw two"), key);
});

test("fields: wrong field, wrong item, tamper, wrong key, unknown version", async () => {
  const key = s.randombytes_buf(32);
  const b = (itemId: string, hosts: string[]) => ({ itemId, username: "u", hosts });
  const totp = await encryptField(key, "totp", b("item-1", ["a.com"]), "seed");
  await assert.rejects(decryptField(key, "password", "item-1", totp), /for field totp/);
  await assert.rejects(decryptField(key, "totp", "item-2", totp), /another item/);
  const raw = s.from_base64(totp.slice(6), 1);
  raw[raw.length - 1] ^= 1;
  await assert.rejects(decryptField(key, "totp", "item-1", "l2:v1:" + s.to_base64(raw, 1)));
  await assert.rejects(decryptField(s.randombytes_buf(32), "totp", "item-1", totp));
  assert.ok(isL2Value("l2:v2:abc"));
  await assert.rejects(decryptField(key, "password", "item-1", "l2:v2:abc"));
  assert.ok(!isL2Value("hunter2"));
  await assert.rejects(encryptField(key, "password", b("", []), "x"));
  const phoneOnly = await encryptField(key, "password", b("item-1", []), "x");
  assert.ok(!originAllowed("https://a.com", (await decryptField(key, "password", "item-1", phoneOnly)).hosts));
});

test("hostsFromUris", () => {
  assert.deepEqual(
    hostsFromUris(["https://GitHub.com/login", "example.org", "androidapp://com.x", null, "http://bücher.de:81/x", "::bad"]),
    ["github.com", "example.org", "xn--bcher-kva.de"],
  );
});

test("messages: wrong sender key, unknown type, malformed", async () => {
  const a = s.crypto_box_keypair(), b = s.crypto_box_keypair(), c = s.crypto_box_keypair();
  // Bypasses seal()'s validation so the receiver's checks can be exercised.
  const rawSeal = (obj: unknown) => {
    const nonce = s.randombytes_buf(24);
    const box = s.crypto_box_easy(JSON.stringify(obj), nonce, b.publicKey, a.privateKey);
    const out = new Uint8Array(24 + box.length);
    out.set(nonce);
    out.set(box, 24);
    return s.to_base64(out, 1);
  };
  const rid = s.to_base64(s.randombytes_buf(16), 1);
  const nonce = s.to_base64(s.randombytes_buf(32), 1);

  const body = await seal({ v: 1, type: "pairAccept", nonce }, b.publicKey, a.privateKey);
  await assert.rejects(open(body, c.publicKey, b.privateKey));
  assert.deepEqual(await open(body, a.publicKey, b.privateKey), { v: 1, type: "pairAccept", nonce });
  const unknown = await seal({ v: 1, type: "future" } as any, b.publicKey, a.privateKey);
  assert.equal(await open(unknown, a.publicKey, b.privateKey), null);

  // seal() refuses what open() would refuse.
  const numericTotp = { v: 1, type: "fillResult", requestId: rid, status: "approved", password: "x", totp: 123456 };
  await assert.rejects(seal(numericTotp as any, b.publicKey, a.privateKey), /bad totp/);
  await assert.rejects(open(rawSeal(numericTotp), a.publicKey, b.privateKey), /bad totp/);
  await assert.rejects(seal({ v: 1, type: "pairAccept" } as any, b.publicKey, a.privateKey));
  const longPw = { v: 1, type: "fillResult", requestId: rid, status: "approved", password: "x".repeat(4097) };
  await assert.rejects(seal(longPw as any, b.publicKey, a.privateKey), /bad password/);

  const leak = { v: 1, type: "fillResult", requestId: rid, status: "denied", password: "x" };
  await assert.rejects(open(rawSeal(leak), a.publicKey, b.privateKey), /non-approved/);
  await assert.rejects(open(rawSeal({ v: 2, type: "pairAccept", nonce }), a.publicKey, b.privateKey));
});

test("pairing: commitment binds key and nonce", async () => {
  const pk = s.randombytes_buf(32), n = s.randombytes_buf(32);
  const c = await commitment(pk, n);
  assert.ok(await checkCommitment(c, pk, n));
  assert.ok(!(await checkCommitment(c, pk, s.randombytes_buf(32))));
  assert.ok(!(await checkCommitment(c, s.randombytes_buf(32), n)));
});
