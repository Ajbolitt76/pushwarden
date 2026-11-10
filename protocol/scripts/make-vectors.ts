// Regenerates vectors/v1.json. The vectors are the contract: change only with a version bump.
import { writeFileSync } from "node:fs";
import { encryptField, getSodium, wrapKey, seal, commitment, fingerprintPhrase, originAllowed, qrProof } from "../src/index.ts";
import type { Message } from "../src/index.ts";

const s = await getSodium();
const hex = (b: Uint8Array) => s.to_hex(b);
const fill = (n: number, byte: number) => new Uint8Array(n).fill(byte);

const key = fill(32, 0x42);
const keyItem = {
  password: "correct horse battery staple",
  ops: 3, memMiB: 64,
  saltHex: hex(fill(16, 0x01)), nonceHex: hex(fill(24, 0x02)), keyHex: hex(key),
  fieldValue: await wrapKey(key, "correct horse battery staple", { ops: 3, memMiB: 64 }, { salt: fill(16, 1), nonce: fill(24, 2) }),
};

const fields = [];
for (const [field, secret, hosts, nb] of [
  ["password", "hunter2", ["github.com"], 0x03],
  ["password", "pässwörd ✓ \"quoted\"", ["accounts.example.org", "example.net"], 0x04],
  ["totp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", ["github.com"], 0x05],
  ["password", "phone-only", [], 0x09],
] as const) {
  const binding = { itemId: "1b2c3d4e-0000-4000-8000-000000000001", username: "alice@example.com", hosts: [...hosts] };
  fields.push({ keyHex: hex(key), field, ...binding, secret, nonceHex: hex(fill(24, nb)), value: await encryptField(key, field, binding, secret, fill(24, nb)) });
}

const phone = s.crypto_box_seed_keypair(fill(32, 0x10));
const ext = s.crypto_box_seed_keypair(fill(32, 0x20));
const msg: Message = { v: 1, type: "fillRequest", requestId: s.to_base64(fill(16, 0x30), 1), itemId: "1b2c3d4e-0000-4000-8000-000000000001", origin: "https://github.com", time: 1762646400000 };
const box = {
  senderSeedHex: hex(fill(32, 0x20)), recipientSeedHex: hex(fill(32, 0x10)),
  senderPkHex: hex(ext.publicKey), recipientPkHex: hex(phone.publicKey),
  nonceHex: hex(fill(24, 0x06)), message: msg,
  body: await seal(msg, phone.publicKey, ext.privateKey, fill(24, 0x06)),
};

const nExt = fill(32, 0x07), nPhone = fill(32, 0x08);
const pairing = {
  phonePkHex: hex(phone.publicKey), extPkHex: hex(ext.publicKey), nExtHex: hex(nExt), nPhoneHex: hex(nPhone),
  commitHex: hex(await commitment(ext.publicKey, nExt)),
  phrase: await fingerprintPhrase(phone.publicKey, ext.publicKey, nExt, nPhone),
  qrSecretHex: hex(fill(32, 0x0a)),
  qrProofHex: hex(await qrProof(fill(32, 0x0a), phone.publicKey, ext.publicKey)),
};

const hostMatch = ([
  ["https://github.com", ["github.com"]],
  ["https://gist.github.com:8443", ["github.com"]],
  ["https://evilgithub.com", ["github.com"]],
  ["https://github.com.evil.com", ["github.com"]],
  ["http://github.com", ["github.com"]],
  ["http://localhost:3000", ["localhost"]],
  ["https://GitHub.COM", ["github.com"]],
  ["https://example.org", ["a.example.org"]],
  ["javascript:alert(1)", ["github.com"]],
] as const).map(([origin, hosts]) => ({ origin, hosts, allowed: originAllowed(origin, [...hosts]) }));

writeFileSync(new URL("../vectors/v1.json", import.meta.url), JSON.stringify({ keyItem, fields, box, pairing, hostMatch }, null, 2) + "\n");
console.log("wrote vectors/v1.json");
