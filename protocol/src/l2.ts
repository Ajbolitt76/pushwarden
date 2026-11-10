// L2 key item and L2 field values. Spec: PROTOCOL.md §1–2.
import { b64, getSodium, unb64 } from "./sodium.ts";

export const KEY_FIELD_NAME = "l2key";
export const KEY_ITEM_NAME = "PushWarden key – do not edit";
export const L2_PREFIX = "l2:v1:";

export type L2Field = "password" | "totp";

export interface KdfParams {
  ops: number;
  memMiB: number;
}

export const DEFAULT_KDF: KdfParams = { ops: 3, memMiB: 256 };
const OPS_MIN = 3, OPS_MAX = 10, MEM_MIN = 64, MEM_MAX = 1024;

interface KeyItemJson {
  v: 1;
  kdf: "argon2id";
  ops: number;
  memMiB: number;
  salt: string;
  wrappedKey: string;
}

async function kek(password: string, salt: Uint8Array, p: KdfParams): Promise<Uint8Array> {
  const s = await getSodium();
  return s.crypto_pwhash(32, password, salt, p.ops, p.memMiB * 1024 * 1024, s.crypto_pwhash_ALG_ARGON2ID13);
}

/** Wraps `key` under `password`. Returns the `l2key` field value. */
export async function wrapKey(
  key: Uint8Array,
  password: string,
  params: KdfParams = DEFAULT_KDF,
  fixed?: { salt: Uint8Array; nonce: Uint8Array }, // test vectors only
): Promise<string> {
  const s = await getSodium();
  checkParams(params.ops, params.memMiB);
  if (key.length !== 32) throw new Error("L2 key must be 32 bytes");
  const salt = fixed?.salt ?? s.randombytes_buf(16);
  const nonce = fixed?.nonce ?? s.randombytes_buf(24);
  const k = await kek(password, salt, params);
  try {
    const wrapped = concat(nonce, s.crypto_secretbox_easy(key, nonce, k));
    const json: KeyItemJson = {
      v: 1, kdf: "argon2id", ops: params.ops, memMiB: params.memMiB,
      salt: b64(s, salt), wrappedKey: b64(s, wrapped),
    };
    return JSON.stringify(json);
  } finally {
    s.memzero(k);
  }
}

/** Creates a new random L2 key. Returns it and the `l2key` field value. */
export async function createKey(password: string, params: KdfParams = DEFAULT_KDF) {
  const s = await getSodium();
  const key = s.randombytes_buf(32);
  return { key, fieldValue: await wrapKey(key, password, params) };
}

/** Unwraps the L2 key. Throws `WrongPasswordError` if the password is wrong. */
export async function unwrapKey(fieldValue: string, password: string): Promise<Uint8Array> {
  const s = await getSodium();
  const item = parseKeyItem(fieldValue);
  const salt = unb64(s, item.salt, 16);
  const wrapped = unb64(s, item.wrappedKey, 72);
  const k = await kek(password, salt, item);
  try {
    return s.crypto_secretbox_open_easy(wrapped.subarray(24), wrapped.subarray(0, 24), k);
  } catch {
    throw new WrongPasswordError();
  } finally {
    s.memzero(k);
  }
}

export class WrongPasswordError extends Error {
  constructor() {
    super("wrong L2 password");
  }
}

function parseKeyItem(fieldValue: string): KeyItemJson {
  const j = JSON.parse(fieldValue);
  if (j?.v !== 1 || j.kdf !== "argon2id") throw new Error("unsupported L2 key item");
  checkParams(j.ops, j.memMiB);
  return j;
}

function checkParams(ops: unknown, memMiB: unknown) {
  if (!Number.isInteger(ops) || (ops as number) < OPS_MIN || (ops as number) > OPS_MAX ||
      !Number.isInteger(memMiB) || (memMiB as number) < MEM_MIN || (memMiB as number) > MEM_MAX) {
    throw new Error("L2 key item KDF parameters out of bounds");
  }
}

/** True for any `l2:` value. Values with an unknown version must not be filled. */
export function isL2Value(value: string | null | undefined): boolean {
  return value != null && value.startsWith("l2:");
}

/** What an L2 value is bound to besides its field (PROTOCOL.md §2). */
export interface L2Binding {
  itemId: string;
  username: string;
  hosts: string[];
}

export async function encryptField(
  key: Uint8Array,
  field: L2Field,
  binding: L2Binding,
  secret: string,
  fixedNonce?: Uint8Array, // test vectors only
): Promise<string> {
  const s = await getSodium();
  if (!binding.itemId) throw new Error("L2 values need the item id");
  const nonce = fixedNonce ?? s.randombytes_buf(24);
  const payload = JSON.stringify({ f: field, i: binding.itemId, u: binding.username, v: secret, h: binding.hosts });
  return L2_PREFIX + b64(s, concat(nonce, s.crypto_secretbox_easy(payload, nonce, key)));
}

export interface L2Plain {
  secret: string;
  username: string;
  hosts: string[];
}

/** Decrypts an L2 value read from `field` of item `itemId`. Throws on tampering, wrong key, field or item. */
export async function decryptField(
  key: Uint8Array,
  field: L2Field,
  itemId: string,
  value: string,
): Promise<L2Plain> {
  const s = await getSodium();
  if (!value.startsWith(L2_PREFIX)) throw new Error("not an l2:v1 value");
  const raw = unb64(s, value.slice(L2_PREFIX.length));
  if (raw.length < 24 + s.crypto_secretbox_MACBYTES) throw new Error("L2 value too short");
  const plain = s.crypto_secretbox_open_easy(raw.subarray(24), raw.subarray(0, 24), key);
  const j = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain));
  if (j?.f !== field) throw new Error(`L2 value is for field ${String(j?.f)}, read from ${field}`);
  if (j.i !== itemId) throw new Error("L2 value belongs to another item");
  if (
    typeof j.v !== "string" ||
    typeof j.u !== "string" ||
    !Array.isArray(j.h) ||
    !j.h.every((h: unknown) => typeof h === "string")
  ) {
    throw new Error("malformed L2 payload");
  }
  return { secret: j.v, username: j.u, hosts: j.h };
}

/** Hosts for `h`, from a Bitwarden item's URIs. Non-web URIs (androidapp://) are skipped. */
export function hostsFromUris(uris: Array<string | null | undefined>): string[] {
  const out = new Set<string>();
  for (const uri of uris) {
    if (!uri) continue;
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(uri) ? uri : `https://${uri}`;
    let url: URL;
    try {
      url = new URL(withScheme);
    } catch {
      continue;
    }
    if ((url.protocol === "https:" || url.protocol === "http:") && url.hostname) {
      out.add(url.hostname.toLowerCase());
    }
  }
  return [...out];
}

/** PROTOCOL.md §2 "Host match". */
export function originAllowed(origin: string, hosts: string[]): boolean {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  const o = url.hostname.toLowerCase();
  const local = o === "localhost" || o === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) return false;
  return hosts.some((x) => {
    x = x.toLowerCase();
    return x !== "" && (o === x || o.endsWith("." + x));
  });
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}
