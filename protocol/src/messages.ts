// End-to-end messages between paired devices. Spec: PROTOCOL.md §4.
import { concat } from "./l2.ts";
import { b64, getSodium, unb64 } from "./sodium.ts";

export type FillStatus = "approved" | "denied" | "expired" | "rejected" | "error";

export type Message =
  | { v: 1; type: "pairRequest"; name: string; commit: string }
  | { v: 1; type: "pairChallenge"; nonce: string }
  | { v: 1; type: "pairReveal"; nonce: string }
  | { v: 1; type: "pairAccept"; nonce: string }
  | { v: 1; type: "pairReject"; nonce?: string }
  | { v: 1; type: "qrPair"; proof: string; name: string }
  | { v: 1; type: "fillRequest"; requestId: string; itemId: string; origin: string; time: number }
  | { v: 1; type: "fillResult"; requestId: string; status: FillStatus; password?: string; totp?: string }
  | { v: 1; type: "unpair" };

export const MAX_BODY_BYTES = 8 * 1024;

export async function seal(
  msg: Message,
  recipientPk: Uint8Array,
  senderSk: Uint8Array,
  fixedNonce?: Uint8Array, // test vectors only
): Promise<string> {
  const s = await getSodium();
  validate(JSON.parse(JSON.stringify(msg)), s); // same rules as the receiver, before sending
  const nonce = fixedNonce ?? s.randombytes_buf(24);
  const body = concat(nonce, s.crypto_box_easy(JSON.stringify(msg), nonce, recipientPk, senderSk));
  if (body.length > MAX_BODY_BYTES) throw new Error("message too large");
  return b64(s, body);
}

/**
 * Opens and validates a message. Returns null for an unknown `type` (ignored by spec).
 * Throws if the box doesn't open or a known type is malformed.
 */
export async function open(body: string, senderPk: Uint8Array, recipientSk: Uint8Array): Promise<Message | null> {
  const s = await getSodium();
  const raw = unb64(s, body);
  if (raw.length > MAX_BODY_BYTES || raw.length < 24 + s.crypto_box_MACBYTES) throw new Error("bad body length");
  const plain = s.crypto_box_open_easy(raw.subarray(24), raw.subarray(0, 24), senderPk, recipientSk);
  return validate(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain)), s);
}

const STATUSES: FillStatus[] = ["approved", "denied", "expired", "rejected", "error"];

function validate(m: any, s: Awaited<ReturnType<typeof getSodium>>): Message | null {
  if (m === null || typeof m !== "object" || m.v !== 1) throw new Error("unsupported message version");
  const str = (k: string, max = 4096) => {
    if (typeof m[k] !== "string" || m[k].length > max) throw new Error(`bad ${k}`);
  };
  const bytes = (k: string, n: number) => unb64(s, m[k], n);
  switch (m.type) {
    case "pairRequest":
      str("name", 64);
      bytes("commit", 32);
      break;
    case "pairChallenge":
    case "pairReveal":
    case "pairAccept":
      bytes("nonce", 32);
      break;
    case "pairReject":
      if (m.nonce !== undefined) bytes("nonce", 32);
      break;
    case "unpair":
      break;
    case "qrPair":
      bytes("proof", 32);
      str("name", 64);
      break;
    case "fillRequest":
      bytes("requestId", 16);
      str("itemId", 64);
      str("origin", 2048);
      if (!Number.isSafeInteger(m.time)) throw new Error("bad time");
      break;
    case "fillResult":
      bytes("requestId", 16);
      if (!STATUSES.includes(m.status)) throw new Error("bad status");
      if (m.status === "approved") str("password");
      else if (m.password !== undefined || m.totp !== undefined) throw new Error("secret on non-approved result");
      if (m.totp !== undefined && (typeof m.totp !== "string" || !/^[0-9]{6,8}$/.test(m.totp))) {
        throw new Error("bad totp");
      }
      break;
    default:
      return null;
  }
  return m as Message;
}
