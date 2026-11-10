import sodiumModule from "libsodium-wrappers-sumo";

export type Sodium = typeof sodiumModule;

let ready: Promise<Sodium> | undefined;

/** libsodium, initialised. Every exported function that does crypto awaits this. */
export function getSodium(): Promise<Sodium> {
  ready ??= sodiumModule.ready.then(() => sodiumModule);
  return ready;
}

export const ORIGINAL = 1; // sodium.base64_variants.ORIGINAL: standard alphabet, padded

export function b64(s: Sodium, bytes: Uint8Array): string {
  return s.to_base64(bytes, ORIGINAL);
}

/** Decodes standard base64; throws if malformed or (when given) not `len` bytes. */
export function unb64(s: Sodium, text: unknown, len?: number): Uint8Array {
  if (typeof text !== "string") throw new Error("expected base64 string");
  const bytes = s.from_base64(text, ORIGINAL);
  if (len !== undefined && bytes.length !== len) throw new Error(`expected ${len} bytes`);
  return bytes;
}
