import { randomBytes } from "node:crypto";
import type { Bytes32 } from "./types.js";

/** BN254 scalar field modulus — values must be reduced below this. */
export const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function toBytes32(v: bigint | number | Uint8Array | string): Bytes32 {
  let hex: string;
  if (v instanceof Uint8Array) {
    hex = Buffer.from(v).toString("hex");
  } else if (typeof v === "string") {
    hex = v.replace(/^0x/, "");
  } else {
    hex = BigInt(v).toString(16);
  }
  if (hex.length > 64) throw new Error(`value does not fit in 32 bytes: ${hex}`);
  return `0x${hex.padStart(64, "0")}` as Bytes32;
}

export function bytes32ToBuffer(b: Bytes32): Buffer {
  return Buffer.from(b.replace(/^0x/, "").padStart(64, "0"), "hex");
}

export function bytes32ToBigInt(b: Bytes32): bigint {
  return BigInt(b.startsWith("0x") ? b : `0x${b}`);
}

/** Big-endian integer in the low bytes of a 32-byte word (matches
 *  `corridor_types::word_to_u64` / `word_to_u32`). */
export function numberToWord(n: bigint | number): Bytes32 {
  return toBytes32(BigInt(n));
}

export function isBytes32(s: string): s is Bytes32 {
  return /^0x[0-9a-fA-F]{64}$/.test(s);
}

/** A random field element (< BN254_FR), 32-byte hex. Use for salt / nonce. */
export function randomFieldElement(): Bytes32 {
  let v: bigint;
  do {
    v = BigInt(`0x${randomBytes(32).toString("hex")}`);
  } while (v >= BN254_FR);
  return toBytes32(v);
}

/** A fresh holder secret. There is no key recovery — store it. */
export const randomSecret = randomFieldElement;
