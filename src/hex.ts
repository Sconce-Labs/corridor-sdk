import type { Bytes32 } from "./types.js";

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

/** Big-endian u64/u32 packed into the low bytes of a 32-byte word (matches
 *  `corridor_types::word_to_u64` / `word_to_u32` on the contract side). */
export function numberToWord(n: bigint | number): Bytes32 {
  return toBytes32(BigInt(n));
}
