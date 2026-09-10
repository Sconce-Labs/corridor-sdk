/**
 * Poseidon2 over BN254, via `@zkpassport/poseidon2`.
 *
 * Byte-identical to the circuit's `noir-lang/poseidon` v0.3.0 and Soroban's
 * `rs-soroban-poseidon`, pinned by a shared vector:
 *
 *   poseidon2([1n, 2n]) === 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383
 *
 * asserted here (`poseidon.test.ts`), in corridor-circuits, and in
 * corridor-contracts. See corridor-contracts/ABI.md "Hash conformance".
 */

import { poseidon2Hash } from "@zkpassport/poseidon2";

export function poseidon2(inputs: bigint[]): bigint {
  return poseidon2Hash(inputs);
}

/** The pinned cross-implementation conformance vector, 32-byte canonical form. */
export const CONFORMANCE_VECTOR =
  "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383";
