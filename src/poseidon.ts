/**
 * Poseidon2 over BN254, via `@zkpassport/poseidon2`.
 *
 * Byte-identical to the circuit's `noir-lang/poseidon` v0.3.0 and Soroban's
 * `rs-soroban-poseidon`, pinned by the shared vectors below (asserted here in
 * `poseidon.test.ts`, in corridor-circuits/src/conformance.nr, and in
 * corridor-contracts/crates/poseidon_conformance). See
 * corridor-contracts/ABI.md "Hash conformance".
 */

import { poseidon2Hash } from "@zkpassport/poseidon2";

export function poseidon2(inputs: bigint[]): bigint {
  return poseidon2Hash(inputs);
}

/**
 * Pinned cross-implementation vectors, 32-byte canonical hex — keyed by input
 * arity. `poseidon2([1, 2, …, n]) === CONFORMANCE_VECTORS[n]`.
 */
export const CONFORMANCE_VECTORS: Record<number, string> = {
  1: "0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373",
  2: "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383",
  3: "0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8",
  4: "0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9",
  5: "0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db",
};

/** @deprecated use `CONFORMANCE_VECTORS[2]`. */
export const CONFORMANCE_VECTOR = CONFORMANCE_VECTORS[2];
