/**
 * Build the Noir circuit witness from credential material + a corridor policy.
 *
 * Poseidon2 here (`@zkpassport/poseidon2`) is byte-identical to the circuit's
 * `noir-lang/poseidon` v0.3.0 — pinned by a shared test vector
 * (`0x…1ed7383` for `hash([1,2])`) checked in both this repo and
 * corridor-circuits. The Soroban leg of that conformance is tracked in
 * corridor-contracts (ABI.md "Hash conformance").
 */

import { poseidon2Hash } from "@zkpassport/poseidon2";
import type {
  Bytes32,
  CorridorPolicy,
  CredentialMaterial,
  DisclosureRequest,
  EligibilityWitness,
} from "./types.js";
import { PI_LEN } from "./types.js";
import { bytes32ToBigInt, numberToWord, toBytes32 } from "./hex.js";

const DEPTH = 32;
const MAX_TAG = 16;

const H = (xs: bigint[]): bigint => poseidon2Hash(xs);

/** Recompute a Merkle root from a leaf, its co-path, and direction bits. */
function merkleRoot(leaf: bigint, siblings: bigint[], bits: boolean[]): bigint {
  let node = leaf;
  for (let i = 0; i < DEPTH; i++) {
    const sib = siblings[i] ?? 0n;
    node = bits[i] ? H([sib, node]) : H([node, sib]);
  }
  return node;
}

/** Low `DEPTH` bits of a field element, little-endian (matches `to_le_bits`). */
function leBits(x: bigint, n = DEPTH): boolean[] {
  const out: boolean[] = [];
  for (let i = 0; i < n; i++) out.push(((x >> BigInt(i)) & 1n) === 1n);
  return out;
}

export function buildWitness(
  cred: CredentialMaterial,
  policy: CorridorPolicy,
  req: DisclosureRequest,
  opts: { corridorId: Bytes32; now: number },
): EligibilityWitness {
  if (req.disclosedTag >= MAX_TAG) throw new Error("disclosedTag must be < 16");
  if (cred.tier < policy.minTier) throw new Error("credential tier below corridor minimum");
  if (cred.expiry <= opts.now) throw new Error("credential expired");

  const secret = bytes32ToBigInt(cred.holderSecret);
  const issuer = bytes32ToBigInt(cred.issuerId);
  const salt = bytes32ToBigInt(cred.salt);
  const corridorId = bytes32ToBigInt(opts.corridorId);
  const auditorPk = bytes32ToBigInt(req.auditorPubkey);
  const auditorNonce = bytes32ToBigInt(req.auditorNonce);

  const commitment = H([secret, BigInt(cred.tier), BigInt(cred.expiry), issuer, salt]);
  const nullifier = H([secret, corridorId]);
  const auditorBlob = H([auditorPk, BigInt(cred.tier), issuer, nullifier, auditorNonce]);

  // sanity: our inclusion path must reproduce the policy's credential root
  const credSibs = cred.credSiblings.map(bytes32ToBigInt);
  const revSibs = cred.revSiblings.map(bytes32ToBigInt);
  const gotRoot = merkleRoot(commitment, credSibs, cred.credIndexBits);
  if (toBytes32(gotRoot) !== policy.credentialRoot) {
    throw new Error(
      "credSiblings/credIndexBits do not reproduce the policy credentialRoot — stale path?",
    );
  }
  const revSlot = H([commitment]);
  const gotRevRoot = merkleRoot(0n, revSibs, leBits(revSlot));
  if (toBytes32(gotRevRoot) !== policy.revocationRoot) {
    throw new Error("revSiblings do not reproduce the policy revocationRoot — credential revoked?");
  }

  const publicInputs: Bytes32[] = [
    policy.credentialRoot,
    policy.revocationRoot,
    opts.corridorId,
    numberToWord(policy.minTier),
    numberToWord(opts.now),
    toBytes32(nullifier),
    numberToWord(req.disclosedTag),
    cred.issuerId,
    toBytes32(auditorBlob),
  ];
  if (publicInputs.length !== PI_LEN) throw new Error("public input length mismatch");

  return {
    publicInputs,
    privateInputs: {
      holder_secret: cred.holderSecret,
      tier: cred.tier,
      expiry: cred.expiry,
      salt: cred.salt,
      cred_siblings: cred.credSiblings,
      cred_index_bits: cred.credIndexBits,
      rev_siblings: cred.revSiblings,
      auditor_pk: req.auditorPubkey,
      auditor_nonce: req.auditorNonce,
    },
    commitment: toBytes32(commitment),
    nullifier: toBytes32(nullifier),
    auditorBlob: toBytes32(auditorBlob),
  };
}

export { merkleRoot, leBits, H as poseidon2 };
