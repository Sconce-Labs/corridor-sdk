/**
 * Build the Noir circuit witness from credential material + a corridor policy.
 * Poseidon2 (`./poseidon`) is pinned to the circuit; see `poseidon.ts`.
 */

import type {
  Bytes32,
  CorridorPolicy,
  CredentialMaterial,
  DisclosureRequest,
  EligibilityWitness,
} from "./types.js";
import { PI_LEN } from "./types.js";
import { bytes32ToBigInt, numberToWord, toBytes32 } from "./hex.js";
import { poseidon2 } from "./poseidon.js";
import { rootFromProof, leBits } from "./merkle.js";

const MAX_TAG = 16;

/** Root from a leaf + flat sibling/bit arrays (thin wrapper over rootFromProof). */
export function merkleRoot(leaf: bigint, siblings: bigint[], bits: boolean[]): bigint {
  return rootFromProof(leaf, { siblings, bits });
}

export function buildWitness(
  cred: CredentialMaterial,
  policy: CorridorPolicy,
  req: DisclosureRequest,
  opts: { corridorId: Bytes32; now: number },
): EligibilityWitness {
  if (req.disclosedTag >= MAX_TAG) throw new Error("disclosedTag must be < 16");
  if (cred.tier < policy.minTier)
    throw new Error("credential tier below corridor minimum");
  if (cred.expiry <= opts.now) throw new Error("credential expired");

  const secret = bytes32ToBigInt(cred.holderSecret);
  const issuer = bytes32ToBigInt(cred.issuerId);
  const salt = bytes32ToBigInt(cred.salt);
  const corridorId = bytes32ToBigInt(opts.corridorId);
  const auditorPk = bytes32ToBigInt(req.auditorPubkey);
  const auditorNonce = bytes32ToBigInt(req.auditorNonce);

  const commitment = poseidon2([
    secret,
    BigInt(cred.tier),
    BigInt(cred.expiry),
    issuer,
    salt,
  ]);
  const nullifier = poseidon2([secret, corridorId]);
  const auditorBlob = poseidon2([
    auditorPk,
    BigInt(cred.tier),
    issuer,
    nullifier,
    auditorNonce,
  ]);

  // Re-derive the roots from the supplied paths and fail locally on a stale or
  // revoked credential, before any proof is generated.
  const credSibs = cred.credSiblings.map(bytes32ToBigInt);
  const revSibs = cred.revSiblings.map(bytes32ToBigInt);
  if (
    toBytes32(merkleRoot(commitment, credSibs, cred.credIndexBits)) !==
    policy.credentialRoot
  ) {
    throw new Error(
      "credSiblings/credIndexBits do not reproduce the policy credentialRoot — stale path?",
    );
  }
  const revSlot = poseidon2([commitment]);
  if (toBytes32(merkleRoot(0n, revSibs, leBits(revSlot))) !== policy.revocationRoot) {
    throw new Error(
      "revSiblings do not reproduce the policy revocationRoot — credential revoked?",
    );
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

// Back-compat re-exports.
export { poseidon2 } from "./poseidon.js";
export { leBits } from "./merkle.js";
