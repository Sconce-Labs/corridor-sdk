/**
 * Re-run every check the Noir circuit performs, in TypeScript, against a
 * witness. Not a substitute for the ZK proof (it does not hide anything) — a
 * fast local sanity gate so a bad witness never reaches the prover.
 */

import type { EligibilityWitness } from "./types.js";
import { PI_INDEX } from "./types.js";
import { bytes32ToBigInt } from "./hex.js";
import { poseidon2 } from "./poseidon.js";
import { rootFromProof, imtKey, imtLeafHash } from "./merkle.js";

const KEY_MASK = (1n << 248n) - 1n;
function lt248(a: bigint, b: bigint): boolean {
  const diff = (b - a) & ((1n << 254n) - 1n);
  return diff !== 0n && diff <= KEY_MASK;
}

export interface LocalCheck {
  ok: boolean;
  failures: string[];
}

export function verifyWitnessLocally(w: EligibilityWitness): LocalCheck {
  const failures: string[] = [];
  const pub = w.publicInputs.map(bytes32ToBigInt);
  const p = w.privateInputs as {
    holder_secret: string;
    tier: number;
    expiry: number;
    salt: string;
    cred_siblings: string[];
    cred_index_bits: boolean[];
    rev_low_value: string;
    rev_low_next_index: string;
    rev_low_next_value: string;
    rev_low_siblings: string[];
    rev_low_index_bits: boolean[];
    auditor_nonce: string;
  };

  const secret = bytes32ToBigInt(p.holder_secret as `0x${string}`);
  const issuerId = pub[PI_INDEX.issuerId]!;
  const commitment = poseidon2([
    secret,
    BigInt(p.tier),
    BigInt(p.expiry),
    issuerId,
    bytes32ToBigInt(p.salt as `0x${string}`),
  ]);

  // 2. inclusion
  const credRoot = rootFromProof(commitment, {
    siblings: p.cred_siblings.map((s) => bytes32ToBigInt(s as `0x${string}`)),
    bits: p.cred_index_bits,
  });
  if (credRoot !== pub[PI_INDEX.credentialRoot])
    failures.push("credential not in issued set");

  // 3. revocation non-membership (indexed Merkle tree low-leaf range proof)
  const revKey = imtKey(poseidon2([commitment]));
  const lowValue = bytes32ToBigInt(p.rev_low_value as `0x${string}`);
  const lowNextValue = bytes32ToBigInt(p.rev_low_next_value as `0x${string}`);
  const lowLeaf = imtLeafHash({
    value: lowValue,
    nextIndex: bytes32ToBigInt(p.rev_low_next_index as `0x${string}`),
    nextValue: lowNextValue,
  });
  const revRoot = rootFromProof(lowLeaf, {
    siblings: p.rev_low_siblings.map((s) => bytes32ToBigInt(s as `0x${string}`)),
    bits: p.rev_low_index_bits,
  });
  if (revRoot !== pub[PI_INDEX.revocationRoot])
    failures.push("revocation proof: bad low-leaf path");
  else if (!lt248(lowValue, revKey)) failures.push("credential revoked");
  else if (lowNextValue !== 0n && !lt248(revKey, lowNextValue))
    failures.push("credential revoked");

  // 4/5 tier + expiry
  if (BigInt(p.tier) < pub[PI_INDEX.minTier]!) failures.push("tier below minimum");
  if (BigInt(p.expiry) <= pub[PI_INDEX.now]!) failures.push("credential expired");

  // 6 nullifier
  const expectedNullifier = poseidon2([secret, pub[PI_INDEX.corridorId]!]);
  if (expectedNullifier !== pub[PI_INDEX.nullifier]) failures.push("bad nullifier");

  // 7 tag bound
  if (pub[PI_INDEX.disclosedTag]! >= 16n) failures.push("tag out of range");

  // 8 auditor blob binding (auditor_pubkey is a public input)
  const expectedBlob = poseidon2([
    pub[PI_INDEX.auditorPubkey]!,
    BigInt(p.tier),
    issuerId,
    pub[PI_INDEX.nullifier]!,
    bytes32ToBigInt(p.auditor_nonce as `0x${string}`),
  ]);
  if (expectedBlob !== pub[PI_INDEX.auditorBlob])
    failures.push("auditor blob mismatch");

  return { ok: failures.length === 0, failures };
}
