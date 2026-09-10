/**
 * Re-run every check the Noir circuit performs, in TypeScript, against a
 * witness. Not a substitute for the ZK proof (it does not hide anything) — a
 * fast local sanity gate so a bad witness never reaches the prover.
 */

import type { EligibilityWitness } from "./types.js";
import { PI_INDEX } from "./types.js";
import { bytes32ToBigInt } from "./hex.js";
import { poseidon2 } from "./poseidon.js";
import { rootFromProof, leBits } from "./merkle.js";

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
    rev_siblings: string[];
    auditor_pk: string;
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

  // 3. revocation non-membership
  const revSlot = poseidon2([commitment]);
  const revRoot = rootFromProof(0n, {
    siblings: p.rev_siblings.map((s) => bytes32ToBigInt(s as `0x${string}`)),
    bits: leBits(revSlot),
  });
  if (revRoot !== pub[PI_INDEX.revocationRoot]) failures.push("credential revoked");

  // 4/5 tier + expiry
  if (BigInt(p.tier) < pub[PI_INDEX.minTier]!) failures.push("tier below minimum");
  if (BigInt(p.expiry) <= pub[PI_INDEX.now]!) failures.push("credential expired");

  // 6 nullifier
  const expectedNullifier = poseidon2([secret, pub[PI_INDEX.corridorId]!]);
  if (expectedNullifier !== pub[PI_INDEX.nullifier]) failures.push("bad nullifier");

  // 7 tag bound
  if (pub[PI_INDEX.disclosedTag]! >= 16n) failures.push("tag out of range");

  // 8 auditor blob binding
  const expectedBlob = poseidon2([
    bytes32ToBigInt(p.auditor_pk as `0x${string}`),
    BigInt(p.tier),
    issuerId,
    pub[PI_INDEX.nullifier]!,
    bytes32ToBigInt(p.auditor_nonce as `0x${string}`),
  ]);
  if (expectedBlob !== pub[PI_INDEX.auditorBlob])
    failures.push("auditor blob mismatch");

  return { ok: failures.length === 0, failures };
}
