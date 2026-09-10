/**
 * Re-run every check the Noir circuit performs, in TypeScript, against a
 * witness. Not a substitute for the ZK proof (it does not hide anything) — a
 * fast local sanity gate so a bad witness never reaches the prover.
 */

import type { EligibilityWitness } from "./types.js";
import { PI_INDEX } from "./types.js";
import { bytes32ToBigInt, toBytes32 } from "./hex.js";
import { poseidon2 } from "./poseidon.js";
import { verify as verifySchnorr } from "./schnorr.js";

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
    cred_epoch: number;
    salt: string;
    issuer_pk_x: string;
    issuer_pk_y: string;
    sig_s_lo: string;
    sig_s_hi: string;
    sig_e_lo: string;
    sig_e_hi: string;
    auditor_nonce: string;
  };

  const secret = bytes32ToBigInt(p.holder_secret as `0x${string}`);

  // 1. the issuer signed { holderBinding, tier, expiry, credEpoch }
  const holderBinding = poseidon2([secret, bytes32ToBigInt(p.salt as `0x${string}`)]);
  const message = toBytes32(
    poseidon2([holderBinding, BigInt(p.tier), BigInt(p.expiry), BigInt(p.cred_epoch)]),
  );
  const sigOk = verifySchnorr(
    { x: p.issuer_pk_x as `0x${string}`, y: p.issuer_pk_y as `0x${string}` },
    {
      sLo: p.sig_s_lo as `0x${string}`,
      sHi: p.sig_s_hi as `0x${string}`,
      eLo: p.sig_e_lo as `0x${string}`,
      eHi: p.sig_e_hi as `0x${string}`,
    },
    message,
  );
  if (!sigOk) failures.push("bad issuer signature");

  // 2. issuer_id is that key
  const issuerId = poseidon2([
    bytes32ToBigInt(p.issuer_pk_x as `0x${string}`),
    bytes32ToBigInt(p.issuer_pk_y as `0x${string}`),
  ]);
  if (issuerId !== pub[PI_INDEX.issuerId]) failures.push("issuer id mismatch");

  // 3/4 tier + expiry
  if (BigInt(p.tier) < pub[PI_INDEX.minTier]!) failures.push("tier below minimum");
  if (BigInt(p.expiry) <= pub[PI_INDEX.now]!) failures.push("credential expired");

  // 5 bulk revocation
  if (BigInt(p.cred_epoch) < pub[PI_INDEX.minCredEpoch]!)
    failures.push("credential epoch revoked");

  // 6 nullifier
  const expectedNullifier = poseidon2([secret, pub[PI_INDEX.corridorId]!]);
  if (expectedNullifier !== pub[PI_INDEX.nullifier]) failures.push("bad nullifier");

  // 7 tag bound
  if (pub[PI_INDEX.disclosedTag]! >= 16n) failures.push("tag out of range");

  // 8 auditor blob binding
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
