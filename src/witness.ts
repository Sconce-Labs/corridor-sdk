/**
 * Build the Noir circuit witness (Option B) from credential material — an
 * issuer-signed statement — plus a corridor policy. No Merkle trees.
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
import { verify as verifySchnorr } from "./schnorr.js";

const MAX_TAG = 16;

/** `Poseidon2(holder_secret, salt)` — the holder-hiding value the issuer signs. */
export function holderBinding(holderSecret: Bytes32, salt: Bytes32): bigint {
  return poseidon2([bytes32ToBigInt(holderSecret), bytes32ToBigInt(salt)]);
}

/** The exact message an issuer signs for a credential. */
export function statementMessage(cred: CredentialMaterial): Bytes32 {
  return toBytes32(
    poseidon2([
      holderBinding(cred.holderSecret, cred.salt),
      BigInt(cred.tier),
      BigInt(cred.expiry),
      BigInt(cred.credEpoch),
    ]),
  );
}

export function issuerIdOf(pubkeyX: Bytes32, pubkeyY: Bytes32): Bytes32 {
  return toBytes32(poseidon2([bytes32ToBigInt(pubkeyX), bytes32ToBigInt(pubkeyY)]));
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
  if (BigInt(cred.credEpoch) < policy.minCredEpoch)
    throw new Error("credential epoch is below the corridor's revocation floor");

  const secret = bytes32ToBigInt(cred.holderSecret);
  const issuer = cred.issuer;
  const issuerId = issuerIdOf(issuer.pubkeyX, issuer.pubkeyY);

  // fail locally on a bad/forged signature before any proof is generated
  const message = statementMessage(cred);
  if (
    !verifySchnorr(
      { x: issuer.pubkeyX, y: issuer.pubkeyY },
      { sLo: issuer.sLo, sHi: issuer.sHi, eLo: issuer.eLo, eHi: issuer.eHi },
      message,
    )
  ) {
    throw new Error("issuer signature does not verify over the credential statement");
  }
  if (req.auditorPubkey !== policy.auditorPubkey) {
    throw new Error("auditorPubkey must equal the corridor policy's auditor key");
  }

  const nullifier = poseidon2([secret, bytes32ToBigInt(opts.corridorId)]);
  const auditorBlob = poseidon2([
    bytes32ToBigInt(req.auditorPubkey),
    BigInt(cred.tier),
    bytes32ToBigInt(issuerId),
    nullifier,
    bytes32ToBigInt(req.auditorNonce),
  ]);

  const publicInputs: Bytes32[] = [
    opts.corridorId,
    numberToWord(policy.minTier),
    numberToWord(opts.now),
    toBytes32(nullifier),
    numberToWord(req.disclosedTag),
    issuerId,
    numberToWord(policy.minCredEpoch),
    req.auditorPubkey,
    toBytes32(auditorBlob),
  ];
  if (publicInputs.length !== PI_LEN) throw new Error("public input length mismatch");

  return {
    publicInputs,
    privateInputs: {
      holder_secret: cred.holderSecret,
      tier: cred.tier,
      expiry: cred.expiry,
      cred_epoch: cred.credEpoch,
      salt: cred.salt,
      issuer_pk_x: issuer.pubkeyX,
      issuer_pk_y: issuer.pubkeyY,
      sig_s_lo: issuer.sLo,
      sig_s_hi: issuer.sHi,
      sig_e_lo: issuer.eLo,
      sig_e_hi: issuer.eHi,
      auditor_nonce: req.auditorNonce,
    },
    issuerId,
    nullifier: toBytes32(nullifier),
    auditorBlob: toBytes32(auditorBlob),
  };
}

export { poseidon2 } from "./poseidon.js";
