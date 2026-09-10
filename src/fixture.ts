/**
 * The three sides of issuance, plus a test fixture.
 *
 *   holder:  prepareCredentialRequest(secret, salt, attrs)  →  CredentialRequest
 *   issuer:  issueCredential(issuerSk, request)             →  SignedStatement
 *   holder:  assembleCredential(secret, salt, statement)    →  CredentialMaterial
 *
 * The issuer only ever sees the blinded `holderBinding` — never `holderSecret`.
 */

import type {
  Bytes32,
  CredentialMaterial,
  CredentialRequest,
  IssuerSignature,
  SignedStatement,
} from "./types.js";
import { toBytes32 } from "./hex.js";
import { publicKey, sign, randomIssuerKey } from "./schnorr.js";
import { holderBinding, statementMessage, issuerIdOf } from "./witness.js";
import { verify as verifySchnorr } from "./schnorr.js";

export interface CredentialAttrs {
  tier: number;
  expiry: number;
  credEpoch: number;
}

/** Holder side: blind the secret and package the attributes for the issuer. */
export function prepareCredentialRequest(
  holderSecret: Bytes32,
  salt: Bytes32,
  attrs: CredentialAttrs,
): CredentialRequest {
  return {
    holderBinding: holderBinding(holderSecret, salt),
    tier: attrs.tier,
    expiry: attrs.expiry,
    credEpoch: attrs.credEpoch,
  };
}

/**
 * Issuer side: sign a credential request. The issuer runs KYC out of band,
 * verifies the attributes, and signs — without ever seeing `holderSecret`.
 */
export function issueCredential(
  issuerPrivateKey: Bytes32,
  req: CredentialRequest,
): SignedStatement {
  const pk = publicKey(issuerPrivateKey);
  const sig = sign(
    issuerPrivateKey,
    statementMessage(req.holderBinding, req.tier, req.expiry, req.credEpoch),
  );
  const issuer: IssuerSignature = {
    pubkeyX: pk.x,
    pubkeyY: pk.y,
    sLo: sig.sLo,
    sHi: sig.sHi,
    eLo: sig.eLo,
    eHi: sig.eHi,
  };
  return { tier: req.tier, expiry: req.expiry, credEpoch: req.credEpoch, issuer };
}

/**
 * Holder side: combine the local `{ holderSecret, salt }` with the issuer's
 * signed statement into the material the wallet stores. Throws if the
 * signature doesn't verify over this holder's binding.
 */
export function assembleCredential(
  holderSecret: Bytes32,
  salt: Bytes32,
  stmt: SignedStatement,
): CredentialMaterial {
  const message = statementMessage(
    holderBinding(holderSecret, salt),
    stmt.tier,
    stmt.expiry,
    stmt.credEpoch,
  );
  const ok = verifySchnorr(
    { x: stmt.issuer.pubkeyX, y: stmt.issuer.pubkeyY },
    {
      sLo: stmt.issuer.sLo,
      sHi: stmt.issuer.sHi,
      eLo: stmt.issuer.eLo,
      eHi: stmt.issuer.eHi,
    },
    message,
  );
  if (!ok) {
    throw new Error(
      "issuer signature does not verify over this holder's binding + attributes",
    );
  }
  return {
    holderSecret,
    salt,
    tier: stmt.tier,
    expiry: stmt.expiry,
    credEpoch: stmt.credEpoch,
    issuer: stmt.issuer,
  };
}

export interface Fixture {
  issuerPrivateKey: Bytes32;
  credential: CredentialMaterial;
  /** `Poseidon2(pk.x, pk.y)` — put this in a policy's `acceptedIssuers`. */
  issuerId: Bytes32;
}

interface FixtureHolder extends CredentialAttrs {
  holderSecret: bigint;
  salt: bigint;
}

const DEFAULT_HOLDER: FixtureHolder = {
  holderSecret: 0x0affee0decaf0badf00d1234567890abcdef0affee0decaf0badf00d12345678n,
  salt: 42n,
  tier: 4,
  expiry: 9_000_000,
  credEpoch: 7,
};

/**
 * Test/dev helper — runs all three sides (holder → issuer → holder) with a
 * deterministic holder. Real code never has both keys in one place.
 */
export function makeFixture(
  opts: { holder?: Partial<FixtureHolder>; issuerPrivateKey?: Bytes32 } = {},
): Fixture {
  const sk = opts.issuerPrivateKey ?? randomIssuerKey();
  const h = { ...DEFAULT_HOLDER, ...opts.holder };
  const secret = toBytes32(h.holderSecret);
  const salt = toBytes32(h.salt);

  const request = prepareCredentialRequest(secret, salt, h);
  const statement = issueCredential(sk, request);
  const credential = assembleCredential(secret, salt, statement);

  const pk = publicKey(sk);
  return { issuerPrivateKey: sk, credential, issuerId: issuerIdOf(pk.x, pk.y) };
}
