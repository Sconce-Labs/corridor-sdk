/**
 * Test-fixture + issuer helper. `issueCredential` is what a real issuer does
 * (sign a statement); `makeFixture` wraps it with a deterministic holder for
 * tests and `gen-circuit-fixture`.
 */

import type { Bytes32, CredentialMaterial, IssuerSignature } from "./types.js";
import { toBytes32 } from "./hex.js";
import { publicKey, sign, randomIssuerKey } from "./schnorr.js";
import { statementMessage, issuerIdOf } from "./witness.js";

export interface CredentialAttrs {
  holderSecret: bigint;
  tier: number;
  expiry: number;
  credEpoch: number;
  salt: bigint;
}

/** An issuer signs a credential statement for a holder. Returns the material
 *  the holder's wallet stores. */
export function issueCredential(
  issuerPrivateKey: Bytes32,
  attrs: CredentialAttrs,
): CredentialMaterial {
  const pk = publicKey(issuerPrivateKey);
  const cred: Omit<CredentialMaterial, "issuer"> = {
    holderSecret: toBytes32(attrs.holderSecret),
    tier: attrs.tier,
    expiry: attrs.expiry,
    credEpoch: attrs.credEpoch,
    salt: toBytes32(attrs.salt),
  };
  const sig = sign(issuerPrivateKey, statementMessage(cred as CredentialMaterial));
  const issuer: IssuerSignature = {
    pubkeyX: pk.x,
    pubkeyY: pk.y,
    sLo: sig.sLo,
    sHi: sig.sHi,
    eLo: sig.eLo,
    eHi: sig.eHi,
  };
  return { ...cred, issuer };
}

export interface Fixture {
  issuerPrivateKey: Bytes32;
  credential: CredentialMaterial;
  /** `Poseidon2(pk.x, pk.y)` — put this in a policy's `acceptedIssuers`. */
  issuerId: Bytes32;
}

const DEFAULT_HOLDER: CredentialAttrs = {
  holderSecret: 0x0affee0decaf0badf00d1234567890abcdef0affee0decaf0badf00d12345678n,
  tier: 4,
  expiry: 9_000_000,
  credEpoch: 7,
  salt: 42n,
};

/** Build a valid signed credential for a holder. */
export function makeFixture(
  opts: { holder?: Partial<CredentialAttrs>; issuerPrivateKey?: Bytes32 } = {},
): Fixture {
  const sk = opts.issuerPrivateKey ?? randomIssuerKey();
  const attrs = { ...DEFAULT_HOLDER, ...opts.holder };
  const credential = issueCredential(sk, attrs);
  const pk = publicKey(sk);
  return {
    issuerPrivateKey: sk,
    credential,
    issuerId: issuerIdOf(pk.x, pk.y),
  };
}
