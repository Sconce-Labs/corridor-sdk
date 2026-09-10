import { test } from "node:test";
import assert from "node:assert/strict";
import { buildWitness, issuerIdOf } from "./witness.js";
import { makeFixture, issueCredential } from "./fixture.js";
import { verifyWitnessLocally } from "./verify-local.js";
import { publicKey } from "./schnorr.js";
import { poseidon2 } from "./poseidon.js";
import { PI_INDEX, PI_LEN } from "./types.js";
import type { CorridorPolicy } from "./types.js";
import { toBytes32, bytes32ToBigInt } from "./hex.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;

function policyFor(
  fx: ReturnType<typeof makeFixture>,
  over: Partial<CorridorPolicy> = {},
): CorridorPolicy {
  return {
    operator: "G".padEnd(56, "A"),
    acceptedIssuers: [fx.issuerId],
    minTier: 3,
    requiredDisclosures: 0,
    minCredEpoch: 1n,
    verifier: "C".padEnd(56, "A"),
    vkHash: toBytes32(9n),
    auditorPubkey: toBytes32(0n),
    nowToleranceSecs: 300n,
    paused: false,
    ...over,
  };
}

const disclosure = {
  disclosedTag: 2,
  auditorPubkey: toBytes32(0n),
  auditorNonce: toBytes32(77n),
};

test("buildWitness assembles the 9-field vector and passes the local check", () => {
  const fx = makeFixture();
  const w = buildWitness(fx.credential, policyFor(fx), disclosure, {
    corridorId: CID,
    now: 1_000_000,
  });

  assert.equal(w.publicInputs.length, PI_LEN);
  assert.equal(w.publicInputs[PI_INDEX.corridorId], CID);
  assert.equal(bytes32ToBigInt(w.publicInputs[PI_INDEX.minTier]!), 3n);
  assert.equal(w.publicInputs[PI_INDEX.issuerId], fx.issuerId);
  assert.equal(bytes32ToBigInt(w.publicInputs[PI_INDEX.minCredEpoch]!), 1n);
  assert.equal(
    w.publicInputs[PI_INDEX.nullifier],
    toBytes32(poseidon2([bytes32ToBigInt(fx.credential.holderSecret), BigInt(CID)])),
  );
  assert.deepEqual(verifyWitnessLocally(w), { ok: true, failures: [] });
});

test("buildWitness rejects a forged signature", () => {
  const fx = makeFixture();
  const bad = {
    ...fx.credential,
    issuer: {
      ...fx.credential.issuer,
      sLo: toBytes32(bytes32ToBigInt(fx.credential.issuer.sLo) + 1n),
    },
  };
  assert.throws(
    () =>
      buildWitness(bad, policyFor(fx), disclosure, { corridorId: CID, now: 1_000_000 }),
    /signature does not verify/,
  );
});

test("buildWitness rejects a credential below the corridor's epoch floor", () => {
  const fx = makeFixture({ holder: { credEpoch: 3 } });
  assert.throws(
    () =>
      buildWitness(fx.credential, policyFor(fx, { minCredEpoch: 5n }), disclosure, {
        corridorId: CID,
        now: 1_000_000,
      }),
    /revocation floor/,
  );
});

test("buildWitness rejects an expired credential", () => {
  const fx = makeFixture({ holder: { expiry: 100 } });
  assert.throws(
    () =>
      buildWitness(fx.credential, policyFor(fx), disclosure, {
        corridorId: CID,
        now: 1_000_000,
      }),
    /expired/,
  );
});

test("issuer id is Poseidon2 of both pubkey coordinates", () => {
  const fx = makeFixture();
  const pk = publicKey(fx.issuerPrivateKey);
  assert.equal(fx.issuerId, issuerIdOf(pk.x, pk.y));
  assert.notEqual(fx.issuerId, issuerIdOf(pk.y, pk.x));
});

test("two issuers produce different signatures for the same holder", () => {
  const holder = {
    holderSecret: 5n,
    tier: 4,
    expiry: 9_000_000,
    credEpoch: 7,
    salt: 1n,
  };
  const a = issueCredential(makeFixture().issuerPrivateKey, holder);
  const b = issueCredential(makeFixture().issuerPrivateKey, holder);
  assert.notEqual(a.issuer.pubkeyX, b.issuer.pubkeyX);
});
