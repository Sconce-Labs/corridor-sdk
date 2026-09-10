/**
 * Cross-component integration: the witness the SDK builds must (1) satisfy the
 * circuit's constraints (verifyWitnessLocally mirrors `eligibility::check`),
 * (2) carry a public-input vector in the exact `PI_INDEX` layout the Soroban
 * contract's `PublicInputs::decode` expects, and (3) round-trip a revoked
 * credential to a rejection.
 *
 * The circuit ⇄ SDK seam is also checked in CI end-to-end: `npm run gen-fixture`
 * writes corridor-circuits' `Prover.toml` and `nargo execute` solves it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildWitness } from "./witness.js";
import { makeFixture } from "./fixture.js";
import { verifyWitnessLocally } from "./verify-local.js";
import { poseidon2 } from "./poseidon.js";
import { PI_INDEX, PI_LEN } from "./types.js";
import type { CorridorPolicy } from "./types.js";
import { toBytes32, bytes32ToBigInt } from "./hex.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;
const AUDITOR = toBytes32(0xa0d170n); // a non-zero auditor key

function policy(
  fx: ReturnType<typeof makeFixture>,
  over: Partial<CorridorPolicy> = {},
): CorridorPolicy {
  return {
    operator: "G".padEnd(56, "A"),
    acceptedIssuers: [toBytes32(7n)],
    minTier: fx.policy.minTier,
    requiredDisclosures: 0,
    credentialRoot: fx.policy.credentialRoot,
    revocationRoot: fx.policy.revocationRoot,
    rootEpoch: 1n,
    verifier: "C".padEnd(56, "A"),
    vkHash: toBytes32(9n),
    auditorPubkey: toBytes32(0n),
    nowToleranceSecs: 300n,
    paused: false,
    ...over,
  };
}

const holder = {
  holderSecret: 424242n,
  tier: 4,
  expiry: 9_999_999,
  issuerId: 7n,
  salt: 11n,
};

test("SDK witness satisfies the circuit and matches the contract ABI layout", () => {
  const fx = makeFixture({ holder, index: 5n, minTier: 3 });
  const w = buildWitness(
    fx.credential,
    policy(fx, { auditorPubkey: AUDITOR }),
    { disclosedTag: 2, auditorPubkey: AUDITOR, auditorNonce: toBytes32(77n) },
    { corridorId: CID, now: 1_000_000 },
  );

  // 1. circuit constraints
  assert.deepEqual(verifyWitnessLocally(w), { ok: true, failures: [] });

  // 2. ABI layout — the exact slots corridor_types::PublicInputs::decode reads
  assert.equal(w.publicInputs.length, PI_LEN);
  assert.equal(w.publicInputs[PI_INDEX.credentialRoot], fx.policy.credentialRoot);
  assert.equal(w.publicInputs[PI_INDEX.revocationRoot], fx.policy.revocationRoot);
  assert.equal(w.publicInputs[PI_INDEX.corridorId], CID);
  assert.equal(bytes32ToBigInt(w.publicInputs[PI_INDEX.minTier]!), 3n);
  assert.equal(bytes32ToBigInt(w.publicInputs[PI_INDEX.now]!), 1_000_000n);
  assert.equal(
    w.publicInputs[PI_INDEX.nullifier],
    toBytes32(poseidon2([424242n, BigInt(CID)])),
  );
  assert.equal(bytes32ToBigInt(w.publicInputs[PI_INDEX.disclosedTag]!), 2n);
  assert.equal(w.publicInputs[PI_INDEX.issuerId], toBytes32(7n));
  assert.equal(w.publicInputs[PI_INDEX.auditorPubkey], AUDITOR);
  assert.equal(w.publicInputs[PI_INDEX.auditorBlob], w.auditorBlob);
});

test("a revoked credential is rejected before proving", () => {
  const commitment = poseidon2([
    holder.holderSecret,
    BigInt(holder.tier),
    BigInt(holder.expiry),
    holder.issuerId,
    holder.salt,
  ]);
  const fx = makeFixture({ holder, index: 5n, minTier: 3, revoked: [commitment] });
  assert.throws(
    () =>
      buildWitness(
        fx.credential,
        policy(fx),
        { disclosedTag: 0, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(1n) },
        { corridorId: CID, now: 1_000_000 },
      ),
    /revoked/,
  );
});

test("the auditor blob is bound to the auditor key, not holder-chosen", () => {
  const fx = makeFixture({ holder, index: 5n, minTier: 3 });
  const w1 = buildWitness(
    fx.credential,
    policy(fx),
    { disclosedTag: 0, auditorPubkey: toBytes32(1n), auditorNonce: toBytes32(5n) },
    { corridorId: CID, now: 1_000_000 },
  );
  const w2 = buildWitness(
    fx.credential,
    policy(fx),
    { disclosedTag: 0, auditorPubkey: toBytes32(2n), auditorNonce: toBytes32(5n) },
    { corridorId: CID, now: 1_000_000 },
  );
  assert.notEqual(w1.auditorBlob, w2.auditorBlob);
  assert.notEqual(
    w1.publicInputs[PI_INDEX.auditorPubkey],
    w2.publicInputs[PI_INDEX.auditorPubkey],
  );
});
