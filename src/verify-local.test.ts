import { test } from "node:test";
import assert from "node:assert/strict";
import { buildWitness } from "./witness.js";
import { makeFixture } from "./fixture.js";
import { verifyWitnessLocally } from "./verify-local.js";
import { toBytes32 } from "./hex.js";
import type { CorridorPolicy } from "./types.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;

function policyFor(fx: ReturnType<typeof makeFixture>): CorridorPolicy {
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
  };
}

test("verifyWitnessLocally accepts a fixture-built witness", () => {
  const fx = makeFixture({
    holder: { holderSecret: 5n, tier: 3, expiry: 9_000_000, issuerId: 7n, salt: 1n },
    index: 2n,
    minTier: 2,
  });
  const w = buildWitness(
    fx.credential,
    policyFor(fx),
    { disclosedTag: 3, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(9n) },
    { corridorId: CID, now: 1_000_000 },
  );
  assert.deepEqual(verifyWitnessLocally(w), { ok: true, failures: [] });
});

test("verifyWitnessLocally catches a tampered nullifier", () => {
  const fx = makeFixture({
    holder: { holderSecret: 5n, tier: 3, expiry: 9_000_000, issuerId: 7n, salt: 1n },
    index: 2n,
    minTier: 2,
  });
  const w = buildWitness(
    fx.credential,
    policyFor(fx),
    { disclosedTag: 3, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(9n) },
    { corridorId: CID, now: 1_000_000 },
  );
  w.publicInputs[5] = toBytes32(0xbadn); // nullifier
  const res = verifyWitnessLocally(w);
  assert.equal(res.ok, false);
  assert.ok(res.failures.includes("bad nullifier"));
});
