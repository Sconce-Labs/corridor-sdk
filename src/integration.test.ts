/**
 * Cross-component integration: the witness the SDK builds must (1) satisfy the
 * circuit's constraints (verifyWitnessLocally mirrors `eligibility::check`) and
 * (2) carry a public-input vector in the exact `PI_INDEX` layout the Soroban
 * contract's `PublicInputs::decode` expects.
 *
 * The circuit ⇄ SDK seam is also checked in CI end-to-end: `npm run gen-fixture`
 * writes corridor-circuits' `Prover.toml` + `fixture.nr` and `nargo execute`
 * solves it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildWitness } from "./witness.js";
import { makeFixture } from "./fixture.js";
import { verifyWitnessLocally } from "./verify-local.js";
import { PI_INDEX, PI_LEN } from "./types.js";
import type { CorridorPolicy } from "./types.js";
import { toBytes32, bytes32ToBigInt } from "./hex.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;
const AUDITOR = toBytes32(0xa0d170n);

function policy(
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

test("SDK witness satisfies the circuit and matches the contract ABI layout", () => {
  const fx = makeFixture({ holder: { tier: 4, credEpoch: 9 } });
  const w = buildWitness(
    fx.credential,
    policy(fx, { auditorPubkey: AUDITOR }),
    { disclosedTag: 2, auditorPubkey: AUDITOR, auditorNonce: toBytes32(77n) },
    { corridorId: CID, now: 1_000_000 },
  );

  assert.deepEqual(verifyWitnessLocally(w), { ok: true, failures: [] });

  assert.equal(w.publicInputs.length, PI_LEN); // 9
  assert.equal(w.publicInputs[PI_INDEX.corridorId], CID);
  assert.equal(bytes32ToBigInt(w.publicInputs[PI_INDEX.minTier]!), 3n);
  assert.equal(bytes32ToBigInt(w.publicInputs[PI_INDEX.now]!), 1_000_000n);
  assert.equal(w.publicInputs[PI_INDEX.issuerId], fx.issuerId);
  assert.equal(bytes32ToBigInt(w.publicInputs[PI_INDEX.minCredEpoch]!), 1n);
  assert.equal(w.publicInputs[PI_INDEX.auditorPubkey], AUDITOR);
  assert.equal(w.publicInputs[PI_INDEX.auditorBlob], w.auditorBlob);
});

test("a proof from an issuer not on the allowlist would fail the contract's check", () => {
  // buildWitness itself does not enforce the allowlist (the contract does), but
  // the issuer_id it emits must be the one the contract compares.
  const fx = makeFixture();
  const other = makeFixture();
  const w = buildWitness(
    fx.credential,
    policy(fx),
    { disclosedTag: 0, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(1n) },
    { corridorId: CID, now: 1_000_000 },
  );
  assert.notEqual(w.publicInputs[PI_INDEX.issuerId], other.issuerId);
});

test("the auditor blob is bound to the policy's auditor key", () => {
  const fx = makeFixture();
  const w1 = buildWitness(
    fx.credential,
    policy(fx, { auditorPubkey: toBytes32(1n) }),
    { disclosedTag: 0, auditorPubkey: toBytes32(1n), auditorNonce: toBytes32(5n) },
    { corridorId: CID, now: 1_000_000 },
  );
  const w2 = buildWitness(
    fx.credential,
    policy(fx, { auditorPubkey: toBytes32(2n) }),
    { disclosedTag: 0, auditorPubkey: toBytes32(2n), auditorNonce: toBytes32(5n) },
    { corridorId: CID, now: 1_000_000 },
  );
  assert.notEqual(w1.auditorBlob, w2.auditorBlob);

  // a proof that claims a different auditor key than the policy is refused locally
  assert.throws(
    () =>
      buildWitness(
        fx.credential,
        policy(fx, { auditorPubkey: toBytes32(1n) }),
        { disclosedTag: 0, auditorPubkey: toBytes32(9n), auditorNonce: toBytes32(5n) },
        { corridorId: CID, now: 1_000_000 },
      ),
    /auditor key/,
  );
});
