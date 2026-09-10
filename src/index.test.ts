import { test } from "node:test";
import assert from "node:assert/strict";
import { Corridor, TESTNET, poseidon2, merkleRoot, leBits } from "./index.js";
import { buildWitness } from "./witness.js";
import { makeFixture, toProverToml } from "./fixture.js";
import type { CorridorPolicy, CredentialMaterial } from "./types.js";
import { toBytes32 } from "./hex.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;

test("poseidon2 matches the pinned cross-impl vector (== the Noir circuit)", () => {
  assert.equal(
    toBytes32(poseidon2([1n, 2n])),
    "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383",
  );
});

test("leBits is little-endian", () => {
  assert.deepEqual(leBits(0b1011n, 4), [true, true, false, true]);
});

test("buildWitness assembles a 9-field public vector and derived values", () => {
  const holder = {
    holderSecret: 1n,
    tier: 2,
    expiry: 2_000_000,
    issuerId: 7n,
    salt: 5n,
  };
  const fx = makeFixture({ holder, index: 0n, minTier: 2 });
  const policy: CorridorPolicy = {
    operator: "G".padEnd(56, "A"),
    acceptedIssuers: [toBytes32(7n)],
    minTier: 2,
    requiredDisclosures: 0,
    credentialRoot: fx.policy.credentialRoot,
    revocationRoot: fx.policy.revocationRoot,
    rootEpoch: 1n,
    verifier: "C".padEnd(56, "A"),
    vkHash: toBytes32(9n),
    nowToleranceSecs: 300n,
    paused: false,
  };

  const w = buildWitness(
    fx.credential,
    policy,
    { disclosedTag: 1, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(0n) },
    { corridorId: CID, now: 1_000_000 },
  );

  assert.equal(w.publicInputs.length, 9);
  assert.equal(w.publicInputs[2], CID);
  assert.equal(w.nullifier, toBytes32(poseidon2([1n, BigInt(CID)])));
  assert.equal(w.commitment, fx.commitment);
});

test("buildWitness rejects a revoked credential", () => {
  const holder = {
    holderSecret: 9n,
    tier: 3,
    expiry: 9_000_000,
    issuerId: 7n,
    salt: 2n,
  };
  const commitment = poseidon2([9n, 3n, 9_000_000n, 7n, 2n]);
  // put THIS credential's key in the revocation tree
  const fx = makeFixture({ holder, index: 0n, minTier: 2, revoked: [commitment] });
  const policy = {
    ...({} as CorridorPolicy),
    acceptedIssuers: [toBytes32(7n)],
    minTier: 2,
    credentialRoot: fx.policy.credentialRoot,
    revocationRoot: fx.policy.revocationRoot,
  } as CorridorPolicy;
  assert.throws(
    () =>
      buildWitness(
        fx.credential,
        policy,
        { disclosedTag: 1, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(0n) },
        { corridorId: CID, now: 1_000_000 },
      ),
    /revoked/,
  );
});

test("makeFixture produces a witness buildWitness accepts", () => {
  const holder = {
    holderSecret: 12345n,
    tier: 3,
    expiry: 9_000_000,
    issuerId: 7n,
    salt: 42n,
  };
  const fx = makeFixture({
    holder,
    index: 3n,
    others: [{ ...holder, holderSecret: 999n }],
    revoked: [poseidon2([1n])], // some unrelated commitment
    minTier: 2,
  });

  const policy: CorridorPolicy = {
    operator: "G".padEnd(56, "A"),
    acceptedIssuers: [toBytes32(7n)],
    minTier: fx.policy.minTier,
    requiredDisclosures: 0,
    credentialRoot: fx.policy.credentialRoot,
    revocationRoot: fx.policy.revocationRoot,
    rootEpoch: 1n,
    verifier: "C".padEnd(56, "A"),
    vkHash: toBytes32(9n),
    nowToleranceSecs: 300n,
    paused: false,
  };

  const w = buildWitness(
    fx.credential,
    policy,
    { disclosedTag: 2, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(7n) },
    { corridorId: CID, now: 1_000_000 },
  );
  assert.equal(w.publicInputs.length, 9);
  assert.equal(w.commitment, fx.commitment);

  const toml = toProverToml(w.publicInputs, w.privateInputs);
  assert.match(toml, /^credential_root = "0x/);
  assert.match(toml, /cred_index_bits = \[/);
});

test("buildWitness rejects an expired credential", () => {
  const policy = {
    minTier: 1,
    credentialRoot: toBytes32(0n),
    revocationRoot: toBytes32(0n),
  } as CorridorPolicy;
  const cred = { tier: 2, expiry: 100 } as CredentialMaterial;
  assert.throws(
    () =>
      buildWitness(
        cred,
        policy,
        { disclosedTag: 0, auditorPubkey: toBytes32(0n), auditorNonce: toBytes32(0n) },
        { corridorId: CID, now: 1_000_000 },
      ),
    /expired/,
  );
});

// ── live testnet reads — gated on CORRIDOR_LIVE_TESTS=1 ─────────────────────
const live = { skip: process.env.CORRIDOR_LIVE_TESTS !== "1" };

test("getPolicy reads the smoke-test corridor from testnet", live, async () => {
  const p = await new Corridor(TESTNET).getPolicy(CID);
  assert.equal(p.minTier, 2);
  assert.equal(p.rootEpoch, 1n);
  assert.equal(p.paused, false);
});

test("isCleared is true for the smoke-test nullifier", live, async () => {
  const c = new Corridor(TESTNET);
  const nullifier =
    "0x3333333333333333333333333333333333333333333333333333333333333333" as const;
  assert.equal(await c.isCleared(CID, nullifier), true);
  assert.equal(await c.isCleared(CID, toBytes32(0n)), false);
});

test("passes >= 1 for the smoke-test corridor", live, async () => {
  assert.ok((await new Corridor(TESTNET).passes(CID)) >= 1n);
});
