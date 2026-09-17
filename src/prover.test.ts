import test from "node:test";
import assert from "node:assert/strict";
import {
  Corridor,
  TESTNET,
  startLocalProver,
  formatProverToml,
  makeFixture,
  buildWitness,
  toBytes32,
  type EligibilityWitness,
  type CorridorPolicy,
} from "./index.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;
const AUDITOR = toBytes32(0xa0d170n);

function samplePolicy(
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
    auditorPubkey: AUDITOR,
    nowToleranceSecs: 300n,
    paused: false,
    ...over,
  };
}

function sampleWitness(): EligibilityWitness {
  const fx = makeFixture({ holder: { tier: 4, credEpoch: 9 } });
  return buildWitness(
    fx.credential,
    samplePolicy(fx),
    { disclosedTag: 2, auditorPubkey: AUDITOR, auditorNonce: toBytes32(77n) },
    { corridorId: CID, now: 1_000_000 },
  );
}

test("formatProverToml correctly outputs circuit Prover.toml syntax", () => {
  const w = sampleWitness();
  const toml = formatProverToml(w);

  assert.match(toml, /corridor_id = "0x[0-9a-f]+"/);
  assert.match(toml, /holder_secret = "0x[0-9a-f]+"/);
  assert.match(toml, /nullifier = "0x[0-9a-f]+"/);
  assert.match(toml, /sig_s_lo = "0x[0-9a-f]+"/);
  assert.match(toml, /sig_e_hi = "0x[0-9a-f]+"/);
  assert.match(toml, /min_tier = "\d+"/);
});

test("startLocalProver and Corridor.requestProof end-to-end flow", async () => {
  // Start prover on an ephemeral local port (port 0)
  const prover = await startLocalProver({ port: 0 });
  assert.ok(prover.url.startsWith("http://127.0.0.1:"));

  try {
    // Check health endpoint
    const healthRes = await fetch(`${prover.url}/health`);
    assert.equal(healthRes.status, 200);
    const health = (await healthRes.json()) as { status: string };
    assert.equal(health.status, "ok");

    // Configure Corridor with local proverUrl
    const c = new Corridor({
      ...TESTNET,
      proverUrl: prover.url,
    });

    const w = sampleWitness();
    const proof = await c.requestProof(w);

    assert.ok(proof.bytes instanceof Uint8Array);
    assert.equal(proof.bytes.length, 424);
    assert.equal(proof.publicInputs.length, w.publicInputs.length);
    assert.deepEqual(proof.publicInputs, w.publicInputs);
  } finally {
    await prover.close();
  }
});

test("prover rejects malformed/tampered witness", async () => {
  const prover = await startLocalProver({ port: 0 });

  try {
    const w = sampleWitness();
    // Tamper with disclosedTag to violate bounds (> 16)
    const badWitness: EligibilityWitness = {
      ...w,
      publicInputs: [...w.publicInputs],
    };
    badWitness.publicInputs[4] =
      "0x00000000000000000000000000000000000000000000000000000000000000ff" as any;

    const res = await fetch(`${prover.url}/prove`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(badWitness),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as { error: string };
    assert.match(body.error, /Invalid witness/);
  } finally {
    await prover.close();
  }
});
