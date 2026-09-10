/**
 * The holder flow with a local fixture (no Midnight deployment needed yet):
 * build a witness, emit a Prover.toml, and show the derived nullifier.
 *   npx tsx examples/holder-flow.ts
 */
import { Corridor, TESTNET, makeFixture, toProverToml } from "../src/index.js";
import type { CorridorPolicy } from "../src/index.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;
const now = Math.floor(Date.now() / 1000);

// A real holder reads paths from the Midnight indexer; here we synthesise a tree.
const fx = makeFixture({
  holder: {
    holderSecret: 0xdeadn,
    tier: 3,
    expiry: now + 86_400,
    issuerId: 7n,
    salt: 99n,
  },
  index: 1n,
  minTier: 2,
});

const policy: CorridorPolicy = {
  operator: "G".padEnd(56, "A"),
  acceptedIssuers: [
    "0x0000000000000000000000000000000000000000000000000000000000000007",
  ],
  minTier: fx.policy.minTier,
  requiredDisclosures: 0,
  credentialRoot: fx.policy.credentialRoot,
  revocationRoot: fx.policy.revocationRoot,
  rootEpoch: 1n,
  verifier: "C".padEnd(56, "A"),
  vkHash: "0x0000000000000000000000000000000000000000000000000000000000000009",
  auditorPubkey: "0x0000000000000000000000000000000000000000000000000000000000000000",
  nowToleranceSecs: 300n,
  paused: false,
};

const c = new Corridor(TESTNET);
const witness = c.buildWitness(
  fx.credential,
  policy,
  {
    disclosedTag: 2,
    auditorPubkey: "0x0000000000000000000000000000000000000000000000000000000000000000",
    auditorNonce: "0x0000000000000000000000000000000000000000000000000000000000000001",
  },
  { corridorId: CID, now },
);

console.log("nullifier   :", witness.nullifier);
console.log("commitment  :", witness.commitment);
console.log(
  "\nProver.toml:\n" + toProverToml(witness.publicInputs, witness.privateInputs),
);
