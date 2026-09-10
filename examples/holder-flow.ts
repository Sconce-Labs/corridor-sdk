/**
 * The holder flow (Option B): an issuer signs a credential, the holder builds a
 * witness for a corridor. No Midnight deployment needed.
 *   npx tsx examples/holder-flow.ts
 */
import { Corridor, TESTNET, makeFixture, verifyWitnessLocally } from "../src/index.js";
import type { CorridorPolicy } from "../src/index.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;
const now = Math.floor(Date.now() / 1000);

// A regulated issuer signs a credential for the holder.
const fx = makeFixture({
  holder: { tier: 3, expiry: now + 30 * 86_400, credEpoch: 12 },
});

// The corridor operator's policy accepts that issuer.
const policy: CorridorPolicy = {
  operator: "G".padEnd(56, "A"),
  acceptedIssuers: [fx.issuerId],
  minTier: 2,
  requiredDisclosures: 0,
  minCredEpoch: 10n,
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

console.log("issuer id :", witness.issuerId);
console.log("nullifier :", witness.nullifier);
console.log("local check:", verifyWitnessLocally(witness));
console.log("public inputs (9):");
witness.publicInputs.forEach((v, i) => console.log(`  [${i}] ${v}`));
