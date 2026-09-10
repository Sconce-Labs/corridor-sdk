/**
 * The full Option B flow, showing the three parties explicitly. No Midnight
 * deployment needed.
 *   npx tsx examples/holder-flow.ts
 */
import {
  Corridor,
  TESTNET,
  prepareCredentialRequest,
  issueCredential,
  assembleCredential,
  verifyWitnessLocally,
  randomSecret,
  randomFieldElement,
  publicKey,
  issuerIdOf,
  randomIssuerKey,
} from "../src/index.js";
import type { CorridorPolicy } from "../src/index.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;
const now = Math.floor(Date.now() / 1000);

// ── holder: generate a secret, blind it, package the attributes ──────────────
const holderSecret = randomSecret(); // CSPRNG — never leaves the device
const salt = randomFieldElement();
const request = prepareCredentialRequest(holderSecret, salt, {
  tier: 3,
  expiry: now + 14 * 86_400, // short — days
  credEpoch: 12,
});
console.log("holder → issuer :", { holderBinding: request.holderBinding, tier: 3 });

// ── issuer: run KYC out of band, then sign — WITHOUT seeing holderSecret ──────
const issuerSk = randomIssuerKey();
const statement = issueCredential(issuerSk, request);
const pk = publicKey(issuerSk);
console.log("issuer → holder :", statement.issuer);

// ── holder: reassemble into wallet material ─────────────────────────────────
const credential = assembleCredential(holderSecret, salt, statement);

// ── the corridor operator's policy accepts that issuer ──────────────────────
const policy: CorridorPolicy = {
  operator: "G".padEnd(56, "A"),
  acceptedIssuers: [issuerIdOf(pk.x, pk.y)],
  minTier: 2,
  requiredDisclosures: 0,
  minCredEpoch: 10n,
  verifier: "C".padEnd(56, "A"),
  vkHash: "0x0000000000000000000000000000000000000000000000000000000000000009",
  auditorPubkey: "0x0000000000000000000000000000000000000000000000000000000000000000",
  nowToleranceSecs: 300n,
  paused: false,
};

// ── holder: build the circuit witness for a specific corridor ───────────────
const c = new Corridor(TESTNET);
const witness = c.buildWitness(
  credential,
  policy,
  {
    disclosedTag: 1, // REMITTANCE — a category label, not an attested attribute
    auditorPubkey: "0x0000000000000000000000000000000000000000000000000000000000000000",
    auditorNonce: randomFieldElement(),
  },
  { corridorId: CID, now },
);

console.log("issuer id  :", witness.issuerId);
console.log("nullifier  :", witness.nullifier);
console.log("local check:", verifyWitnessLocally(witness));
console.log("public inputs (9):");
witness.publicInputs.forEach((v, i) => console.log(`  [${i}] ${v}`));
