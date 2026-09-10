/**
 * The corridor-operator payout gate: before releasing funds, check the
 * recipient's nullifier has been granted a pass on this corridor.
 *   npx tsx examples/payout-gate.ts
 */
import { isCleared, TESTNET } from "../src/index.js";

const CID =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;
const GRANTED =
  "0x3333333333333333333333333333333333333333333333333333333333333333" as const;
const UNKNOWN =
  "0x0000000000000000000000000000000000000000000000000000000000000000" as const;

console.log("granted nullifier :", await isCleared(TESTNET, CID, GRANTED)); // true
console.log("unknown nullifier :", await isCleared(TESTNET, CID, UNKNOWN)); // false

// In a real payout contract this check is a Soroban cross-contract call to
// corridor_attestation.is_cleared — the SDK version is for off-chain flows.
