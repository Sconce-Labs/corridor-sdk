/**
 * Read a corridor's on-chain policy from Stellar testnet.
 *   npx tsx examples/read-policy.ts
 */
import { Corridor, TESTNET } from "../src/index.js";

const CID = "0x0000000000000000000000000000000000000000000000000000000000000004";

const policy = await new Corridor(TESTNET).getPolicy(CID as `0x${string}`);
console.log(
  JSON.stringify(policy, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2),
);
