/**
 * @corridor/verify — client SDK for Corridor.
 *
 *   import { Corridor, TESTNET } from "@corridor/verify";
 *   const c = new Corridor(TESTNET);
 *   const policy = await c.getPolicy(corridorId);          // live
 *   const ok = await c.isCleared(corridorId, nullifier);   // live — the payout gate
 *   const w = c.buildWitness(cred, policy, disclosure, { corridorId, now });  // local
 *   const proof = await c.requestProof(w);                 // needs proverUrl (M3)
 *   await c.enter(corridorId, proof);                      // needs relayerUrl (M6)
 */

import type {
  Bytes32,
  CorridorConfig,
  CorridorPolicy,
  CredentialMaterial,
  DisclosureRequest,
  EligibilityWitness,
} from "./types.js";
import { SorobanReader } from "./soroban.js";
import { buildWitness } from "./witness.js";

export * from "./types.js";
export { buildWitness, merkleRoot } from "./witness.js";
export { poseidon2, CONFORMANCE_VECTOR } from "./poseidon.js";
export { SparseTree, rootFromProof, leBits, DEPTH } from "./merkle.js";
export { makeFixture, toProverToml, commitmentOf } from "./fixture.js";
export { SorobanReader } from "./soroban.js";
export * from "./hex.js";

export interface Proof {
  bytes: Uint8Array;
  publicInputs: Bytes32[];
}

export class Corridor {
  private readonly reader: SorobanReader;

  constructor(private readonly cfg: CorridorConfig) {
    this.reader = new SorobanReader(cfg);
  }

  /** Fetch a corridor's on-chain policy. */
  getPolicy(corridorId: Bytes32): Promise<CorridorPolicy> {
    return this.reader.getPolicy(corridorId);
  }

  /** The payout gate: has this nullifier been granted a pass on this corridor? */
  isCleared(corridorId: Bytes32, nullifier: Bytes32): Promise<boolean> {
    return this.reader.isCleared(corridorId, nullifier);
  }

  /** Aggregate pass count for a corridor. */
  passes(corridorId: Bytes32): Promise<bigint> {
    return this.reader.passes(corridorId);
  }

  /** Assemble the circuit witness locally. No network, no secrets leave. */
  buildWitness(
    cred: CredentialMaterial,
    policy: CorridorPolicy,
    req: DisclosureRequest,
    opts: { corridorId: Bytes32; now: number },
  ): EligibilityWitness {
    return buildWitness(cred, policy, req, opts);
  }

  /** POST the witness to a prover. Never sends `privateInputs` to a server you
   *  don't control — point `proverUrl` at a local process. */
  async requestProof(witness: EligibilityWitness): Promise<Proof> {
    if (!this.cfg.proverUrl) {
      throw new Error("no proverUrl configured — run a local Noir prover (M3)");
    }
    const res = await fetch(`${this.cfg.proverUrl}/prove`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(witness),
    });
    if (!res.ok) throw new Error(`prover ${res.status}: ${await res.text()}`);
    const { proof } = (await res.json()) as { proof: string };
    return {
      bytes: Uint8Array.from(Buffer.from(proof.replace(/^0x/, ""), "hex")),
      publicInputs: witness.publicInputs,
    };
  }

  /** Submit `enter` via the fee-sponsoring relayer so the holder's account
   *  stays unlinked from the pass. */
  async enter(corridorId: Bytes32, proof: Proof): Promise<{ txHash: string }> {
    if (!this.cfg.relayerUrl) {
      throw new Error("no relayerUrl configured (M6)");
    }
    const res = await fetch(`${this.cfg.relayerUrl}/enter`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        corridorId,
        proof: `0x${Buffer.from(proof.bytes).toString("hex")}`,
        publicInputs: proof.publicInputs,
      }),
    });
    if (!res.ok) throw new Error(`relayer ${res.status}: ${await res.text()}`);
    return (await res.json()) as { txHash: string };
  }
}

/** One-call helper for corridor operators. */
export async function isCleared(
  cfg: CorridorConfig,
  corridorId: Bytes32,
  nullifier: Bytes32,
): Promise<boolean> {
  return new Corridor(cfg).isCleared(corridorId, nullifier);
}
