/**
 * Test-fixture helpers: build a small credential tree, derive the inclusion +
 * revocation-non-membership paths for one holder, and emit either a
 * `CredentialMaterial` (for `buildWitness`) or a Noir `Prover.toml`.
 *
 * Not for production — a real deployment reads paths from the Midnight indexer.
 */

import type { Bytes32, CorridorPolicy, CredentialMaterial } from "./types.js";
import { toBytes32, bytes32ToBigInt } from "./hex.js";
import { poseidon2, leBits } from "./witness.js";

const DEPTH = 32;

export interface CredentialAttrs {
  holderSecret: bigint;
  tier: number;
  expiry: number;
  issuerId: bigint;
  salt: bigint;
}

export function commitmentOf(a: CredentialAttrs): bigint {
  return poseidon2([
    a.holderSecret,
    BigInt(a.tier),
    BigInt(a.expiry),
    a.issuerId,
    a.salt,
  ]);
}

/** A sparse Merkle tree over `DEPTH` bits, empty leaf = 0. */
class SparseTree {
  private nodes = new Map<string, bigint>(); // "level:index" -> value
  private zero: bigint[] = [];

  constructor() {
    this.zero[0] = 0n;
    for (let i = 1; i <= DEPTH; i++) this.zero[i] = poseidon2([this.zero[i - 1]!, this.zero[i - 1]!]);
  }

  private get(level: number, index: bigint): bigint {
    return this.nodes.get(`${level}:${index}`) ?? this.zero[level]!;
  }

  insert(index: bigint, leaf: bigint): void {
    let idx = index;
    this.nodes.set(`0:${idx}`, leaf);
    for (let lvl = 0; lvl < DEPTH; lvl++) {
      const sib = idx ^ 1n;
      const [l, r] = idx % 2n === 0n ? [this.get(lvl, idx), this.get(lvl, sib)] : [this.get(lvl, sib), this.get(lvl, idx)];
      idx >>= 1n;
      this.nodes.set(`${lvl + 1}:${idx}`, poseidon2([l, r]));
    }
  }

  root(): bigint {
    return this.get(DEPTH, 0n);
  }

  /** Co-path (siblings, leaf → root) and the direction bits for `index`. */
  proof(index: bigint): { siblings: bigint[]; bits: boolean[] } {
    const siblings: bigint[] = [];
    const bits: boolean[] = [];
    let idx = index;
    for (let lvl = 0; lvl < DEPTH; lvl++) {
      siblings.push(this.get(lvl, idx ^ 1n));
      bits.push(idx % 2n === 1n);
      idx >>= 1n;
    }
    return { siblings, bits };
  }
}

export interface Fixture {
  policy: Pick<CorridorPolicy, "credentialRoot" | "revocationRoot" | "minTier">;
  credential: CredentialMaterial;
  commitment: Bytes32;
}

/**
 * Build a credential tree containing `holder` (at `index`) plus `others`,
 * with `revoked` commitments in the revocation tree, and return everything
 * `buildWitness` needs for `holder`.
 */
export function makeFixture(opts: {
  holder: CredentialAttrs;
  index?: bigint;
  others?: CredentialAttrs[];
  revoked?: bigint[];
  minTier?: number;
}): Fixture {
  const index = opts.index ?? 0n;
  const credTree = new SparseTree();
  const holderCommit = commitmentOf(opts.holder);
  credTree.insert(index, holderCommit);
  (opts.others ?? []).forEach((a, i) => credTree.insert(BigInt(i + 1) + index + 1n, commitmentOf(a)));

  const revTree = new SparseTree();
  for (const c of opts.revoked ?? []) {
    revTree.insert(BigInt.asUintN(DEPTH, poseidon2([c])), 1n); // mark slot non-empty
  }

  const credProof = credTree.proof(index);
  const revSlot = poseidon2([holderCommit]);
  const revProof = revTree.proof(BigInt.asUintN(DEPTH, revSlot));
  // sanity: our leBits must equal the tree's derived bits
  const expectBits = leBits(revSlot);
  if (revProof.bits.some((b, i) => b !== expectBits[i])) {
    throw new Error("revocation slot bit derivation mismatch");
  }

  return {
    policy: {
      credentialRoot: toBytes32(credTree.root()),
      revocationRoot: toBytes32(revTree.root()),
      minTier: opts.minTier ?? opts.holder.tier,
    },
    commitment: toBytes32(holderCommit),
    credential: {
      holderSecret: toBytes32(opts.holder.holderSecret),
      tier: opts.holder.tier,
      expiry: opts.holder.expiry,
      issuerId: toBytes32(opts.holder.issuerId),
      salt: toBytes32(opts.holder.salt),
      credSiblings: credProof.siblings.map(toBytes32),
      credIndexBits: credProof.bits,
      revSiblings: revProof.siblings.map(toBytes32),
    },
  };
}

/** Emit a Noir `Prover.toml` for the circuit from a witness. */
export function toProverToml(publicInputs: Bytes32[], privateInputs: Record<string, unknown>): string {
  const q = (v: unknown): string => {
    if (Array.isArray(v)) return `[${v.map(q).join(", ")}]`;
    if (typeof v === "boolean") return String(v);
    if (typeof v === "number") return `"${v}"`;
    return `"${String(v)}"`;
  };
  const names = [
    "credential_root", "revocation_root", "corridor_id", "min_tier", "now",
    "nullifier", "disclosed_tag", "issuer_id", "auditor_blob",
  ];
  const lines = names.map((n, i) => {
    const raw = publicInputs[i]!;
    const numeric = n === "min_tier" || n === "now" || n === "disclosed_tag";
    return `${n} = ${numeric ? `"${bytes32ToBigInt(raw)}"` : q(raw)}`;
  });
  for (const [k, v] of Object.entries(privateInputs)) lines.push(`${k} = ${q(v)}`);
  return lines.join("\n") + "\n";
}
