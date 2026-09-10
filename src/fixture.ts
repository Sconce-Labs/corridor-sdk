/**
 * Test-fixture helpers: build a small credential tree, derive the inclusion +
 * revocation-non-membership paths for one holder, and emit either a
 * `CredentialMaterial` (for `buildWitness`) or a Noir `Prover.toml`.
 *
 * Not for production — a real deployment reads paths from the Midnight indexer.
 */

import type { Bytes32, CorridorPolicy, CredentialMaterial } from "./types.js";
import { toBytes32, bytes32ToBigInt } from "./hex.js";
import { poseidon2 } from "./poseidon.js";
import { SparseTree, leBits, DEPTH } from "./merkle.js";

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

export interface Fixture {
  policy: Pick<CorridorPolicy, "credentialRoot" | "revocationRoot" | "minTier">;
  credential: CredentialMaterial;
  commitment: Bytes32;
}

/**
 * Build a credential tree containing `holder` (at `index`) plus `others`, with
 * `revoked` commitments in the revocation tree, and return everything
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
  (opts.others ?? []).forEach((a, i) =>
    credTree.insert(BigInt(i) + index + 1n, commitmentOf(a)),
  );

  const revTree = new SparseTree();
  for (const c of opts.revoked ?? []) {
    revTree.insert(BigInt.asUintN(DEPTH, poseidon2([c])), 1n);
  }

  const credProof = credTree.proof(index);
  const revSlot = poseidon2([holderCommit]);
  const revProof = revTree.proof(BigInt.asUintN(DEPTH, revSlot));
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

/** Emit a Noir `Prover.toml` from a witness. */
export function toProverToml(
  publicInputs: Bytes32[],
  privateInputs: Record<string, unknown>,
): string {
  const q = (v: unknown): string => {
    if (Array.isArray(v)) return `[${v.map(q).join(", ")}]`;
    if (typeof v === "boolean") return String(v);
    if (typeof v === "number") return `"${v}"`;
    return `"${String(v)}"`;
  };
  const names = [
    "credential_root",
    "revocation_root",
    "corridor_id",
    "min_tier",
    "now",
    "nullifier",
    "disclosed_tag",
    "issuer_id",
    "auditor_blob",
  ];
  const lines = names.map((n, i) => {
    const raw = publicInputs[i]!;
    const numeric = n === "min_tier" || n === "now" || n === "disclosed_tag";
    return `${n} = ${numeric ? `"${bytes32ToBigInt(raw)}"` : q(raw)}`;
  });
  for (const [k, v] of Object.entries(privateInputs)) lines.push(`${k} = ${q(v)}`);
  return lines.join("\n") + "\n";
}
