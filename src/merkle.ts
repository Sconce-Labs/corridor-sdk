/**
 * Sparse Merkle tree over `DEPTH` bits with an all-zero empty subtree.
 * Poseidon2 node hash — the same one the circuit and Soroban use.
 */

import { poseidon2 } from "./poseidon.js";

export const DEPTH = 32;

export interface MerkleProof {
  siblings: bigint[];
  /** direction bits, leaf → root; false = our node is the left child. */
  bits: boolean[];
}

/** Recompute a root from a leaf + co-path (mirrors the circuit's `merkle_root_from`). */
export function rootFromProof(leaf: bigint, proof: MerkleProof): bigint {
  let node = leaf;
  for (let i = 0; i < DEPTH; i++) {
    const sib = proof.siblings[i] ?? 0n;
    node = proof.bits[i] ? poseidon2([sib, node]) : poseidon2([node, sib]);
  }
  return node;
}

/** Low `n` bits of a field element, little-endian (matches Noir `to_le_bits`). */
export function leBits(x: bigint, n = DEPTH): boolean[] {
  const out: boolean[] = [];
  for (let i = 0; i < n; i++) out.push(((x >> BigInt(i)) & 1n) === 1n);
  return out;
}

export class SparseTree {
  private nodes = new Map<string, bigint>();
  private zero: bigint[] = [];

  constructor() {
    this.zero[0] = 0n;
    for (let i = 1; i <= DEPTH; i++) {
      this.zero[i] = poseidon2([this.zero[i - 1]!, this.zero[i - 1]!]);
    }
  }

  private get(level: number, index: bigint): bigint {
    return this.nodes.get(`${level}:${index}`) ?? this.zero[level]!;
  }

  insert(index: bigint, leaf: bigint): void {
    let idx = index;
    this.nodes.set(`0:${idx}`, leaf);
    for (let lvl = 0; lvl < DEPTH; lvl++) {
      const sib = idx ^ 1n;
      const [l, r] =
        idx % 2n === 0n
          ? [this.get(lvl, idx), this.get(lvl, sib)]
          : [this.get(lvl, sib), this.get(lvl, idx)];
      idx >>= 1n;
      this.nodes.set(`${lvl + 1}:${idx}`, poseidon2([l, r]));
    }
  }

  root(): bigint {
    return this.get(DEPTH, 0n);
  }

  proof(index: bigint): MerkleProof {
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

/** Low 248 bits of a field element — the order-comparable IMT key. */
export function imtKey(x: bigint): bigint {
  return x & ((1n << 248n) - 1n);
}

export interface ImtLeaf {
  value: bigint;
  nextIndex: bigint;
  nextValue: bigint;
}

export function imtLeafHash(l: ImtLeaf): bigint {
  return poseidon2([l.value, l.nextIndex, l.nextValue]);
}

export interface LowLeafProof {
  leaf: ImtLeaf;
  siblings: bigint[];
  bits: boolean[];
}

/**
 * Indexed Merkle tree — a sorted linked list of keys, over a `SparseTree`.
 * `insert` maintains the ordering; `lowLeafProof(key)` returns the predecessor
 * leaf for a non-membership proof (or the leaf `value == key` if the key is
 * present, which the circuit then rejects as "revoked").
 */
export class IndexedMerkleTree {
  private tree = new SparseTree();
  private leaves: ImtLeaf[] = [{ value: 0n, nextIndex: 0n, nextValue: 0n }];

  constructor() {
    this.tree.insert(0n, imtLeafHash(this.leaves[0]!));
  }

  root(): bigint {
    return this.tree.root();
  }

  has(key: bigint): boolean {
    const k = imtKey(key);
    return this.leaves.some((l) => l.value === k);
  }

  /** Insert a key (idempotent — inserting a present key is a no-op). */
  insert(key: bigint): void {
    const k = imtKey(key);
    if (this.has(k)) return;
    const lowIdx = this.lowLeafIndex(k);
    const low = this.leaves[lowIdx]!;
    const newIdx = BigInt(this.leaves.length);

    const inserted: ImtLeaf = {
      value: k,
      nextIndex: low.nextIndex,
      nextValue: low.nextValue,
    };
    const updatedLow: ImtLeaf = { ...low, nextIndex: newIdx, nextValue: k };

    this.leaves[lowIdx] = updatedLow;
    this.leaves.push(inserted);
    this.tree.insert(BigInt(lowIdx), imtLeafHash(updatedLow));
    this.tree.insert(newIdx, imtLeafHash(inserted));
  }

  private lowLeafIndex(k: bigint): number {
    let best = 0;
    for (let i = 0; i < this.leaves.length; i++) {
      const l = this.leaves[i]!;
      if (l.value < k && l.value >= this.leaves[best]!.value) best = i;
      if (l.value === k) return i; // present
    }
    return best;
  }

  /** Non-membership witness for `key`. */
  lowLeafProof(key: bigint): LowLeafProof {
    const k = imtKey(key);
    const idx = this.lowLeafIndex(k);
    const { siblings, bits } = this.tree.proof(BigInt(idx));
    return { leaf: this.leaves[idx]!, siblings, bits };
  }
}
