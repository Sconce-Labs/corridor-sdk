import { test } from "node:test";
import assert from "node:assert/strict";
import { SparseTree, rootFromProof, leBits, DEPTH } from "./merkle.js";
import { poseidon2 } from "./poseidon.js";

test("an empty tree has a deterministic zero root", () => {
  assert.equal(new SparseTree().root(), new SparseTree().root());
});

test("proof(index) reproduces the root via rootFromProof", () => {
  const t = new SparseTree();
  t.insert(5n, 999n);
  t.insert(12n, 7n);
  const p = t.proof(5n);
  assert.equal(rootFromProof(999n, p), t.root());
  assert.equal(p.siblings.length, DEPTH);
});

test("a wrong leaf does not reproduce the root", () => {
  const t = new SparseTree();
  t.insert(3n, 42n);
  assert.notEqual(rootFromProof(43n, t.proof(3n)), t.root());
});

test("leBits little-endian", () => {
  assert.deepEqual(leBits(0b1101n, 4), [true, false, true, true]);
});

test("left child at level 0 pairs with the zero sibling", () => {
  const t = new SparseTree();
  t.insert(0n, 1n);
  const p = t.proof(0n);
  assert.equal(p.bits[0], false); // index 0 → left child
  assert.equal(p.siblings[0], 0n); // empty right sibling
  assert.equal(rootFromProof(1n, p), t.root());
});
