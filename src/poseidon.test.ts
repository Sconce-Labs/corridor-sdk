import { test } from "node:test";
import assert from "node:assert/strict";
import { poseidon2, CONFORMANCE_VECTOR } from "./poseidon.js";
import { toBytes32 } from "./hex.js";

test("poseidon2([1,2]) matches the pinned cross-impl vector", () => {
  assert.equal(toBytes32(poseidon2([1n, 2n])), CONFORMANCE_VECTOR);
});

test("poseidon2 is deterministic and order-sensitive", () => {
  assert.equal(poseidon2([3n, 4n, 5n]), poseidon2([3n, 4n, 5n]));
  assert.notEqual(poseidon2([1n, 2n]), poseidon2([2n, 1n]));
});
