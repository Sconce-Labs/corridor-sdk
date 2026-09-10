import { test } from "node:test";
import assert from "node:assert/strict";
import { poseidon2, CONFORMANCE_VECTOR, CONFORMANCE_VECTORS } from "./poseidon.js";
import { toBytes32 } from "./hex.js";

// Byte-identical to corridor-circuits/src/conformance.nr and
// corridor-contracts/crates/poseidon_conformance. The circuit uses arities
// 2 (nullifier / issuer_id / holder_binding), 4 (statement message) and
// 5 (auditor blob).
test("poseidon2 matches the pinned cross-impl vectors (arities 1–5)", () => {
  for (const [n, expected] of Object.entries(CONFORMANCE_VECTORS)) {
    const inputs = Array.from({ length: Number(n) }, (_, i) => BigInt(i + 1));
    assert.equal(toBytes32(poseidon2(inputs)), expected, `arity ${n}`);
  }
  assert.equal(CONFORMANCE_VECTORS[2], CONFORMANCE_VECTOR); // legacy alias
});

test("poseidon2 is deterministic and order-sensitive", () => {
  assert.equal(poseidon2([3n, 4n, 5n]), poseidon2([3n, 4n, 5n]));
  assert.notEqual(poseidon2([1n, 2n]), poseidon2([2n, 1n]));
  assert.notEqual(poseidon2([1n, 2n, 3n, 4n]), poseidon2([1n, 2n, 3n, 4n, 5n]));
});
