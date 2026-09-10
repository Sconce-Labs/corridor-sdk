import { test } from "node:test";
import assert from "node:assert/strict";
import {
  toBytes32,
  bytes32ToBigInt,
  bytes32ToBuffer,
  numberToWord,
  isBytes32,
  randomFieldElement,
  BN254_FR,
} from "./hex.js";

test("toBytes32 zero-pads and round-trips", () => {
  assert.equal(toBytes32(5n), "0x" + "0".repeat(63) + "5");
  assert.equal(bytes32ToBigInt(toBytes32(123456789n)), 123456789n);
  assert.equal(toBytes32(new Uint8Array([0xab, 0xcd])), "0x" + "0".repeat(60) + "abcd");
});

test("toBytes32 rejects an over-long value", () => {
  assert.throws(() => toBytes32("0x" + "f".repeat(65)), /32 bytes/);
});

test("bytes32ToBuffer is 32 bytes", () => {
  assert.equal(bytes32ToBuffer(toBytes32(1n)).length, 32);
});

test("numberToWord accepts number and bigint", () => {
  assert.equal(numberToWord(7), numberToWord(7n));
});

test("isBytes32", () => {
  assert.equal(isBytes32("0x" + "0".repeat(64)), true);
  assert.equal(isBytes32("0x04"), false);
  assert.equal(isBytes32("nope"), false);
});

test("randomFieldElement is in-range and non-repeating", () => {
  const a = randomFieldElement();
  const b = randomFieldElement();
  assert.notEqual(a, b);
  assert.ok(bytes32ToBigInt(a) < BN254_FR);
});
