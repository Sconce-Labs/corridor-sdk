import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GrumpkinPoint,
  GRUMPKIN_P,
  SCHNORR_CHALLENGE_DST,
  randomIssuerKey,
  publicKey,
  sign,
  verify,
} from "./schnorr.js";
import { poseidon2 } from "./poseidon.js";
import { toBytes32 } from "./hex.js";

test("the DST matches the noir-lang/schnorr v0.4.0 derivation", () => {
  // poseidon2_hash_bytes("schnorr_grumpkin_poseidon2") — little-endian pack into
  // one 31-byte chunk, then Poseidon2 of the single field element.
  const src = Buffer.from("schnorr_grumpkin_poseidon2", "utf8");
  let packed = 0n;
  let mul = 1n;
  for (const b of src) {
    packed += BigInt(b) * mul;
    mul *= 256n;
  }
  assert.equal(poseidon2([packed]), SCHNORR_CHALLENGE_DST);
});

test("the Grumpkin generator is on the curve (y² = x³ − 17)", () => {
  const G = GrumpkinPoint.BASE.toAffine();
  const lhs = (G.y * G.y) % GRUMPKIN_P;
  const rhs = (((G.x * G.x * G.x - 17n) % GRUMPKIN_P) + GRUMPKIN_P) % GRUMPKIN_P;
  assert.equal(lhs, rhs);
  assert.equal(G.x, 1n);
});

test("verifies noir-lang/schnorr's pinned test vector (small)", () => {
  const ok = verify(
    {
      x: toBytes32(0x2c39bbbde2d0ffcb5c4317dcbfa1771cf554a2f33c647446632fa707a5bf5f3fn),
      y: toBytes32(0x2b9c81935298af5ebe22f1a7279bb76781e6cadba3fb6c5c41ed942392dc687cn),
    },
    {
      sLo: toBytes32(0x5fd1ac0ad411110674830c54cb506212n),
      sHi: toBytes32(0x281906862cdb4e0efec7226d757fe803n),
      eLo: toBytes32(0x6c368959f958e525d761d06c47fd2ad6n),
      eHi: toBytes32(0x013f6a902c6c0efafdadbd4de409690dn),
    },
    toBytes32(0x2bcn),
  );
  assert.equal(ok, true);
});

test("sign → verify round-trips", () => {
  const sk = randomIssuerKey();
  const pk = publicKey(sk);
  const msg = toBytes32(poseidon2([1n, 2n, 3n, 4n]));
  const sig = sign(sk, msg);
  assert.equal(verify(pk, sig, msg), true);
});

test("a tampered message fails", () => {
  const sk = randomIssuerKey();
  const pk = publicKey(sk);
  const sig = sign(sk, toBytes32(111n));
  assert.equal(verify(pk, sig, toBytes32(112n)), false);
});

test("another key's signature fails", () => {
  const msg = toBytes32(999n);
  const sig = sign(randomIssuerKey(), msg);
  assert.equal(verify(publicKey(randomIssuerKey()), sig, msg), false);
});
