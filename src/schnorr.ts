/**
 * Grumpkin Schnorr signatures with a Poseidon2 challenge — the exact scheme
 * `noir-lang/schnorr` v0.4.0 verifies in-circuit, and the scheme a Corridor
 * issuer uses to sign credential statements.
 *
 *   e   = Poseidon2(DST, R.x, A.x, A.y, message)          (a BN254 Fr element)
 *   R   = k·G                                              (Grumpkin point)
 *   s   = (k − e·d) mod q                                  (Grumpkin scalar)
 *   sig = (s, e)   verified as   s·G + e·A == R, e' == e
 *
 * Grumpkin: y² = x³ − 17 over Fp = BN254 Fr; scalar field q = BN254 Fq.
 */

import { weierstrassPoints } from "@noble/curves/abstract/weierstrass";
import { Field } from "@noble/curves/abstract/modular";
import { randomBytes } from "node:crypto";
import { poseidon2 } from "./poseidon.js";
import type { Bytes32 } from "./types.js";
import { toBytes32, bytes32ToBigInt } from "./hex.js";

/** BN254 Fr — Grumpkin's base field. */
export const GRUMPKIN_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** BN254 Fq — Grumpkin's scalar field. */
export const GRUMPKIN_Q =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/** `poseidon2_hash_bytes("schnorr_grumpkin_poseidon2")`, pinned to
 *  `noir-lang/schnorr` v0.4.0's `SCHNORR_CHALLENGE_DST`. */
export const SCHNORR_CHALLENGE_DST =
  0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832en;

const Fp = Field(GRUMPKIN_P);

// Barretenberg's Grumpkin generator (== Noir `EmbeddedCurvePoint::generator()`):
// x = 1, y = the root below of y² = 1³ − 17 = −16 (mod p).
const GX = 1n;
const GY = 0x02cf135e7506a45d632d270d45f1181294833fc48d823f272cn;
// (checked on-curve + against noir-lang/schnorr's pinned vector in schnorr.test.ts)

const { ProjectivePoint: GrumpkinPoint } = weierstrassPoints({
  a: 0n,
  b: Fp.create(-17n),
  Fp,
  n: GRUMPKIN_Q,
  h: 1n,
  Gx: GX,
  Gy: GY,
});

export { GrumpkinPoint };

const mod = (a: bigint, m: bigint): bigint => ((a % m) + m) % m;

export interface SchnorrPublicKey {
  x: Bytes32;
  y: Bytes32;
}

export interface SchnorrSignature {
  /** response scalar s, as (lo, hi) 128-bit limbs */
  sLo: Bytes32;
  sHi: Bytes32;
  /** challenge e (a Poseidon2 output), as (lo, hi) 128-bit limbs */
  eLo: Bytes32;
  eHi: Bytes32;
}

const HALF = 1n << 128n;
const splitLimbs = (v: bigint): [Bytes32, Bytes32] => [
  toBytes32(v % HALF),
  toBytes32(v / HALF),
];
const joinLimbs = (lo: Bytes32, hi: Bytes32): bigint =>
  bytes32ToBigInt(lo) + bytes32ToBigInt(hi) * HALF;

const randScalar = (): bigint =>
  BigInt(`0x${randomBytes(32).toString("hex")}`) % GRUMPKIN_Q;

/** Random private key scalar in [1, q). */
export function randomIssuerKey(): Bytes32 {
  let d = 0n;
  while (d === 0n) d = randScalar();
  return toBytes32(d);
}

export function publicKey(privateKey: Bytes32): SchnorrPublicKey {
  const P = GrumpkinPoint.BASE.multiply(bytes32ToBigInt(privateKey)).toAffine();
  return { x: toBytes32(P.x), y: toBytes32(P.y) };
}

/**
 * Sign a single-field message with the in-circuit scheme.
 *
 * The nonce is derived deterministically from (private key, message, counter)
 * — EdDSA-style — so a given key never reuses a nonce across messages (nonce
 * reuse leaks the key) and fixtures are byte-stable across regenerations.
 */
export function sign(privateKey: Bytes32, message: Bytes32): SchnorrSignature {
  const d = bytes32ToBigInt(privateKey);
  const A = GrumpkinPoint.BASE.multiply(d).toAffine();
  const m = bytes32ToBigInt(message);

  let s = 0n;
  let e = 0n;
  for (let counter = 0n; s === 0n || e === 0n; counter++) {
    const k = poseidon2([d, m, counter]) % GRUMPKIN_Q;
    if (k === 0n) continue;
    const R = GrumpkinPoint.BASE.multiply(k).toAffine();
    e = poseidon2([SCHNORR_CHALLENGE_DST, R.x, A.x, A.y, m]);
    s = mod(k - mod(e * d, GRUMPKIN_Q), GRUMPKIN_Q);
  }

  const [sLo, sHi] = splitLimbs(s);
  const [eLo, eHi] = splitLimbs(e);
  return { sLo, sHi, eLo, eHi };
}

/** Verify — mirrors `schnorr::verify_signature`. For SDK self-checks. */
export function verify(
  pk: SchnorrPublicKey,
  sig: SchnorrSignature,
  message: Bytes32,
): boolean {
  const ax = bytes32ToBigInt(pk.x);
  const ay = bytes32ToBigInt(pk.y);
  if (Fp.create(ay * ay) !== Fp.create(ax * ax * ax - 17n)) return false;
  const s = joinLimbs(sig.sLo, sig.sHi);
  const e = joinLimbs(sig.eLo, sig.eHi);
  if (s === 0n || e === 0n) return false;

  const A = GrumpkinPoint.fromAffine({ x: ax, y: ay });
  const R = GrumpkinPoint.BASE.multiply(s).add(A.multiply(e)).toAffine();
  const eComputed = poseidon2([
    SCHNORR_CHALLENGE_DST,
    R.x,
    ax,
    ay,
    bytes32ToBigInt(message),
  ]);
  return eComputed === e;
}
