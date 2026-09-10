# Changelog

## [Unreleased]

### Added
- `Corridor` client: `getPolicy`, `isCleared`, `passes` (live Soroban reads),
  `buildWitness` (local), `requestProof` / `enter` (HTTP clients).
- `poseidon.ts` — Poseidon2 pinned to the circuit + Soroban by a shared vector.
- `merkle.ts` — `SparseTree`, `rootFromProof`, `leBits`.
- `fixture.ts` — `makeFixture` / `toProverToml`; `scripts/gen-fixture.ts` writes
  a valid `Prover.toml` for `corridor-circuits`.
- `hex.ts` — `Bytes32` encode/decode helpers.
- `TESTNET` config preset for the deployed contracts.
- Prettier, typedoc, CI (typecheck + test + build), standard repo docs.
