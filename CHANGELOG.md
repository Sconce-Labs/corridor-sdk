# Changelog

## [Unreleased]

### Changed — audit Round 2 hardening
- **Issuance is now three steps and the issuer never sees `holderSecret`**
  (audit R2-H2). `prepareCredentialRequest(secret, salt, attrs)` (holder) →
  `issueCredential(issuerSk, request)` (issuer, sees only `holderBinding`) →
  `assembleCredential(secret, salt, statement)` (holder). New types
  `CredentialRequest` / `SignedStatement`.
- `statementMessage(holderBinding, tier, expiry, credEpoch)` — signature is now
  `(binding, …)`; `credentialStatement(cred)` is the holder-side convenience.
- `holderBinding()` returns `Bytes32` (was `bigint`).
- `buildWitness` calls `assertStrongSecret(cred.holderSecret)` (R2-L2).
- `DisclosureTag` — `Tier*Pass` values removed; tags are corridor category
  labels with no attestation (R2-H1, matches `corridor-circuits` `tags.nr`).
- `poseidon.ts` — `CONFORMANCE_VECTORS` (arities 1–5); `poseidon.test.ts` pins
  arity-4 (statement) and arity-5 (auditor blob) explicitly (R2-M6).
- `typecheck` now covers `src` + `examples` + `scripts` (`tsconfig.check.json`).

### Changed — Option B (issuer-signed statements)
- **Rebuilt for Option B**: `buildWitness` / `verifyWitnessLocally` now verify a
  Grumpkin Schnorr issuer signature + policy predicates instead of Merkle roots.
- `schnorr.ts` — Grumpkin Schnorr signer/verifier, pinned to `noir-lang/schnorr`
  v0.4.0's test vector; EdDSA-style deterministic nonces.
- `fixture.ts` — `issueCredential(issuerSk, attrs)` signs; `makeFixture` returns
  `issuerId`.
- `types.ts` — `PI_INDEX` is 9 inputs (`min_cred_epoch` replaces the two roots);
  `CorridorPolicy` gains `minCredEpoch`, drops the roots.
- `scripts/gen-circuit-fixture.ts` — prints a signed witness by default,
  `--write` updates the circuit's `fixture.nr` + `Prover.toml`.
- Removed `merkle.ts` and the old `gen-fixture.ts`.
- Added `@noble/curves` (Grumpkin point ops).

### Added (earlier)
- `Corridor` client: `getPolicy`, `isCleared`, `passes` (live Soroban reads),
  `buildWitness` (local), `requestProof` / `enter` (HTTP clients).
- `poseidon.ts` — Poseidon2 pinned to the circuit + Soroban by a shared vector.
- `hex.ts` — `Bytes32` encode/decode helpers.
- `TESTNET` config preset (pending the Option B redeploy — corridor ROADMAP M2).
- Prettier, typedoc, CI (typecheck + test + build), standard repo docs.
