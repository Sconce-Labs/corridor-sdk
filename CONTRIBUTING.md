# Contributing

`@corridor/verify` participates in the **Stellar Drips Wave** — see
[Sconce-Labs/corridor `DRIPS.md`](https://github.com/Sconce-Labs/corridor/blob/main/DRIPS.md).
Open issues are labelled `drips`.

## Setup

```bash
nvm use
npm install
npm test          # offline
npm run test:live # + against Stellar testnet
npm run typecheck
```

## Rules

- One issue per PR; `Closes #N`.
- `npm run typecheck`, `npm test`, `npm run format:check` must pass.
- **The public-input layout** (`src/types.ts` `PI_INDEX`) mirrors
  `corridor-contracts/ABI.md`. Changing it means matching PRs on
  `corridor-contracts` and `corridor-circuits`.
- **Poseidon2** must keep matching the pinned vector
  (`CONFORMANCE_VECTORS` in `src/poseidon.ts`); **Grumpkin Schnorr**
  (`src/schnorr.ts`) must keep matching `noir-lang/schnorr` v0.4.0's vector and
  the circuit (`npm run gen-fixture` + `nargo execute`).
- Conventional commits. Apache-2.0.

## Module map

| Module | Role |
|--------|------|
| `poseidon.ts` | the Poseidon2 hash + conformance vector |
| `schnorr.ts` | Grumpkin Schnorr signer/verifier (pinned to `noir-lang/schnorr`) |
| `hex.ts` | `Bytes32` helpers (`randomSecret`, `assertStrongSecret`) |
| `witness.ts` | `buildWitness` — assemble + locally verify circuit inputs |
| `verify-local.ts` | `verifyWitnessLocally` — mirrors `eligibility::check` |
| `fixture.ts` | `prepareCredentialRequest` / `issueCredential` / `assembleCredential` / `makeFixture` |
| `soroban.ts` | `SorobanReader` — `getPolicy` / `isCleared` / `passes` |
| `index.ts` | the `Corridor` class + re-exports |
