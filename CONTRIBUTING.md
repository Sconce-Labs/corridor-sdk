# Contributing to corridor-sdk

Thanks for helping build Corridor — a portable proof-of-eligibility for
cross-border payments (Stellar/Soroban + Noir/UltraHonk). Newcomers welcome:
look for issues labeled `good first issue`. The project overview lives in the
[hub repo](https://github.com/Sconce-Labs/corridor).

## Ground rules

- **One issue per PR.** Reference it with `Closes #NNN`.
- Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).
- Don't weaken a trust assumption without updating `ARCHITECTURE.md §6` in the
  hub repo.
- Apache-2.0; by contributing you agree your work is licensed under it.
- We follow the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Setup

```bash
nvm use
npm install
npm test          # offline
npm run test:live # + against Stellar testnet
npm run typecheck
```

## What you can work on

- TypeScript SDK: witness building, local verification, issuance flow,
  signing (`src/`), the fixture generators (`scripts/`), examples, docs.
- Test fixtures use deterministic keys — never commit real secrets.

## Gates (all must pass)

```bash
npm run typecheck
npm test
npm run format:check
npm run build
```

## Invariants

- **The public-input layout** (`src/types.ts` `PI_INDEX`) mirrors
  `corridor-contracts/ABI.md`. Changing it means matching PRs on
  `corridor-contracts` and `corridor-circuits`.
- **Poseidon2** must keep matching the pinned vector (`CONFORMANCE_VECTORS`
  in `src/poseidon.ts`); **Grumpkin Schnorr** must keep matching the circuit
  (`npm run gen-fixture` + `nargo execute`).

## Module map

| Module | Role |
|--------|------|
| `poseidon.ts` | the Poseidon2 hash + conformance vector |
| `schnorr.ts` | Grumpkin Schnorr signer/verifier (pinned to `noir-lang/schnorr` v0.4.0) |
| `hex.ts` | `Bytes32` helpers (`randomSecret`, `assertStrongSecret`) |
| `witness.ts` | `buildWitness` — assemble + locally verify circuit inputs |
| `verify-local.ts` | `verifyWitnessLocally` — mirrors `eligibility::check` |
| `fixture.ts` | `prepareCredentialRequest` / `issueCredential` / `assembleCredential` / `makeFixture` |
| `soroban.ts` | `SorobanReader` — `getPolicy` / `isCleared` / `passes` |
| `index.ts` | the `Corridor` class + re-exports |

## Review & merging

Maintainers aim to review within 48h during active contribution waves. Small
PRs get reviewed first — keep diffs reviewable. CI must be green before merge;
if CI fails for reasons outside your control, say so in the PR and we will
pick it up.
