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
  (`CONFORMANCE_VECTOR` in `src/poseidon.ts`) — don't swap the hash library
  without re-checking it against the circuit and Soroban.
- Conventional commits. Apache-2.0.

## Module map

| Module | Role |
|--------|------|
| `poseidon.ts` | the Poseidon2 hash + conformance vector |
| `merkle.ts` | `SparseTree`, `rootFromProof`, `leBits` |
| `hex.ts` | `Bytes32` encoding helpers |
| `witness.ts` | `buildWitness` — assemble circuit inputs |
| `fixture.ts` | `makeFixture` / `toProverToml` (tests + `gen-fixture`) |
| `soroban.ts` | `SorobanReader` — `getPolicy` / `isCleared` / `passes` |
| `index.ts` | the `Corridor` class + re-exports |
