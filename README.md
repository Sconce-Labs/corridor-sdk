# corridor-sdk — `@corridor/verify`

[![CI](https://github.com/Sconce-Labs/corridor-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Sconce-Labs/corridor-sdk/actions/workflows/ci.yml)

Client SDK for **[Corridor](https://github.com/Sconce-Labs/corridor)** — a
portable proof of eligibility for cross-border payments. Read a corridor's
policy, build the zero-knowledge witness on the holder's device, present the
proof, and check whether a payout is cleared — all from TypeScript.

| Repo | |
|------|--|
| [corridor](https://github.com/Sconce-Labs/corridor) | product + architecture |
| [corridor-contracts](https://github.com/Sconce-Labs/corridor-contracts) | Soroban contracts + the `PI_*` ABI |
| [corridor-circuits](https://github.com/Sconce-Labs/corridor-circuits) | the Noir circuit |

## What works today

| API | Status |
|-----|--------|
| `getPolicy(corridorId)` | ✅ live — reads the on-chain `CorridorPolicy` from the deployed registry |
| `isCleared(corridorId, nullifier)` | ✅ live — the payout gate; reads the attestation contract |
| `passes(corridorId)` | ✅ live — aggregate pass count |
| `buildWitness(cred, policy, disclosure, {corridorId, now})` | ✅ local — assembles the 9-field public vector + private witness; Poseidon2 pinned to the circuit by a shared test vector |
| `requestProof(witness)` | needs a local Noir prover endpoint (`proverUrl`) — M3 |
| `enter(corridorId, proof)` | needs a fee-sponsoring relayer (`relayerUrl`) — M6 |

## Install

```bash
npm install @corridor/verify @stellar/stellar-sdk
```

## Payout gate (corridor operators)

```ts
import { isCleared, TESTNET } from "@corridor/verify";

// in your payout contract's off-chain guard, or a Soroban cross-contract call:
if (!(await isCleared(TESTNET, corridorId, nullifier))) {
  throw new Error("recipient not cleared for this corridor");
}
```

`TESTNET` points at the live deployment
([`corridor-contracts/deployments/testnet.json`](https://github.com/Sconce-Labs/corridor-contracts/blob/main/deployments/testnet.json)).
Pass your own `CorridorConfig` for a different network.

## Holder flow

```ts
import { Corridor, TESTNET } from "@corridor/verify";

const c = new Corridor({ ...TESTNET, proverUrl: "http://localhost:8787" });

const policy  = await c.getPolicy(corridorId);
const witness = c.buildWitness(credentialMaterial, policy, {
  disclosedTag: 1,                       // bounded enum index, < 16
  auditorPubkey: "0x00…00",              // "0x00…00" = no auditor
  auditorNonce: randomBytes32(),
}, { corridorId, now: Math.floor(Date.now() / 1000) });

// witness.publicInputs  → 9 field elements, ordered by PI_INDEX
// witness.nullifier     → Poseidon2(holderSecret, corridorId), unlinkable per corridor
// witness.privateInputs → keyed exactly as the circuit's `main` params

const proof = await c.requestProof(witness);   // proving stays on proverUrl
await c.enter(corridorId, proof);              // via relayerUrl (M6)
```

`buildWitness` re-derives the Merkle roots from the supplied paths and throws if
they don't match the policy — so a stale or revoked credential fails locally
before any proof is generated.

## Develop

```bash
npm install
npm run typecheck
npm test              # offline — 4 tests
npm run test:live     # + 3 tests against Stellar testnet
npm run build
```

## Poseidon2 conformance

`buildWitness` uses `@zkpassport/poseidon2`. `poseidon2([1n,2n])` equals
`0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383` — the same
value asserted in `corridor-circuits`. The Soroban leg of that conformance
(matching `poseidon2_permutation`) is tracked in
[`corridor-contracts/ABI.md`](https://github.com/Sconce-Labs/corridor-contracts/blob/main/ABI.md).

## Contributing

Corridor participates in the **Stellar Drips Wave** — see the
[main repo](https://github.com/Sconce-Labs/corridor) `DRIPS.md`. If the
public-input layout changes in `corridor-contracts`, mirror it in `types.ts`.

## License

Apache-2.0
