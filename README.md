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
| `getPolicy(corridorId)` | ✅ live — the on-chain `CorridorPolicy` |
| `isCleared(corridorId, nullifier)` | ✅ live — the payout gate |
| `passes(corridorId)` / `passRecord(corridorId, nullifier)` | ✅ live — aggregate count / full record |
| `buildWitness(cred, policy, disclosure, {corridorId, now})` | ✅ local — the 9-field public vector + private witness; verifies the issuer signature and every predicate first |
| `verifyWitnessLocally(witness)` | ✅ local — re-runs every circuit constraint in TS before proving |
| `issueCredential(issuerSk, attrs)` / `makeFixture` | ✅ local — sign a credential statement (Grumpkin Schnorr) |
| `sign` / `verify` / `publicKey` / `randomIssuerKey` | ✅ local — the Grumpkin Schnorr primitives, pinned to `noir-lang/schnorr` v0.4.0 |
| `requestProof(witness)` | needs a local Noir prover (`proverUrl`) — M3 |
| `enter(corridorId, proof)` | needs a fee-sponsoring tx-relayer (`relayerUrl`) — M6 |

Config: `TESTNET` / `MAINNET` presets, `Corridor.fromEnv()`, or pass your own
`CorridorConfig`. Runnable examples in [`examples/`](./examples).

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

`TESTNET` points at
[`corridor-contracts/deployments/testnet.json`](https://github.com/Sconce-Labs/corridor-contracts/blob/main/deployments/testnet.json).
Those addresses ran the pre-Option-B ABI and are pending a redeploy (corridor
ROADMAP M2) — update the preset in `src/networks.ts` when that lands. Pass your
own `CorridorConfig` for a different network.

## Holder flow

```ts
import { Corridor, TESTNET } from "@corridor/verify";

const c = new Corridor({ ...TESTNET, proverUrl: "http://localhost:8787" });

const policy  = await c.getPolicy(corridorId);
const witness = c.buildWitness(credentialMaterial, policy, {
  disclosedTag: 1,                       // bounded enum index, < 16
  auditorPubkey: "0x00…00",              // must equal policy.auditorPubkey
  auditorNonce: randomBytes32(),
}, { corridorId, now: Math.floor(Date.now() / 1000) });

// witness.publicInputs  → 9 field elements, ordered by PI_INDEX
// witness.nullifier     → Poseidon2(holderSecret, corridorId), unlinkable per corridor
// witness.privateInputs → keyed exactly as the circuit's `main` params

const proof = await c.requestProof(witness);   // proving stays on proverUrl
await c.enter(corridorId, proof);              // via relayerUrl (M6)
```

`buildWitness` verifies the issuer's Grumpkin Schnorr signature and checks every
predicate (tier, expiry, the `min_cred_epoch` revocation floor, the auditor key)
— so an expired, bulk-revoked, or wrong-issuer credential fails locally before
any proof is generated.

### Issuing (issuer side)

```ts
import { issueCredential, randomIssuerKey } from "@corridor/verify";

const issuerSk = randomIssuerKey();                 // keep safe; rotate on compromise
const credential = issueCredential(issuerSk, {
  holderSecret,   // CSPRNG, from the holder; the issuer only hashes it
  tier: 3, expiry: nowSecs + 14 * 86400, credEpoch: 5, salt,
});
```

## Develop

```bash
npm install
npm run typecheck
npm test              # offline — 23 tests
npm run test:live     # + live reads against Stellar testnet
npm run build
npm run gen-fixture   # signs a witness (smoke); add -- --write to update the circuit
```

## Conformance

- **Poseidon2** — `buildWitness` uses `@zkpassport/poseidon2`;
  `poseidon2([1n,2n])` equals
  `0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383`, the
  value asserted in `corridor-circuits` and `corridor-contracts`.
- **Grumpkin Schnorr** — `src/schnorr.ts` is checked against `noir-lang/schnorr`
  v0.4.0's pinned test vector, and `gen-fixture` produces a witness that
  `nargo execute` solves in the circuit's CI — so the signer and the circuit's
  verifier provably agree.

## Contributing

Corridor participates in the **Stellar Drips Wave** — see the
[main repo](https://github.com/Sconce-Labs/corridor) `DRIPS.md`. If the
public-input layout changes in `corridor-contracts`, mirror it in `types.ts`.

## License

Apache-2.0
