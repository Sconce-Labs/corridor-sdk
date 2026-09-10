# corridor-sdk — `@corridor/verify`

[![CI](https://github.com/Sconce-Labs/corridor-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Sconce-Labs/corridor-sdk/actions/workflows/ci.yml)

Client SDK for **Corridor** — a portable proof of eligibility for cross-border
payments. Build an eligibility witness, request a zero-knowledge proof, present
it to a Stellar corridor, and check whether a payout is cleared.

- Product + architecture: **[Sconce-Labs/corridor](https://github.com/Sconce-Labs/corridor)**
- Soroban contracts + ABI: **[Sconce-Labs/corridor-contracts](https://github.com/Sconce-Labs/corridor-contracts)**
- Noir circuit: **[Sconce-Labs/corridor-circuits](https://github.com/Sconce-Labs/corridor-circuits)**

> **Status: skeleton.** The types and the public-input layout are real and match
> `corridor-contracts`. The methods are signatures + TODOs — see the main repo
> `ROADMAP.md` (M6).

## Install

```bash
npm install @corridor/verify @stellar/stellar-sdk
```

## Shape

```ts
import { Corridor, isCleared } from "@corridor/verify";

const corridor = new Corridor({
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  registryContractId: "CB6LZV6TJN6YZ2O7FVLNRCJMRVBXCDG6JFFREHGY2BD5K4EYWJ6WKT2K",
  attestationContractId: "CCAGXABIZWHNLA754LSQCFPA35VLJZEH24MD5OGJNIEMFQHZ7LWQD5AR",
  relayerUrl: "https://relayer.example",       // fee-sponsored submit
});

// Holder
const policy  = await corridor.getPolicy(corridorId);
const witness = corridor.buildWitness(credentialMaterial, policy, disclosure, Date.now() / 1000);
const proof   = await corridor.requestProof(witness);   // proving stays local
await corridor.enter(corridorId, proof);                 // submitted via relayer

// Corridor operator — the payout gate
if (!(await isCleared(cfg, corridorId, nullifier))) throw new Error("not cleared");
```

## Develop

```bash
npm install
npm run typecheck
npm test
```

## Contributing

Corridor participates in the **Stellar Drips Wave**. See the
[main repo](https://github.com/Sconce-Labs/corridor) `DRIPS.md`. If the
public-input layout changes in `corridor-contracts`, mirror it here.

## License

Apache-2.0
