import type { CorridorConfig } from "./types.js";

/**
 * Stellar testnet — the live Option B deployment in
 * corridor-contracts/deployments/testnet.json (redeployed 2026-09-10).
 */
export const TESTNET: CorridorConfig = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  registryContractId: "CAV6DMVCBOU5DGQVFSPU2UIF62LNFW7PWAGC7HCPHVIUO6SWRPSX3B65",
  attestationContractId: "CD76SRVQS6QSDFL2DYWGPK2JGWQPZO4NBFOGRDR5UWLGCABLBONNUXK5",
};

/** Placeholder — Corridor is not on Stellar mainnet yet. */
export const MAINNET: Omit<
  CorridorConfig,
  "registryContractId" | "attestationContractId"
> = {
  rpcUrl: "https://mainnet.sorobanrpc.com",
  networkPassphrase: "Public Global Stellar Network ; September 2015",
};

/** Build a config from `CORRIDOR_*` env vars, falling back to TESTNET. */
export function fromEnv(env: NodeJS.ProcessEnv = process.env): CorridorConfig {
  return {
    rpcUrl: env.CORRIDOR_RPC_URL ?? TESTNET.rpcUrl,
    networkPassphrase: env.CORRIDOR_NETWORK_PASSPHRASE ?? TESTNET.networkPassphrase,
    registryContractId: env.CORRIDOR_REGISTRY_ID ?? TESTNET.registryContractId,
    attestationContractId: env.CORRIDOR_ATTESTATION_ID ?? TESTNET.attestationContractId,
    relayerUrl: env.CORRIDOR_RELAYER_URL || undefined,
    proverUrl: env.CORRIDOR_PROVER_URL || undefined,
  };
}

/** Disclosure tag — a bounded enum index (`< 16`), not free text. */
export const DisclosureTag = {
  Generic: 0,
  Tier1Pass: 1,
  Tier2Pass: 2,
  Tier3Pass: 3,
  AidDisbursement: 4,
  Remittance: 5,
  LendingPool: 6,
} as const;
export type DisclosureTag = (typeof DisclosureTag)[keyof typeof DisclosureTag];
