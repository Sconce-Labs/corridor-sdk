import type { CorridorConfig } from "./types.js";

/** Stellar testnet — the live deployment in corridor-contracts. */
export const TESTNET: CorridorConfig = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  registryContractId: "CB6LZV6TJN6YZ2O7FVLNRCJMRVBXCDG6JFFREHGY2BD5K4EYWJ6WKT2K",
  attestationContractId: "CCAGXABIZWHNLA754LSQCFPA35VLJZEH24MD5OGJNIEMFQHZ7LWQD5AR",
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
