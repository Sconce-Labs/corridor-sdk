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

/**
 * Disclosure tag — a bounded **category label** for the corridor (`< 16`),
 * chosen by the app and published in the `PassRecord`.
 *
 * The circuit only range-checks it; it carries **no attestation** and is not
 * bound to the credential or the tier. Do not treat `PassRecord.tag` as a
 * verified attribute. (Audit R2-H1: `Tier*Pass` values were removed — nothing
 * bound them to the real tier.)
 */
export const DisclosureTag = {
  Generic: 0,
  Remittance: 1,
  AidDisbursement: 2,
  LendingPool: 3,
  MerchantSettlement: 4,
  Payroll: 5,
} as const;
export type DisclosureTag = (typeof DisclosureTag)[keyof typeof DisclosureTag];
