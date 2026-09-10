/**
 * Types shared across the SDK. The public-input layout mirrors
 * `corridor-contracts/crates/corridor_types` (`PI_*`) and
 * `corridor-circuits/corridor_eligibility/src/main.nr`. A change there is a
 * coordinated change here — see `corridor-contracts/ABI.md`.
 */

/** A 32-byte value as a lowercase, `0x`-prefixed hex string. */
export type Bytes32 = `0x${string}`;

export const PI_INDEX = {
  credentialRoot: 0,
  revocationRoot: 1,
  corridorId: 2,
  minTier: 3,
  now: 4,
  nullifier: 5,
  disclosedTag: 6,
  issuerId: 7,
  auditorPubkey: 8,
  auditorBlob: 9,
} as const;

export const PI_LEN = 10;

export interface CorridorPolicy {
  operator: string;
  acceptedIssuers: Bytes32[];
  minTier: number;
  requiredDisclosures: number;
  credentialRoot: Bytes32;
  revocationRoot: Bytes32;
  rootEpoch: bigint;
  verifier: string;
  vkHash: Bytes32;
  /** Auditor key `auditor_blob` must bind to. `0x00…00` = no auditor. */
  auditorPubkey: Bytes32;
  nowToleranceSecs: bigint;
  paused: boolean;
}

/** Everything the holder's wallet holds for one credential. */
export interface CredentialMaterial {
  holderSecret: Bytes32;
  tier: number;
  expiry: number;
  issuerId: Bytes32;
  salt: Bytes32;
  /** Inclusion co-path under the issuer-set root, leaf → root. */
  credSiblings: Bytes32[];
  /** Left/right direction bits for the inclusion path (false = we are the left child). */
  credIndexBits: boolean[];
  /** Revocation non-membership: the indexed-Merkle-tree low leaf for this
   *  credential's revocation key, plus its inclusion path. */
  revLowValue: Bytes32;
  revLowNextIndex: Bytes32;
  revLowNextValue: Bytes32;
  revLowSiblings: Bytes32[];
  revLowIndexBits: boolean[];
}

export interface DisclosureRequest {
  /** Bounded enum index (< 16), not free text. */
  disclosedTag: number;
  /** Auditor public key the blob is bound to. `0x00…00` = no auditor. */
  auditorPubkey: Bytes32;
  /** Random nonce for the auditor blob (hex). Generate fresh per proof. */
  auditorNonce: Bytes32;
}

/** The assembled circuit inputs, ready for a Noir prover. */
export interface EligibilityWitness {
  /** length `PI_LEN`, ordered by `PI_INDEX`. */
  publicInputs: Bytes32[];
  /** Private witness map, keyed exactly as the circuit's `main` params. */
  privateInputs: Record<string, unknown>;
  /** Derived values a caller commonly needs. */
  commitment: Bytes32;
  nullifier: Bytes32;
  auditorBlob: Bytes32;
}

export interface CorridorConfig {
  rpcUrl: string;
  networkPassphrase: string;
  registryContractId: string;
  attestationContractId: string;
  /** Endpoint of a fee-sponsoring relayer that submits `enter` for holders. */
  relayerUrl?: string;
  /** Optional: a local prover endpoint the SDK POSTs the witness to. */
  proverUrl?: string;
}
// Network presets live in `networks.ts`.
