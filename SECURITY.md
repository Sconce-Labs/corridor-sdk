# Security

## Reporting

Open a private security advisory on the repo, or email the maintainers. Do not
file a public issue for an exploitable vulnerability.

## What this SDK does and does not touch

- **`buildWitness` runs entirely locally.** `privateInputs` (the holder secret,
  attributes, Merkle paths) never leave the process. Callers must keep it that
  way: `requestProof` only POSTs to a `proverUrl` you control (a local process),
  never a third-party server.
- **Reads (`getPolicy` / `isCleared` / `passes`) are simulation-only** — no
  account, no signature. Point `rpcUrl` at an RPC you trust; a malicious RPC
  could lie about `isCleared`, so a corridor operator's payout contract should
  ultimately do this check on-chain, not just in the SDK.
- **`enter` goes through a relayer** so the holder's Stellar account is not
  linked to the pass. The relayer sees the proof + public inputs (all public)
  but not the witness.

## Never

- Send `EligibilityWitness.privateInputs` to a remote server.
- Reuse a holder secret across identities, or a nonce across auditor blobs.
- Trust `isCleared` from an untrusted `rpcUrl` as the sole payout gate.
