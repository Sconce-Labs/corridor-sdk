# The auditor blob

Every pass carries an `auditor_blob` — one field element, public, stored in the
`PassRecord` on Stellar. It exists so a **warranted regulator** can learn the
`{tier, issuer}` behind a *specific* flagged pass, and nothing about anyone
else.

## Current form (MVP — a commitment)

```
auditor_blob = Poseidon2(auditor_pubkey, tier, issuer_id, nullifier, auditor_nonce)
```

`buildWitness` computes this and the circuit asserts it. Today it is a **hiding
commitment**: it binds the warrant-relevant fields to the nullifier, but the
auditor cannot yet *decrypt* it. `auditor_pubkey` is a **public input the
Stellar contract binds to `policy.auditor_pubkey`** — the holder cannot
substitute their own key. Pass `auditorPubkey: "0x00…00"` only when the policy
itself has no auditor (`buildWitness` throws on a mismatch).

## Target form (M7 — real encryption)

Replace the commitment with in-circuit **ECIES** to the policy's auditor key:

```
auditor_blob = ECIES_encrypt(auditor_pubkey, {tier, issuer_id}, auditor_nonce)
```

The auditor, given a warrant list of nullifiers, fetches the matching
`PassRecord`s and decrypts each. Key management is threshold (t-of-n regulators),
rotated per epoch. Tracked in
[corridor-circuits#3](https://github.com/Sconce-Labs/corridor-circuits/issues/3).

## Privacy properties (both forms)

- The blob reveals nothing to a chain observer.
- It is per-pass and bound to the nullifier, so it cannot be lifted onto a
  different pass.
- Only the holder of the auditor key (target form) can read it, and only for
  the specific records they look up.
