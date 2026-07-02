# ProofLink TypeScript SDK

Cryptographic verification of ProofLink **v3** audit receipts (EU AI Act Article 12).
Zero third-party dependencies — uses Node 18+ built-in `crypto`.

## Verify a receipt (quickstart, ≤5 lines)

```ts
import { verify, verifyReceipt } from "prooflink-sdk";

const ok = verify(receipt);              // boolean — true iff all crypto checks pass
const { valid, checks, errors } = verifyReceipt(receipt, prevHash); // structured detail
```

`verify` / `verifyReceipt` perform four checks (all must pass):

1. **hash** — `sha256(canonical_bytes) === hash_sha256`
2. **canonical_rederivation** — `canonicalize(payload)` byte-for-byte equals `canonical_bytes`
   (payload = receipt minus `canonical_bytes`, `signature`, `hash_sha256`; canonical JSON
   matches Python `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`)
3. **ed25519_signature** — `signature.value` verifies over the raw canonical bytes with `signature.public_key`
4. **chain_link** *(optional)* — `receipt.prev_hash === prevHash` when `prevHash` is supplied

`verifyReceipt` never throws on a failed check — inspect `valid` / `checks` / `errors`.
It throws only for wholly malformed input (non-object receipt).

Published v3 Ed25519 public key:
`21102eaa68ea9ed42c05a2253aa953d33c59b5348ff8659018146e59fb061b97` (exported as `PUBLISHED_PUBLIC_KEY`).

## Sealing

Sealing (creating) receipts is a **server-side** operation: the private Ed25519 key lives
on the ledger server (`append.py`) and never leaves it. This SDK does **not** sign locally.
`sealRemote(endpoint, payload)` is a thin HTTP POST to a ProofLink seal endpoint and performs
no local cryptography.

## Build & test

```bash
npm install     # typescript + @types/node (dev)
npm run build   # tsc -> dist/
npm test        # node test/verify.test.mjs — verifies live receipts + a tamper case
```
