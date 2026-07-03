# @itechsmart/prooflink

[![npm](https://img.shields.io/npm/v/%40itechsmart%2Fprooflink)](https://www.npmjs.com/package/@itechsmart/prooflink)
[![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![ledger](https://img.shields.io/badge/live_ledger-80%2C000%2B_receipts-22d3ee)](https://verify.itechsmart.dev)

**The TypeScript SDK for ProofLink — the Trust & Accountability Layer for Autonomous AI, by [iTechSmart Inc.](https://itechsmart.dev)**

Every autonomous AI action seals a cryptographic receipt — SHA-256 hash-chained, **Ed25519-signed**, Bitcoin-anchored via OpenTimestamps — into a public ledger. This SDK verifies those receipts and reads the live ledger, with **zero runtime dependencies** (Node 18+ built-in `crypto` + `fetch`).

> **Don't trust the AI. Trust the math.**

## Install

```bash
npm install @itechsmart/prooflink
```

## Verify a real receipt in 5 lines

```ts
import { fetchAndVerify } from "@itechsmart/prooflink";

const result = await fetchAndVerify("107453ec5eadf445");  // any id on the public chain
console.log(result.valid);   // true
console.log(result.checks);  // [{name:"payload_consistency"|"hash", passed}, {name:"ed25519_signature", passed}, ...]
```

Or from the command line, no install:

```bash
npx @itechsmart/prooflink 107453ec5eadf445
npx @itechsmart/prooflink --stats
```

## API

| Function | Purpose |
|---|---|
| `verify(receipt)` → `boolean` | One-liner: true iff all crypto checks pass |
| `verifyReceipt(receipt, prevHash?)` → `{valid, checks, errors}` | Full detail; schema-aware (v3 recomputes hash + canonical bytes; v2 binds via signature + signed-payload consistency) |
| `fetchReceipt(idOrHash)` → `Promise<Receipt>` | Pull a receipt from the public verifier |
| `fetchAndVerify(idOrHash)` → `Promise<{valid, checks, errors}>` | Fetch + verify in one call |
| `stats()` → `Promise<{total, chain_intact, ...}>` | Live ledger totals |
| `recent(limit?)` → `Promise<Receipt[]>` | Newest N receipts |
| `sealRemote(endpoint, payload)` → `Promise<Receipt>` | Thin remote-seal helper (sealing happens server-side; the private key never leaves the ledger host) |
| `canonicalize`, `importEd25519PublicKey`, `PUBLISHED_PUBLIC_KEY` | Primitives for advanced use |

## What gets verified

- **v3 receipts** (current): `SHA-256(canonical_bytes) === hash_sha256`, canonical re-derivation (field-tamper detection), and Ed25519 signature over the canonical bytes.
- **v2 receipts** (legacy, still on-chain): Ed25519 signature + signed-payload consistency (the v2 `hash_sha256` is a ledger-internal chain link, not recomputable from the public form — so it is not asserted).
- Optional chain-link check when you pass the previous entry's hash.

Receipts are additionally Bitcoin-anchored (OpenTimestamps), SCITT-compatible, and carry EU AI Act Article 12 clause mappings — see the [public verification spec](https://verify.itechsmart.dev/api/how-to-verify).

## Related

- Verifier-only package (identical crypto, no ledger convenience layer): [`@itechsmart/prooflink-verifier`](https://www.npmjs.com/package/@itechsmart/prooflink-verifier)
- Product: [prooflink.itechsmart.dev](https://prooflink.itechsmart.dev) · Live ledger: [verify.itechsmart.dev](https://verify.itechsmart.dev)
- For AI agents: the same verification is exposed over MCP at [mcp.itechsmart.dev](https://mcp.itechsmart.dev) (65 tools).

## License

MIT © iTechSmart Inc. — ProofLink™ is a registered federal trademark of iTechSmart Inc.
