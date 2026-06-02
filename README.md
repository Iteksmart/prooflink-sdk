# ProofLink SDK

> Cryptographic receipts for autonomous AI actions.

Every autonomous action gets a receipt. **SHA-256 hash-chained, Bitcoin-anchored, publicly verifiable** at [verify.itechsmart.dev](https://verify.itechsmart.dev).

[![Test](https://github.com/Iteksmart/prooflink-sdk/actions/workflows/test.yml/badge.svg)](https://github.com/Iteksmart/prooflink-sdk/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What it does

ProofLink turns "the agent did X" into a receipt you can prove later. Each receipt is:

- **Hash-chained** — every receipt links to the previous one's SHA-256
- **Bitcoin-anchored** — submitted to 4 OpenTimestamps calendars, settled in the next Bitcoin block
- **Publicly verifiable** — anyone can replay the chain at [verify.itechsmart.dev](https://verify.itechsmart.dev)
- **Tamper-evident** — modifying a past receipt breaks every receipt that follows

The SDK is a **thin wrapper**. The cryptography lives in `append.py` (the canonical seal logic) and the verify API. The SDK adds idiomatic language bindings — it does not reimplement.

## Two modes

| Mode | Available methods | Where it runs |
|---|---|---|
| **Server** (append.py present) | `seal`, `verify`, `chain_status`, `submit_to_ledger` | iTechSmart UAIO host or any host with `/opt/itechsmart/audit_ledger/append.py` |
| **Client** (verify API only) | `verify`, `chain_status` | Anywhere with HTTPS access to `verify.itechsmart.dev` |

`seal()` raises a clear error in client mode — read-only methods still work.

## Install

### Python

```bash
pip install prooflink
```

### Node

```bash
npm install @itechsmart/prooflink
```

## Quick start

### Python

```python
from prooflink import ProofLinkClient

client = ProofLinkClient()

# Seal a receipt (server mode only)
receipt = client.seal({
    'category': 'container_restart',
    'actor': 'system:supervisor',
    'subject': 'suite-nginx',
    'action': 'restarted after OOM kill',
    'outcome': 'service healthy 12s after restart',
    'details': {'pid': 12345, 'oom_score': 800},
})
print(receipt['hash'])  # 64-char SHA-256
print(f"https://verify.itechsmart.dev/{receipt['hash']}")

# Verify any receipt by hash (any mode)
entry = client.verify(receipt['hash'])

# Chain status (any mode)
status = client.chain_status()
# {'chain_intact': True, 'total': 15741, 'breaks': 0}
```

### Node

```javascript
const { ProofLinkClient } = require('@itechsmart/prooflink')
// or: import { ProofLinkClient } from '@itechsmart/prooflink'

const client = new ProofLinkClient()

const receipt = await client.seal({
  category: 'container_restart',
  actor: 'system:supervisor',
  subject: 'suite-nginx',
  action: 'restarted after OOM kill',
  outcome: 'service healthy 12s after restart',
  details: { pid: 12345, oomScore: 800 },
})
console.log(receipt.hash)
console.log(`https://verify.itechsmart.dev/${receipt.hash}`)

const status = await client.chainStatus()
// { chain_intact: true, total: 15741, breaks: 0 }
```

## Receipt schema

Every receipt has the same shape, regardless of language binding:

```json
{
  "id": "437f2bbd7fb221ac",
  "timestamp": "2026-06-02T22:14:08.231054+00:00",
  "category": "container_restart",
  "actor": "system:supervisor",
  "subject": "suite-nginx",
  "action": "restarted after OOM kill",
  "outcome": "service healthy 12s after restart",
  "details": { "pid": 12345, "oom_score": 800 },
  "hash_sha256": "437f2bbd7fb221ac7ce8ff917f84135e7607c5f5b1282354f4c4ac6e0ef8560b",
  "prev_hash": "<previous receipt's hash_sha256>",
  "tamper_detected": false,
  "human_input": false,
  "auto_resolved": true
}
```

`seal()` returns the short form `{ok, id, hash}`. Full receipts are returned by `verify()`.

## Configuration

| Param | Default | Purpose |
|---|---|---|
| `append_py` | `/opt/itechsmart/audit_ledger/append.py` | Path to the canonical seal CLI |
| `verify_url` | `https://verify.itechsmart.dev` | Base URL of the verify API |
| `python_bin` | `python3` | Python interpreter for the seal subprocess |
| `timeout` | 30s | Per-seal subprocess timeout |
| `no_ots` | `False` (per-call) | Skip Bitcoin anchoring (~70x faster seal; receipt still hashed and chained) |

## Status of the verify API

| Endpoint | Status |
|---|---|
| `GET /api/chain` | ✅ Live — returns `{chain_intact, total, breaks}` |
| `GET /api/receipts?hash=...` | ⚠ Currently returns HTML — JSON response in progress (sprint item H3) |
| `GET /api/stats` | ⚠ Same as above |

Until H3 lands, `verify(hash)` may return parsed HTML scaffolding rather than the receipt JSON. `chain_status()` is the production-stable read path.

## License

MIT — see [LICENSE](LICENSE).

## Author

iTechSmart Inc. — djuane@itechsmart.dev
