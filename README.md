# ProofLink SDK

> **Every other AI-accountability standard is a PDF. ProofLink is a running ledger of
> 79,000+ cryptographically-sealed AI actions you can verify right now — not a spec, a
> live chain.** → **[verify.itechsmart.dev](https://verify.itechsmart.dev)**

Seal + verify [ProofLink Receipt Standard **v3.0**](https://github.com/Iteksmart/prooflink-standard/blob/main/ProofLink-Receipt-Standard-v3.md)
receipts from Python or TypeScript. Every autonomous action gets a receipt: **SHA-256
hash-chained, Ed25519-signed, Bitcoin-anchored, publicly verifiable.** *Don't trust the AI —
trust the math.*

[![Test](https://github.com/Iteksmart/prooflink-sdk/actions/workflows/test.yml/badge.svg)](https://github.com/Iteksmart/prooflink-sdk/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Not a spec — a running chain

Live snapshot (2026-07-02, from `/api/chain` + `/api/stats`): **79,000+ receipts**, chain
**intact (`chain_intact: true`, 0 breaks)**, **2,100+ strict cryptographically-verifiable v3
receipts** (and every new action is sealed as v3), **13,700+ Bitcoin-anchored** (~17%, growing
daily). Verify any of it yourself with the 5-line snippet below — no iTechSmart account, no
trust required.

**Honest two-era note.** v3 receipts (`schema_version "3.0"`) are strict and fully
cryptographically verifiable (hash + canonical re-derivation + Ed25519 + chain link). Legacy
v1/v2 receipts are pointer-linked and preserved unmodified — disclosed openly at `/api/stats`.
We do **not** claim all 79k are strict-verifiable; 2,100+ v3 are, and the count grows with
every action.

## Built for the regulations

| Regulation / framework | ProofLink field / mechanism that satisfies it |
|---|---|
| **EU AI Act (Reg. 2024/1689) Article 12** — automatic tamper-evident logging for high-risk AI | Append-only hash chain; every `seal()` records `timestamp`, `actor`, `action`, `subject`, `outcome`, `details` |
| **NIST AI RMF 1.0 — MEASURE 2.7 / MANAGE 4.1** — monitoring evaluated & documented | `security` / `platform_fix` / `platform_health_check` receipts, signed & immutable; `actor` distinguishes system vs. agent vs. operator |
| **CMMC L2 — AU.L2-3.3.1 / AU.L2-3.3.8** — retain & protect audit logs | SHA-256 chain + Ed25519 make any edit/deletion/reorder detectable; Bitcoin anchoring adds external existence proof |
| **SOC 2 — CC7.2 / CC7.3 / CC8.1** — anomaly monitoring & change management | `signal_classified` / `security` receipts; `config_change` records `{before_hash, after_hash, diff_summary}` |
| **ISO/IEC 42001:2023 — Clause 9.1** — retain documented monitoring evidence | The receipt ledger is the retained cryptographic evidence; `compliance_tags` seal the control claim inside the signature |

## Connect anything — every call seals a receipt

- **MCP server** — verify/search receipts from any MCP client (Claude, Cursor, Copilot,
  LangGraph, CrewAI): `prooflink_verify_receipt`, `prooflink_search_receipts`,
  `prooflink_verify_chain`.
- **FastAPI / REST** — `verify.itechsmart.dev` exposes `/api/export`, `/api/verify/<id>`,
  `/api/chain`, `/api/stats`, `/api/anchors`, `/api/how-to-verify`.
- **This SDK** — Python (`pip install prooflink  # NOT YET PUBLISHED to PyPI — build from this repo (see below)`) and TypeScript (`npm install
  @itechsmart/prooflink`) wrap seal + verify with idiomatic bindings.

Related: the [**ProofLink Receipt Standard**](https://github.com/Iteksmart/prooflink-standard)
(spec + conformance suite) and the zero-dependency
[**prooflink-verifier**](https://github.com/Iteksmart/prooflink-verifier). ProofLink aligns
conceptually with the IETF Internet-Draft
[`draft-sharif-agent-audit-trail-00`](https://datatracker.ietf.org/doc/html/draft-sharif-agent-audit-trail-00)
(same problem, shared hash-chain core) while differing deliberately on canonicalization
(`json.dumps`, not RFC 8785 JCS) and signature (Ed25519, not ECDSA P-256) — see §11 of the
standard.

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
npm install @itechsmart/prooflink-verifier   # published verifier (v2.x). The full @itechsmart/prooflink SDK is not yet on npm — build from this repo.
```

## Quick start

Conforms to the [ProofLink Receipt Standard v3.0](https://github.com/Iteksmart/prooflink-standard/blob/main/ProofLink-Receipt-Standard-v3.md).

### Python — verify a receipt (5 lines)

`verify()` reproduces the **live** verification exactly: SHA-256 hash recompute,
canonical re-derivation, Ed25519 signature, and (optionally) the `prev_hash`
chain link. It returns `True` only if all checks pass.

```python
import prooflink
receipt = prooflink.fetch("c58347c60394a21f")   # pull any receipt from the public API
assert prooflink.verify(receipt)                # cryptographically verify it — True
```

Want the per-check breakdown? Use `verify_receipt()`:

```python
result = prooflink.verify_receipt(receipt, prev_hash="<previous entry hash>")
# {'valid': True, 'id': 'c58347c60394a21f', 'schema_version': '3.0',
#  'checks': [{'name': 'hash_integrity', 'passed': True, ...}, ...], 'errors': []}
```

### Python — seal a receipt (server mode)

`seal()` shells out to the canonical `append.py` (only available on a host that
has `/opt/itechsmart/audit_ledger/append.py` + `SEAL_TOKEN`):

```python
import prooflink
r = prooflink.seal("restarted suite-nginx after OOM kill",
                   category="container_restart", actor="system:supervisor",
                   subject="suite-nginx", outcome="healthy 12s after restart")
print(r["id"], r["hash"])   # short form; verify with prooflink.fetch(r["id"])
```

### Node / TypeScript — verify a receipt (5 lines)

See [`typescript/`](typescript/) for the TS verifier. It reproduces the same
four checks using Node's built-in `crypto` (no runtime dependencies):

```typescript
import { verify } from "./src/index";
const res = await fetch("https://verify.itechsmart.dev/api/verify/c58347c60394a21f");
const { receipt } = await res.json();
console.assert(verify(receipt));   // true
```

> `verify()`/`verify_receipt()` require the `cryptography` package (the same
> library as the published reference verifier). `seal()`, `verify_chain()`,
> `recent()`, and `stats()` are stdlib-only.

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
