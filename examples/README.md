# ProofLink SDK — Framework Examples

Drop-in accountability for your stack. Each example uses a **published** SDK
([`prooflink`](https://pypi.org/project/prooflink/) on PyPI,
[`@itechsmart/prooflink`](https://www.npmjs.com/package/@itechsmart/prooflink) on npm)
and works against the **live public ledger** — no account required to verify.

| Example | Stack | Shows |
|---|---|---|
| [`fastapi/`](./fastapi) | FastAPI (Python) | Public verify endpoint + an `@accountable` decorator that seals a receipt for every mutating action |
| [`nextjs/`](./nextjs) | Next.js App Router (TS) | A `/api/verify/[id]` route + a server component rendering live ledger integrity |
| [`langgraph/`](./langgraph) | LangGraph (Python) | Seal a cryptographic receipt for every node/action in an agent graph, then verify the trail |
| [`crewai/`](./crewai) | CrewAI (Python) | A `task_callback` that seals a receipt per completed task |
| [`claude-desktop/`](./claude-desktop) | Claude Desktop (MCP) | Connect Claude to the iTechSmart MCP server (65 tools) to verify receipts and query the platform |

## The two operations

- **Verify** — `prooflink.verify(prooflink.fetch(id))` / `await fetchAndVerify(id)`.
  Runs against `https://verify.itechsmart.dev`, works from anywhere, no account.
- **Seal** — records a new action as a receipt. Sealing writes to a ProofLink
  ledger, so it runs on a ProofLink-enabled host (or point the SDK at a seal
  endpoint via `PROOFLINK_SEAL_API`). Where no ledger is reachable, the examples
  degrade gracefully: the action still runs, the receipt is skipped.

## Why

Regulators (EU AI Act Article 12), auditors, and customers increasingly ask one
question about autonomous software: **"prove it."** These examples wire that proof
into the frameworks you already use — so every AI action leaves a tamper-evident,
independently verifiable receipt.

> AI computes. ProofLink proves.

Product: https://prooflink.itechsmart.dev · Live ledger: https://verify.itechsmart.dev
