# ProofLink × Next.js (App Router)

```bash
npm i @itechsmart/prooflink
```

Copy into your Next.js app:
- `app/api/verify/[id]/route.ts` — `GET /api/verify/<receipt_id>` returns `{valid, checks}`
- `app/proof/page.tsx` — a server component rendering live ledger integrity at `/proof`

Both use the Node runtime (`node:crypto` for Ed25519) and fetch server-side against
the public ledger — no account, no client secrets.
