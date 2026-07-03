# ProofLink × FastAPI

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```

- `GET  /verify/{receipt_id}` — verify any receipt (public, no account)
- `GET  /ledger/stats` — live chain integrity
- `POST /remediate` — a mutating action; response carries the sealed `prooflink_receipt` id

`@accountable` seals a receipt for every wrapped action. Sealing needs a ProofLink
ledger host (or `PROOFLINK_SEAL_API`); without one, the action still runs and the
receipt is `null`. Verification always works.
