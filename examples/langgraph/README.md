# ProofLink × LangGraph

```bash
pip install -r requirements.txt
python agent.py
```

Every graph node is wrapped by `@sealed_action`, which seals a ProofLink receipt
for the node's work and threads the receipt id into graph state. After the run,
each receipt is independently verified — EU AI Act Article 12 record-keeping for
an agent graph. Sealing needs a ProofLink ledger (or `PROOFLINK_SEAL_API`);
verification is always public.
