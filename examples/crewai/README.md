# ProofLink × CrewAI

```bash
pip install -r requirements.txt
python crew.py
```

Each task uses `callback=seal_task_receipt`, sealing a ProofLink receipt when the
task completes — recording the agent role, task, and output. An opaque multi-agent
run becomes a verifiable, tamper-evident action trail. Sealing needs a ProofLink
ledger (or `PROOFLINK_SEAL_API`); verification is public and account-free.
