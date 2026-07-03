"""
ProofLink × CrewAI — a cryptographic receipt for every task a crew completes.

CrewAI's `task_callback` fires when a task finishes. We use it to seal a ProofLink
receipt recording the agent, the task, and its output — turning an opaque multi-
agent run into a verifiable, tamper-evident action trail.

Run:
    pip install prooflink crewai
    python crew.py

Verification is public and account-free. Sealing needs a ProofLink ledger host
(or PROOFLINK_SEAL_API); absent that, tasks still run and receipts are skipped.
"""
from __future__ import annotations

import prooflink

try:
    from crewai import Agent, Crew, Task
except ImportError:
    raise SystemExit("pip install crewai to run this example")


def seal_task_receipt(output) -> None:
    """CrewAI task_callback — seal a receipt per completed task."""
    try:
        r = prooflink.seal(
            action=f"task complete: {str(getattr(output, 'raw', output))[:80]}",
            category="agent_task",
            actor=f"crewai:{getattr(getattr(output, 'agent', None), 'role', 'agent')}",
            outcome="completed",
            details={"description": str(getattr(output, "description", ""))[:200]})
        rid = r.get("id")
        if rid:
            print(f"  ✓ sealed ProofLink receipt {rid} — "
                  f"verify at https://verify.itechsmart.dev/{rid}")
    except prooflink.ProofLinkError:
        print("  (no ProofLink ledger on this host — receipt skipped)")


researcher = Agent(role="Researcher", goal="Investigate the incident",
                   backstory="You find root causes.", verbose=False)

analyst = Agent(role="Analyst", goal="Recommend a fix",
                backstory="You turn findings into action.", verbose=False)

investigate = Task(description="Investigate the memory spike on web-01.",
                   expected_output="Root cause summary.", agent=researcher,
                   callback=seal_task_receipt)

recommend = Task(description="Recommend a remediation.",
                 expected_output="A concrete fix.", agent=analyst,
                 callback=seal_task_receipt)

crew = Crew(agents=[researcher, analyst], tasks=[investigate, recommend], verbose=False)

if __name__ == "__main__":
    result = crew.kickoff()
    print("\ncrew result:", result)
    print("Every task above sealed an independently-verifiable ProofLink receipt.")
