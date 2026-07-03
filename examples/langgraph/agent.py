"""
ProofLink × LangGraph — seal a cryptographic receipt for every agent action.

The pattern: wrap each tool/node so that after it runs, a ProofLink receipt is
sealed recording WHAT the agent did, and the receipt id is threaded into state.
Downstream (or an auditor) can independently verify the full action trail — this
is EU AI Act Article 12 record-keeping applied to an agent graph.

Run:
    pip install prooflink langgraph
    python agent.py

Verification works against the public ledger with no account. Sealing requires a
ProofLink ledger host (or set PROOFLINK_SEAL_API); if absent, actions still run
and receipts are skipped gracefully.
"""
from __future__ import annotations

from typing import Annotated, TypedDict

import prooflink
from langgraph.graph import END, START, StateGraph


class AgentState(TypedDict):
    task: str
    result: str
    receipts: Annotated[list[str], lambda a, b: a + b]  # accumulate receipt ids


def sealed_action(category: str):
    """Decorator for a graph node: seal a receipt for its work, thread the id."""
    def deco(node_fn):
        def wrapped(state: AgentState) -> dict:
            out = node_fn(state)
            receipt_id = None
            try:
                r = prooflink.seal(
                    action=f"{node_fn.__name__}: {out.get('result','')[:80]}",
                    category=category, actor="langgraph-agent",
                    outcome="completed", details={"task": state.get("task")})
                receipt_id = r.get("id")
            except prooflink.ProofLinkError:
                pass
            return {**out, "receipts": [receipt_id] if receipt_id else []}
        return wrapped
    return deco


@sealed_action(category="diagnosis")
def diagnose(state: AgentState) -> dict:
    return {"result": f"diagnosed root cause for: {state['task']}"}


@sealed_action(category="platform_fix")
def remediate(state: AgentState) -> dict:
    return {"result": f"applied remediation for: {state['task']}"}


def build_graph():
    g = StateGraph(AgentState)
    g.add_node("diagnose", diagnose)
    g.add_node("remediate", remediate)
    g.add_edge(START, "diagnose")
    g.add_edge("diagnose", "remediate")
    g.add_edge("remediate", END)
    return g.compile()


if __name__ == "__main__":
    graph = build_graph()
    final = graph.invoke({"task": "high memory on web-01", "result": "", "receipts": []})
    print("result:", final["result"])
    print("receipts sealed:", final["receipts"])
    # Independently verify every receipt the agent produced:
    for rid in final["receipts"]:
        if rid:
            ok = prooflink.verify(prooflink.fetch(rid))
            print(f"  verify {rid}: {ok}")
