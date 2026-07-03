"""
ProofLink Python SDK — iTechSmart
Seal, verify, and count audit receipts via the ProofLink Public API.

Usage:
    from prooflink import ProofLink

    pl = ProofLink("http://localhost:8113")
    receipt = pl.seal(action="model-inference", service="aios-kernel", agent="claude")
    print(receipt.receipt_id)

    # As a decorator:
    @pl.decorator(service="my-service", agent="claude")
    def do_work():
        ...
"""
from __future__ import annotations
import requests
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional
from functools import wraps


@dataclass
class Receipt:
    receipt_id: str
    issued_at: str
    service: str
    agent: str
    action: str
    reason: str
    outcome: str
    authorized_by: str
    receipt_hash: str
    chain_hash: str
    verify_url: str
    eu_ai_act: dict = field(default_factory=dict)
    compliance: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"Receipt({self.receipt_id} | {self.action} | {self.verify_url})"


class ProofLinkError(Exception):
    pass


class ProofLink:
    def __init__(self, base_url: str = "http://localhost:8113", timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout

    def seal(
        self,
        action: str,
        service: str = "",
        agent: str = "autonomous",
        reason: str = "",
        outcome: str = "",
        authorized_by: str = "system",
        metadata: Optional[dict] = None,
    ) -> Receipt:
        payload = {
            "action":        action,
            "service":       service,
            "agent":         agent,
            "reason":        reason,
            "outcome":       outcome,
            "authorized_by": authorized_by,
            "metadata":      metadata or {},
        }
        try:
            resp = requests.post(f"{self.base_url}/receipt", json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            raise ProofLinkError(f"seal failed: {e}") from e
        data = resp.json()
        return Receipt(
            receipt_id=data["receipt_id"],
            issued_at=data["issued_at"],
            service=data.get("service", ""),
            agent=data.get("agent", ""),
            action=data.get("action", ""),
            reason=data.get("reason", ""),
            outcome=data.get("outcome", ""),
            authorized_by=data.get("authorized_by", ""),
            receipt_hash=data.get("receipt_hash", ""),
            chain_hash=data.get("chain_hash", ""),
            verify_url=data.get("verify_url", ""),
            eu_ai_act=data.get("eu_ai_act", {}),
            compliance=data.get("compliance", {}),
            metadata=data.get("metadata", {}),
        )

    def verify(self, receipt_id: str) -> dict:
        try:
            resp = requests.get(f"{self.base_url}/receipt/{receipt_id}", timeout=self.timeout)
            if resp.status_code == 404:
                return {"found": False, "receipt_id": receipt_id}
            resp.raise_for_status()
            data = resp.json()
            data["found"] = True
            return data
        except requests.RequestException as e:
            raise ProofLinkError(f"verify failed: {e}") from e

    def count(self) -> int:
        try:
            resp = requests.get(f"{self.base_url}/receipts/count", timeout=self.timeout)
            resp.raise_for_status()
            return resp.json().get("count", 0)
        except requests.RequestException as e:
            raise ProofLinkError(f"count failed: {e}") from e

    def verify_chain(self) -> dict:
        try:
            resp = requests.get(f"{self.base_url}/receipts/verify-chain", timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            raise ProofLinkError(f"verify_chain failed: {e}") from e

    def decorator(self, service: str = "", agent: str = "autonomous") -> Callable:
        def wrapper(fn: Callable) -> Callable:
            @wraps(fn)
            def inner(*args, **kwargs):
                result = fn(*args, **kwargs)
                try:
                    self.seal(
                        action=f"{fn.__module__}.{fn.__qualname__}",
                        service=service,
                        agent=agent,
                        outcome="completed",
                    )
                except ProofLinkError:
                    pass
                return result
            return inner
        return wrapper
