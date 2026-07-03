"""
ProofLink × FastAPI — the accountability layer for an autonomous API.

Two patterns:
  1. GET /verify/{receipt_id}   — public verification endpoint (works anywhere).
  2. @accountable decorator     — seal a ProofLink receipt for every mutating
                                  action, returning the receipt id in the response
                                  so callers can independently verify what happened.

Run:
    pip install prooflink fastapi uvicorn
    uvicorn app:app --reload
    curl http://127.0.0.1:8000/verify/c58347c60394a21f
    curl -X POST http://127.0.0.1:8000/remediate -d '{"host":"web-01"}'

Sealing writes to a ProofLink ledger. `prooflink.seal()` shells out to the
canonical append service (server-side). On any other host, point the SDK at a
ProofLink seal endpoint via  PROOFLINK_SEAL_API=https://your-ledger/seal
Verification always works against the public ledger, no account needed.
"""
from __future__ import annotations

import functools
from typing import Any, Callable

import prooflink
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="ProofLink-accountable API", version="1.0.0")


@app.get("/verify/{receipt_id}")
def verify(receipt_id: str) -> dict[str, Any]:
    """Publicly verify any ProofLink receipt by id or hash prefix."""
    try:
        receipt = prooflink.fetch(receipt_id)
    except prooflink.ProofLinkError as e:
        raise HTTPException(status_code=404, detail=str(e))
    result = prooflink.verify_receipt(receipt)
    return {"receipt_id": receipt_id, "valid": result["valid"],
            "checks": result["checks"], "verify_url": f"https://verify.itechsmart.dev/{receipt_id}"}


@app.get("/ledger/stats")
def stats() -> dict[str, Any]:
    """Live ledger integrity — proves the chain is intact."""
    return prooflink.stats()


def accountable(category: str = "api_action") -> Callable:
    """Decorator: seal a ProofLink receipt for the wrapped action and attach
    its id to the response, so every action this endpoint takes is provable."""
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            out = fn(*args, **kwargs)
            try:
                r = prooflink.seal(
                    action=f"{fn.__name__}({kwargs or args})",
                    category=category, actor="fastapi-app",
                    outcome="completed", details={"result": str(out)[:500]})
                receipt_id = r.get("id")
            except prooflink.ProofLinkError:
                # No ledger on this host — action still runs; receipt skipped.
                receipt_id = None
            return JSONResponse({"result": out, "prooflink_receipt": receipt_id,
                                 "verify_url": (f"https://verify.itechsmart.dev/{receipt_id}"
                                                if receipt_id else None)})
        return wrapper
    return deco


@app.post("/remediate")
@accountable(category="platform_fix")
def remediate(host: str = "unknown") -> str:
    """A mutating action — every call is sealed and independently verifiable."""
    # ... your real remediation logic here ...
    return f"restarted service on {host}"
