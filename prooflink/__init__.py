"""ProofLink SDK — seal and verify cryptographically-chained, optionally
Bitcoin-anchored receipts for any action.

The moat, as a library. Any iTechSmart app (or a customer's) can:

    import prooflink
    r = prooflink.seal("deployed build abc123", category="deploy", actor="ci")
    print(r["id"], r["hash"])

    v = prooflink.verify(r["id"])          # is this receipt in the ledger?
    chain = prooflink.verify_chain()       # is the whole chain intact?

Zero third-party dependencies (stdlib only). seal() wraps the local append.py
(needs SEAL_TOKEN, read from /home/ubuntu/.secrets/prooflink.env by append.py);
verify()/verify_chain()/recent() hit the read-only verify-api.
"""
from __future__ import annotations

import json
import subprocess
import urllib.request
from typing import Any, Optional

# Reference cryptographic verification (ProofLink Receipt Standard v1.0).
from .crypto import (  # noqa: E402
    verify_receipt,
    verify,
    canonicalize,
    PUBLIC_KEY_HEX,
    EXCLUDE,
    SCHEMA_V3,
)

__version__ = "1.0.0"

APPEND_PY = "/opt/itechsmart/audit_ledger/append.py"
VERIFY_API = "http://127.0.0.1:8092"
PUBLIC_VERIFY_URL = "https://verify.itechsmart.dev"

__all__ = [
    "seal", "verify_id", "verify_chain", "recent", "stats",
    "verify_receipt", "verify", "canonicalize", "fetch",
    "PUBLIC_KEY_HEX", "EXCLUDE", "SCHEMA_V3", "ProofLinkError",
]


class ProofLinkError(Exception):
    pass


def _get(path: str, timeout: int = 10) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(f"{VERIFY_API}{path}", timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        raise ProofLinkError(f"verify-api request failed ({path}): {e}") from e


def seal(action: str, *, category: str = "platform_fix", actor: str = "prooflink-sdk",
         subject: str = "", outcome: str = "", details: Optional[dict] = None,
         human_input: bool = False, auto_resolved: bool = True,
         anchor: bool = False, timeout: int = 180) -> dict[str, Any]:
    """Seal a receipt into the ProofLink ledger. Returns {ok, id, hash, chain_id}.

    anchor=True submits to the Bitcoin OpenTimestamps calendars (slower);
    default False seals immediately (the chain is still cryptographically linked).
    """
    cmd = [
        "python3", APPEND_PY,
        "--category", category, "--actor", actor,
        "--subject", subject or action[:60], "--action", action,
        "--outcome", outcome, "--details", json.dumps(details or {}),
        "--human-input", "true" if human_input else "false",
        "--auto-resolved", "true" if auto_resolved else "false",
    ]
    if not anchor:
        cmd.append("--no-ots")
    try:
        pr = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        raise ProofLinkError(f"seal failed to run append.py: {e}") from e
    if pr.returncode != 0:
        raise ProofLinkError(f"seal failed rc={pr.returncode}: {(pr.stderr or pr.stdout)[:300]}")
    # append.py prints the JSON result as the last stdout line
    for line in reversed((pr.stdout or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise ProofLinkError("seal: could not parse append.py output")


def verify_id(receipt_id: str) -> dict[str, Any]:
    """Look up a receipt by id or hash prefix via the local verify-api.
    Returns {ok, receipt} or raises. For cryptographic verification of a
    receipt you already hold, use verify()/verify_receipt() from .crypto."""
    return _get(f"/api/v1/ledger/receipt/{receipt_id}")


def fetch(id_or_hash: str, base_url: str = PUBLIC_VERIFY_URL, timeout: int = 30) -> dict[str, Any]:
    """Fetch a single receipt from the PUBLIC verify API by id or hash prefix,
    so it can be handed straight to verify()/verify_receipt().

        r = prooflink.fetch("c58347c60394a21f")
        assert prooflink.verify(r)
    """
    url = f"{base_url.rstrip('/')}/api/verify/{id_or_hash}"
    req = urllib.request.Request(url, headers={"User-Agent": f"prooflink-sdk/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        raise ProofLinkError(f"fetch failed ({url}): {e}") from e
    # /api/verify/<id> returns the receipt (possibly under a 'receipt' key).
    return data.get("receipt", data) if isinstance(data, dict) else data


def verify_chain() -> dict[str, Any]:
    """Return live chain integrity: {chain_intact, chain_breaks, chain_links_verified, ...}."""
    return _get("/api/v1/ledger/verify")


def recent(limit: int = 25) -> list[dict[str, Any]]:
    return _get(f"/api/v1/ledger/recent?limit={int(limit)}").get("receipts", [])


def stats() -> dict[str, Any]:
    return _get("/api/v1/ledger/stats")
