"""ProofLink Receipt Standard v1.0 — reference verification (Python).

Cryptographically verifies a ProofLink v3 receipt, reproducing the LIVE
verification at https://verify.itechsmart.dev/api/how-to-verify exactly:

  1. hash integrity      SHA256(canonical_bytes) == hash_sha256
  2. canonical re-derive  json.dumps(payload, sort_keys, separators=(",",":"),
                          ensure_ascii=False) == canonical_bytes  (field tamper)
  3. Ed25519 signature    sig over the RAW canonical_bytes with embedded pubkey
  4. chain link           prev_hash == previous ledger entry's hash_sha256

"Don't trust the AI. Trust the math."

Requires `cryptography` (same lib as the published reference verifier).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

# The three computed fields excluded from canonical_bytes (Standard v1 §4).
EXCLUDE = ("canonical_bytes", "signature", "hash_sha256")

# Published production signing key (cross-check /api/how-to-verify).
PUBLIC_KEY_HEX = "21102eaa68ea9ed42c05a2253aa953d33c59b5348ff8659018146e59fb061b97"

SCHEMA_V3 = "3.0"


def canonicalize(payload: Mapping[str, Any]) -> bytes:
    """Canonical bytes per Standard v1 §4: sorted keys, no whitespace, UTF-8,
    non-ASCII left literal (ensure_ascii=False)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class Check:
    __slots__ = ("name", "passed", "detail")

    def __init__(self, name: str, passed: bool, detail: str) -> None:
        self.name, self.passed, self.detail = name, passed, detail

    def as_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


def verify_receipt(receipt: Mapping[str, Any],
                   prev_hash: Optional[str] = None,
                   require_signature: bool = True) -> dict:
    """Verify a v3 ProofLink receipt. Returns a structured result dict:

        {"valid": bool, "id": str, "schema_version": str,
         "checks": [{name, passed, detail}, ...], "errors": [str, ...]}

    Never raises on a *failed* check — it records it. Raises only if the
    receipt is so malformed the checks cannot run (e.g. missing fields).
    Pass ``prev_hash`` (the previous/next-older ledger entry's hash_sha256)
    to also verify the chain link.
    """
    checks: list[Check] = []
    errors: list[str] = []

    schema = str(receipt.get("schema_version", ""))
    if schema != SCHEMA_V3:
        errors.append(
            f"schema_version is {schema!r}; Standard v1.0 normatively covers "
            f'"3.0" (v1/v2 are legacy, not recomputable)')
        return {"valid": False, "id": receipt.get("id", ""),
                "schema_version": schema,
                "checks": [c.as_dict() for c in checks], "errors": errors}

    # --- Check 1: hash integrity ---------------------------------------
    try:
        canon = bytes.fromhex(receipt["canonical_bytes"])
        got = hashlib.sha256(canon).hexdigest()
        ok = got == receipt.get("hash_sha256")
        checks.append(Check("hash_integrity", ok,
                            "SHA256(canonical_bytes) == hash_sha256" if ok
                            else f"hash mismatch: computed {got[:16]}… "
                                 f"stored {str(receipt.get('hash_sha256'))[:16]}…"))
    except Exception as e:
        checks.append(Check("hash_integrity", False, f"cannot decode canonical_bytes: {e}"))
        return {"valid": False, "id": receipt.get("id", ""), "schema_version": schema,
                "checks": [c.as_dict() for c in checks], "errors": errors}

    # --- Check 2: canonical re-derivation (field tamper) ---------------
    payload = {k: v for k, v in receipt.items() if k not in EXCLUDE}
    rederived = canonicalize(payload)
    ok2 = rederived == canon
    checks.append(Check("canonical_rederivation", ok2,
                        "re-derived canonical bytes match" if ok2
                        else "canonical re-derivation MISMATCH — a signed field was tampered"))

    # --- Check 3: Ed25519 signature ------------------------------------
    sig = receipt.get("signature")
    if not sig:
        checks.append(Check("ed25519_signature", not require_signature,
                            "receipt has no signature (unsigned)"))
    elif not _HAVE_CRYPTO:
        errors.append("cryptography not installed — cannot verify Ed25519 signature")
        checks.append(Check("ed25519_signature", False, "cryptography library unavailable"))
    else:
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"]))
            pub.verify(bytes.fromhex(sig["value"]), canon)
            checks.append(Check("ed25519_signature", True,
                                f"Ed25519 OK (key {sig['public_key'][:16]}…)"))
        except InvalidSignature:
            checks.append(Check("ed25519_signature", False, "Ed25519 signature INVALID"))
        except Exception as e:
            checks.append(Check("ed25519_signature", False, f"signature check error: {e}"))

    # --- Check 4: chain link (optional) --------------------------------
    if prev_hash is not None:
        ok4 = receipt.get("prev_hash") == prev_hash
        checks.append(Check("chain_link", ok4,
                            "prev_hash links to previous entry" if ok4
                            else f"chain BROKEN: prev_hash {str(receipt.get('prev_hash'))[:16]}… "
                                 f"!= expected {prev_hash[:16]}…"))

    valid = all(c.passed for c in checks) and not errors
    return {"valid": valid, "id": receipt.get("id", ""), "schema_version": schema,
            "checks": [c.as_dict() for c in checks], "errors": errors}


def verify(receipt: Mapping[str, Any], prev_hash: Optional[str] = None) -> bool:
    """Boolean convenience wrapper around :func:`verify_receipt`."""
    return verify_receipt(receipt, prev_hash=prev_hash)["valid"]
