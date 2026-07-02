"""Offline crypto-verify tests for the ProofLink Python SDK.

Uses real live v3 receipts captured from https://verify.itechsmart.dev
(tests/real_receipts.json) plus deliberately tampered copies
(tests/tampered_receipt.json). Run:  python3 -m pytest tests/  (or run directly)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import prooflink  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    with open(os.path.join(HERE, name)) as f:
        return json.load(f)


def test_real_receipts_pass():
    cases = _load("real_receipts.json")
    assert len(cases) >= 3
    for case in cases:
        r = case["receipt"]
        res = prooflink.verify_receipt(r, prev_hash=case.get("prev_hash_expected"))
        assert res["valid"], (r["id"], res)
        assert all(c["passed"] for c in res["checks"])
        assert prooflink.verify(r, prev_hash=case.get("prev_hash_expected")) is True


def test_tampered_receipts_fail():
    cases = _load("tampered_receipt.json")
    for case in cases:
        r = case["receipt"]
        assert case.get("expect") == "FAIL"
        assert prooflink.verify(r) is False, r.get("_note")


def test_canonical_rederivation_matches_stored():
    for case in _load("real_receipts.json"):
        r = case["receipt"]
        payload = {k: v for k, v in r.items() if k not in prooflink.EXCLUDE}
        assert prooflink.canonicalize(payload).hex() == r["canonical_bytes"]


def test_public_key_is_published_key():
    for case in _load("real_receipts.json"):
        assert case["receipt"]["signature"]["public_key"] == prooflink.PUBLIC_KEY_HEX


if __name__ == "__main__":
    test_real_receipts_pass()
    test_tampered_receipts_fail()
    test_canonical_rederivation_matches_stored()
    test_public_key_is_published_key()
    print("all SDK verify tests passed")
