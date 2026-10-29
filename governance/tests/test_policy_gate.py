import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import digest, evaluate, validate_policy


class PolicyGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "evidence.txt").write_text("Synthetic test fixture; not an authorization or infrastructure simulation.")
        artifact = {"path": "evidence.txt", "sha256": hashlib.sha256((self.root / "evidence.txt").read_bytes()).hexdigest()}
        self.request = {"policy_id": "ITS-UAIO-001", "policy_version": "1.0.0", "kind": "mutation", "execution_mode": "manual",
            "intent": {"tenant": "fixture", "actor": "fixture-operator", "action": "fixture-only", "targets": ["fixture-node"]},
            "evidence": {"fixture": artifact}, "authorization": {"verified": True, "scope_matches": True, "evidence_ref": "fixture", "expires_at": "2030-01-01T00:00:00Z"},
            "detection": {"vantage_verified": True, "unknowns_disclosed": True, "evidence_ref": "fixture"},
            "decision": {"confidence": .99, "confidence_calibrated": True, "evidence_ref": "fixture"},
            "twin": {"status": "passed", "representative": True, "blast_radius_known": True, "rollback_validated": True, "expires_at": "2030-01-01T00:00:00Z", "evidence_ref": "fixture"},
            "execution": {k: True for k in ("bounded", "cancellation_verified", "resource_reserve_verified", "quota_verified", "spend_authorized")},
            "proof": {"state": "signed_local", "trusted_signature_verification": True, "trusted_key_id": "fixture-only-key", "evidence_ref": "fixture"},
            "human_approval": {"verified": True, "expires_at": "2030-01-01T00:00:00Z", "evidence_ref": "fixture"}}
        self.request["execution"]["evidence_ref"] = "fixture"
        self.request["twin"]["action_digest"] = self.request["proof"]["action_digest"] = digest(self.request["intent"])

    def run_gate(self, request=None):
        return evaluate(self.request if request is None else request, self.root, now=datetime(2026, 10, 28, tzinfo=timezone.utc))

    def test_consistent_policy_and_fixture_is_never_execution_authority(self):
        self.assertTrue(validate_policy()["policy_consistent"])
        result = self.run_gate()
        self.assertTrue(result["preflight_passed"])
        self.assertFalse(result["execution_authorized"])

    def test_incomplete_and_malformed_requests_fail_closed(self):
        for request in ({}, [], None, {"intent": []}):
            with self.subTest(request=request):
                # Explicit None uses the low-level evaluator rather than the fixture default.
                result = evaluate(request, self.root)
                self.assertFalse(result["preflight_passed"])
                self.assertFalse(result["execution_authorized"])

    def test_missing_twin_and_changed_action_require_escalation(self):
        for change in (lambda r: r.pop("twin"), lambda r: r["intent"].update(targets=["another-node"])):
            request = copy.deepcopy(self.request); change(request)
            self.assertEqual(self.run_gate(request)["disposition"], "escalate_without_mutation")

    def test_unconfigured_automatic_mode_cannot_pass(self):
        self.request["execution_mode"] = "automatic"
        self.request["authorization"]["automatic_envelope_approved"] = True
        self.assertFalse(self.run_gate()["preflight_passed"])

    def test_expired_approvals_and_unknown_confidence_fail(self):
        for section, field, value in [("human_approval", "expires_at", "2020-01-01T00:00:00Z"), ("decision", "confidence", True), ("twin", "blast_radius_known", False), ("execution", "quota_verified", False)]:
            request = copy.deepcopy(self.request); request[section][field] = value
            self.assertFalse(self.run_gate(request)["preflight_passed"])

    def test_tampered_and_external_evidence_rejected(self):
        (self.root / "evidence.txt").write_text("tampered")
        self.assertFalse(self.run_gate()["preflight_passed"])
        self.request["evidence"]["fixture"]["path"] = "../outside.txt"
        self.assertFalse(self.run_gate()["preflight_passed"])

    def test_pending_anchor_and_missing_trust_cannot_claim_verification(self):
        self.request["proof"].update(state="timestamp_pending", bitcoin_required_before_execution=True)
        self.assertFalse(self.run_gate()["preflight_passed"])
        self.request["proof"].update(state="signed_local", bitcoin_required_before_execution=False, trusted_signature_verification=False)
        self.assertFalse(self.run_gate()["preflight_passed"])

    def test_existing_portfolio_cannot_be_relabelled_conformant(self):
        self.request["kind"] = "release"
        self.request["proof"].update(state="bitcoin_verified", bitcoin_verifier_evidence_ref="fixture")
        self.request["control_evidence"] = {control: "fixture" for control in json.loads((Path(__file__).resolve().parents[1] / "policy.json").read_text())["controls"]}
        result = self.run_gate()
        self.assertFalse(result["preflight_passed"])
        self.assertTrue(any("adoption" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
