"""Fail-closed declaration/evidence-integrity preflight. Never executes changes.

This does not independently verify authorization, twins, signatures or Bitcoin.
Actual runtime verifiers and approval gates remain mandatory.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def evaluate(request, evidence_root, *, now=None, policy=None):
    policy = policy or json.loads((ROOT / "policy.json").read_text())
    now = now or datetime.now(timezone.utc)
    errors = []
    def require(condition, message):
        if not condition:
            errors.append(message)
    if not isinstance(request, dict):
        return {"preflight_passed": False, "execution_authorized": False, "errors": ["Request must be a JSON object"]}
    def section(name):
        value = request.get(name, {})
        return value if isinstance(value, dict) else {}
    require(request.get("policy_id") == policy["policy_id"] and request.get("policy_version") == policy["version"], "Policy ID/version mismatch")
    intent = section("intent")
    targets = intent.get("targets")
    valid_targets = isinstance(targets, list) and 0 < len(targets) <= 4096 and all(isinstance(t, str) and t.strip() for t in targets)
    require(valid_targets, "An explicit bounded target list is required")
    require(all(isinstance(intent.get(k), str) and intent[k].strip() for k in ("tenant", "actor", "action")), "Tenant, actor and action are required")
    require(request.get("kind") in ("read_only", "documentation", "mutation", "release"), "Unknown action kind")
    registry = section("evidence")
    require(len(registry) <= 64, "Evidence registry exceeds 64 artifacts")
    verified_refs = set()
    base = Path(evidence_root).resolve()
    for key, artifact in list(registry.items())[:64]:
        try:
            path = (base / artifact["path"]).resolve()
            if not path.is_relative_to(base) or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Evidence path must be a bounded file inside the bundle")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != artifact["sha256"]:
                raise ValueError("Evidence digest mismatch")
            verified_refs.add(key)
        except (OSError, KeyError, TypeError, ValueError) as exc:
            errors.append(f"Invalid evidence {key}: {exc}")
    def evidence(part, key="evidence_ref"):
        require(isinstance(part.get(key), str) and part.get(key) in verified_refs, f"Missing integrity-checked {key}")
    def fresh(part, label):
        try:
            expiry = datetime.fromisoformat(part["expires_at"].replace("Z", "+00:00"))
            require(expiry.tzinfo is not None and expiry > now, f"{label} is expired or timezone is missing")
        except (KeyError, TypeError, ValueError, AttributeError):
            errors.append(f"{label} needs a valid expiry")
    auth = section("authorization")
    require(auth.get("verified") is True and auth.get("scope_matches") is True, "Authorization/scope is not verified")
    evidence(auth); fresh(auth, "Authorization")
    detection = section("detection")
    require(detection.get("vantage_verified") is True and detection.get("unknowns_disclosed") is True, "Detection vantage/coverage evidence is incomplete")
    evidence(detection)
    if request.get("kind") in ("mutation", "release"):
        mode = request.get("execution_mode")
        require(mode in policy["execution_modes"], "Unknown execution mode")
        decision, twin, execution, proof = (section(k) for k in ("decision", "twin", "execution", "proof"))
        evidence(decision)
        confidence = decision.get("confidence")
        calibrated = type(confidence) in (int, float) and 0 <= confidence <= 1 and decision.get("confidence_calibrated") is True
        require(calibrated, "Calibrated confidence is required")
        require(twin.get("status") == "passed" and all(twin.get(k) is True for k in ("representative", "blast_radius_known", "rollback_validated")), "No safe path: Digital Twin/blast-radius/rollback gate failed")
        require(twin.get("action_digest") == digest(intent), "Simulation does not match the exact intended action")
        evidence(twin); fresh(twin, "Digital Twin")
        require(all(execution.get(k) is True for k in ("bounded", "cancellation_verified", "resource_reserve_verified", "quota_verified", "spend_authorized")), "Execution resource, quota or safety bounds are missing")
        evidence(execution)
        if mode in ("manual", "semi_automatic"):
            approval = section("human_approval")
            require(approval.get("verified") is True, "Required human approval is not verified")
            evidence(approval); fresh(approval, "Human approval")
        elif mode == "automatic":
            limits = policy["automatic_execution_limits"]
            minimum, maximum = limits.get("minimum_calibrated_confidence"), limits.get("maximum_blast_radius_assets")
            configured = type(minimum) in (int, float) and 0 <= minimum <= 1 and type(maximum) is int and maximum > 0
            require(configured, "Automatic envelope is unconfigured: escalate")
            require(auth.get("automatic_envelope_approved") is True, "Automatic scope is not preauthorized")
            if configured:
                require(calibrated and confidence >= minimum, "Confidence below approved automatic threshold")
                radius = twin.get("blast_radius_assets")
                require(type(radius) is int and 0 < radius <= maximum, "Blast radius exceeds approved automatic envelope")
        require(proof.get("state") in ("signed_local", "timestamp_pending", "bitcoin_anchored", "bitcoin_verified"), "Receipt is unsigned, invalid or revoked")
        require(proof.get("trusted_signature_verification") is True and bool(proof.get("trusted_key_id")), "Trusted signature-verifier evidence is missing")
        require(proof.get("action_digest") == digest(intent), "Receipt does not bind the intended action")
        evidence(proof)
        if request.get("kind") == "release" or proof.get("bitcoin_required_before_execution") is True:
            require(proof.get("state") == "bitcoin_verified", "Bitcoin verification is required; pending/anchored alone is insufficient")
            evidence(proof, "bitcoin_verifier_evidence_ref")
        if request.get("kind") == "release":
            status = json.loads((ROOT / "adoption-status.json").read_text())
            require(status.get("all_runtime_gates_enforced") is True, "Portfolio runtime adoption is incomplete; no UAIO-conformant release claim")
            controls = section("control_evidence")
            for control in policy["controls"]:
                require(controls.get(control) in verified_refs, f"Release evidence missing for {control}")
    return {"policy_id": policy["policy_id"], "policy_version": policy["version"], "preflight_passed": not errors,
            "execution_authorized": False, "disposition": "preflight_pass_requires_runtime_verifiers" if not errors else "escalate_without_mutation",
            "limitations": "Declaration and file-integrity checks only; not independent simulation, authorization, signature, Bitcoin or compliance verification.", "errors": errors}


def validate_policy():
    policy = json.loads((ROOT / "policy.json").read_text())
    adoption = json.loads((ROOT / "adoption-status.json").read_text())
    text = (ROOT / "UAIO_CONSTITUTION.md").read_text(encoding="utf-8")
    assert policy["policy_id"] == adoption["policy_id"] == "ITS-UAIO-001"
    assert len(policy["controls"]) == len(set(policy["controls"])) == 10
    assert set(policy["controls"]) == set(adoption["control_status"])
    assert all(control in text for control in policy["controls"])
    assert policy["preflight_is_certification"] is False
    return {"policy_consistent": True, "runtime_enforcement_complete": adoption["all_runtime_gates_enforced"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-policy", action="store_true")
    parser.add_argument("--request", type=Path)
    args = parser.parse_args()
    try:
        if args.validate_policy:
            result = validate_policy()
        elif args.request:
            result = evaluate(json.loads(args.request.read_text()), args.request.parent)
        else:
            parser.error("Provide --validate-policy or --request <bundle/request.json>")
        print(json.dumps(result, indent=2))
        return 0 if result.get("policy_consistent", result.get("preflight_passed", False)) else 1
    except (OSError, ValueError, AssertionError, KeyError, TypeError) as exc:
        print(json.dumps({"preflight_passed": False, "execution_authorized": False, "disposition": "escalate_without_mutation", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
