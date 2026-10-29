# Governing iTechSmart engineering policy

Read `governance/UAIO_CONSTITUTION.md`, `governance/policy.json` and `governance/adoption-status.json` before work. ITS-UAIO-001 is mandatory internal engineering policy, effective 2026-10-28 by explicit user directive.

Follow Detect → Decide → Do → Prove. No safe path → escalation. Require a fresh representative Digital Twin, known blast radius, validated rollback, scoped authorization and the selected mode's approval before infrastructure or production mutations. Authorized read-only investigation, isolated preparation and documentation checks may proceed without repeated confirmation. Do not treat documentation checks as infrastructure simulation.

Preserve tenant boundaries, secret protection, resource/quota limits, evidence provenance and unknown states. Verify fixes independently; disappearing nodes and self-reports do not prove remediation. Distinguish signed local receipts, pending OpenTimestamps and independently verified Bitcoin anchoring. Trusted key verification is required.

Use relevant authorized tools through versioned MCP/A2A contracts; verify the claimed tool count. Sync Brains and model/policy promotion must follow privacy, evaluation, canary and rollback gates. Do not claim universal support, exclusivity, industry-standard status, certification or 10/10 readiness without evidence.

Run `python governance/policy_gate.py --validate-policy` and `python -m unittest discover -s governance/tests -v` for governance changes. A preflight pass is not execution permission or proof verification. Current runtime adoption is incomplete; consult the matrix before claiming otherwise. Do not silently waive gates. Keep unrelated user edits intact.
