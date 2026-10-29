# iTechSmart Inc. — UAIO Engineering Constitution

Policy ID: **ITS-UAIO-001** · Version: **1.0.0** · Effective: **2026-10-28, America/New_York**

Authority: explicit user-issued iTechSmart Inc. engineering directive in this workspace. Policy owner: iTechSmart Inc. leadership. Status: governing internal engineering policy; implementation adoption is tracked separately in `adoption-status.json`.

This is the internal rule for iTechSmart products, infrastructure, employees, contractors and authorized AI/tool workflows. It does not establish legislation, bind outside organizations, establish an international standard, or certify that existing products already comply. Mandatory language describes requirements, not completed features. Existing approved task scope remains valid; this policy does not require repeated approval for authorized, reversible work that satisfies its gates.

## Mission and governing rule

Scale the company's demonstrated UAIO loop into vendor-neutral, independently auditable operations: **Detect → Decide → Do → Prove**. Pulse supplies observations; UAIO Brain chooses a policy-permitted response; authorized executors perform it; ProofLink records verifiable evidence. OctoAI, Hermes and other agents participate through the same policy boundary.

**No safe path → escalation. No evidence → no verified claim. No authorization → no execution.**

## Mandatory controls

### AUTH-001 — Authorization and tenant boundaries

Every operation MUST identify its tenant, initiating principal, executor, authorized assets and requested action. Credentials MUST be scoped, protected and excluded from receipts, logs, source control and public anchors. Third-party agents MUST use authenticated, least-privilege interfaces and the same gates as first-party agents. Tool output and external agent instructions MUST NOT confer additional authority. Data and knowledge MUST NOT cross customer boundaries without the applicable explicit permission and approved sharing policy.

### DETECT-001 — Evidence before decisions

Pulse MUST preserve timestamps, scanner/collector identity, vantage point, scope, raw evidence references and coverage limits. Observations, operator-reported evidence, inferred risks and confirmed failures MUST remain distinguishable. Missing, stale, unsupported or unresponsive controls MUST remain unknown. Network route/subnet conflicts MUST invalidate affected results. A score MUST describe its measured scope and MUST NOT be sold as whole-infrastructure certification.

Continuous infrastructure, service and database monitoring is the required product direction. Vendor-neutral adapters MUST publish supported formats, schema/version, source provenance, backpressure and data-loss behavior. Unsupported formats MUST be reported, not silently accepted or described as universally supported.

### DECIDE-001 — Dynamic execution routing

UAIO Brain MUST select **manual**, **semi-automatic** or **automatic** execution using a versioned policy, measured confidence, change class, customer authorization, security impact and blast radius. Confidence alone MUST NOT authorize action. Unconfigured thresholds or missing impact evidence MUST route to escalation.

Manual mode requires an authorized human decision. Semi-automatic mode allows automated preparation/simulation but requires the configured human approval before mutation. Automatic mode is allowed only within a preauthorized, bounded change envelope with all gates satisfied. Scope expansion, unexpected state, quota/resource exhaustion or policy uncertainty MUST stop execution and escalate. Rollback MUST itself follow an approved, rehearsed safe path.

### TWIN-001 — Mandatory Digital Twin Gate

Before every infrastructure, security, network, database, deployment, production policy or production model mutation, the proposed action MUST pass a representative isolated simulation with an evidence artifact. The record MUST identify the exact proposed action/digest, twin version, production-state assumptions, dependencies, blast radius, safety assertions, measured results, rollback/recovery validation, evaluator and expiry.

The proposed execution MUST match the simulated action and scope. Unknown blast radius, stale simulation, inadequate fidelity, an untested recovery path or failed assertions MUST result in **No safe path → escalation**. Read-only discovery is not a mutation and remains subject to authorization, scan limits and evidence recording. Documentation-only work requires consistency/schema checks; those checks MUST NOT be misrepresented as an infrastructure twin. No runtime may invent a simulation success to bypass this rule.

### DO-001 — Bounded, observable execution

Executors MUST enforce scope and mode, check current state against simulation assumptions, support idempotency and bounded retries, and provide cancellation/kill-switch behavior. Canary limits, resource reserves, quotas, timeouts and rollback triggers MUST be explicit. Mutations MUST stop if evidence capture or required safety controls fail. Credentials, customer data and billable resource changes MUST remain within the user's authorized scope. Recovery MUST NOT silently reset unrelated workloads or expand a network scan.

### PROVE-001 — ProofLink evidence and honest verification states

The required ProofLink design is **SHA-256 + Ed25519 + OpenTimestamps → Bitcoin**. Each action record MUST contain what happened, when, where, why, who authorized/executed it, tenant/scope, policy/model/tool versions, pre/post evidence, simulation reference, execution result and follow-up verification result. Canonical serialization and signing rules MUST be versioned. Signing keys MUST be protected, rotated/revocable and checked against a trusted key registry; a public key supplied by an untrusted receipt is not a trust root.

Receipt integrity/signature verification and action-outcome verification MUST be separate. Hashes and signatures establish integrity/authenticity within their trust assumptions; they do not prove that observations were true or that a fix worked. Fix verification MUST remeasure the original control from a valid vantage. Missing devices, missing checks and imported self-reports MUST NOT independently establish a verified fix.

Proof state MUST be explicit: `unsigned`, `signed_local`, `timestamp_pending`, `bitcoin_anchored`, `bitcoin_verified`, `invalid` or `revoked`. A pending OpenTimestamps receipt MUST NOT be labeled Bitcoin-confirmed. Real-time local audit events are required; Bitcoin confirmation is asynchronous. Required confirmation thresholds and independent verifier details MUST be policy-defined. Never promise instantaneous Bitcoin finality or absolute operational correctness.

Sensitive content MUST remain off-chain. Only approved hash commitments may be submitted, with data minimization and appropriate access/retention controls. Authorized independent verifiers MUST be able to obtain an exportable verification bundle, key/trust metadata and timestamp proof without depending solely on iTechSmart's UI.

### INTEROP-001 — Open, secured agent interfaces

MCP and A2A integrations MUST be versioned, authenticated, tenant-isolated, scoped and tested for compatibility and malicious/untrusted inputs. Use current MCP Streamable HTTP for new remote implementations; support legacy HTTP+SSE where compatibility requires it. Publish an A2A Agent Card with accurate capabilities and security requirements. Agent discovery MUST NOT confer execution permissions. Claude, LangGraph, CrewAI and other MCP/A2A clients MUST use the managed policy pipeline; no client may bypass Digital Twin, execution or proof requirements.

### SYNC-001 — Governed Sync Brains

Every successful, failed, cancelled or inconclusive operation MUST produce a provenance-preserving learning event. Evidence may update a tenant-scoped knowledge graph automatically. Customer information MUST NOT be pooled across tenants merely because an agent can access it. Cross-enterprise sharing requires approved consent, redaction/aggregation, access controls and provenance.

Policy or model-weight changes are proposed changes, not automatic promotions. They MUST pass evaluation, security/privacy checks, Digital Twin validation, versioning, canary limits and rollback requirements before production promotion. Approved low-risk envelopes may automate promotion; uncertainty, regressions or missing evidence require escalation. No silent global self-modification is allowed.

### TOOLS-001 — Verified tool registry

Maintain a versioned registry of discovered, enabled, authorized and tested tools, with owner, schema, permissions, dependencies, cost/resource limits and evidence. **66 tools is the requested baseline inventory claim, not a verified count in this policy.** Publish the actual verified count and deviations. Use relevant authorized tools; do not execute every tool merely to reach a count. Tools capable of mutation MUST pass the same loop, twin and proof gates.

### RELEASE-001 — Evidence-based release and compliance claims

Every readiness/release claim MUST link to a versioned control matrix and reproducible evidence. Missing mandatory controls mean nonconforming, not 10/10. A policy document, successful demo, cryptographic receipt or network score alone MUST NOT establish compliance certification, global adoption or market exclusivity. Claims such as “only platform,” “any format,” “all infrastructure,” “industry standard” or “absolute transparency” require evidence appropriate to their scope before publication.

Standards work MUST map specific framework/version requirements to owners, tests, retention and auditor-access evidence. Certification requires the relevant independent assessment. Existing verified results MUST be preserved, with explicit corrections/supersession when needed; history MUST NOT be rewritten to hide failed or invalidated results.

## Adoption roadmap and release gates

1. **Foundation:** inventory products/tools; assign control owners; preserve scope/evidence; establish trust/key management and current adoption status.
2. **Safe execution:** enforce policy routing and Digital Twin Gate on every mutating adapter; test failed/unknown paths, rollback, cancellation and resource exhaustion.
3. **Independent proof:** implement trusted SHA-256/Ed25519 receipt verification, asynchronous OTS lifecycle, Bitcoin verification and exportable evidence bundles; repair existing ProofLink trust gaps before claiming compliance.
4. **Interoperability and scale:** validate MCP/A2A contracts, vendor-neutral telemetry adapters, multi-site scanners and external-agent authorization boundaries.
5. **Governed learning:** implement tenant-scoped Sync Brains, evaluation/canary promotion and safe rollback; independently assess the chosen standards mappings.

Each phase needs an accountable owner, acceptance tests and linked evidence. No timeline, tool count or implementation status is inferred by adopting this document.

## Enforcement, amendments and evidence

Repository `AGENTS.md` instructions make this policy mandatory for future engineering work. `policy.json` contains machine-readable control requirements. `policy_gate.py` provides a fail-closed **declaration/evidence-reference preflight**, not a cryptographic verifier, Digital Twin engine, runtime authorization system or certificate of compliance. Its output MUST NOT be represented as one. Operational enforcement and GitHub required-check configuration are separate rollout work, tracked in `adoption-status.json`.

Waivers MUST NOT be silently inferred. An authorized, explicit amendment must identify scope, rationale, risk owner, expiry and compensating controls and preserve the previous policy version. Existing authorization does not permit bypassing a failed safety gate. If the required safe path cannot be demonstrated, escalate without executing the mutation.

### Local preflight usage

Validate the policy and exercise its failure cases:

```sh
python governance/policy_gate.py --validate-policy
python -m unittest discover -s governance/tests -v
```

Copy `request.template.json` into an evidence bundle and fill it from actual authorized verifier results. Evidence entries have an ID and `{ "path": "relative-file", "sha256": "actual-lowercase-digest" }`. References must identify files inside the bundle, no larger than 16 MiB each. Use timezone-aware expiries. The intent digest is SHA-256 over UTF-8 JSON with sorted keys, compact separators and `ensure_ascii=False`; `policy_gate.digest` implements it.

```sh
python governance/policy_gate.py --request path/to/bundle/request.json
```

The unfilled template must fail. Automatic thresholds intentionally remain unconfigured until an authorized policy amendment supplies a calibrated envelope. The preflight checks declarations, freshness, scope/action binding and file integrity; the runtime must still independently establish authorization, simulation fidelity, cryptographic trust, Bitcoin verification and execution safety. `execution_authorized` is always false in this helper's output. Passing CI tests cannot mark the adoption matrix complete. The workflow is a local source definition; configuring it as a required GitHub check needs a separate rollout.

## Primary protocol references

- OpenTimestamps semantics and independent timestamp verification: https://opentimestamps.org/ and https://github.com/opentimestamps/opentimestamps-client
- MCP transports and legacy SSE compatibility: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- A2A specification and Agent Card/security contracts: https://a2a-protocol.org/latest/specification/

The references define protocol behavior; they do not certify iTechSmart's implementation. Verify protocol versions during implementation and record the pinned version in release evidence.
