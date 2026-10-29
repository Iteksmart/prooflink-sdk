# ProofLink verification trust model

## Unreleased local remediation

The original receipt verifier validated the Ed25519 signature using whichever public key the receipt supplied. An attacker could alter a receipt, recompute its hash and canonical bytes, and sign it with an unrelated key. This established mathematical self-consistency, not iTechSmart issuer authenticity.

The corrected verifier checks both cryptographic validity and membership in a caller-configured trusted-key set, with revocation taking precedence. By default it pins the existing published iTechSmart key in source. An empty trusted-key list denies every signer. Receipt-controlled fields never extend trust. Confirm a trust root through an independently trusted provisioning process; do not copy a key from an untrusted receipt merely to make verification pass.

Python:

```python
result = prooflink.verify_receipt(receipt)  # default iTechSmart issuer pin
result = prooflink.verify_receipt(receipt, trusted_public_keys=approved_keys,
                                 revoked_public_keys=revoked_keys)
```

TypeScript SDK:

```typescript
verifyReceipt(receipt, undefined, {
  trustedPublicKeys: approvedKeys,
  revokedPublicKeys: revokedKeys,
});
```

The separate verifier package exposes the same options on `verifyReceiptV3`, `verifyV3` and `verifyChainV3`. Provision tenant/issuer-specific keys outside the receipt, review rotation, retain historical verification policy and distribute revocations. This local patch supplies the verifier interface; it does not implement a hosted key-management service or hardware-protected signing.

## Meaning of results

- `valid`: the implemented receipt checks, including configured signer trust, passed. Optional chain-link checking needs an independently supplied expected previous hash.
- `signature_valid`: the signature matches its key and message. This can be true for an untrusted key while `valid` remains false.
- `signer_trusted`: the key matches the configured allowlist and is not revoked.
- `bitcoin_verified`: false in this local receipt verifier. An independent OTS/Bitcoin verification pipeline is required for that claim.

Issuer authentication does not prove ledger inclusion, the truth of logged measurements, successful remediation or compliance. Receipt-provided timestamps and anchor labels are not independently verified Bitcoin evidence. Public summary pointer checks are weaker than per-receipt cryptographic verification.

## Compatibility and rollout

Previously accepted self-signed/custom-issuer receipts now fail unless their key is explicitly trusted by the caller. Python's unsigned diagnostic option cannot turn an unsigned receipt into a trusted result. Python CLI verification returns a failing exit status when the receipt fails verification. Strict key/signature/canonical-byte hex checks reject truncated or garbage-suffixed input. Unsupported schemas/algorithms and contradictory signed-payload metadata fail closed.

v3 canonicalization remains the existing protocol; v2 verification has weaker historical canonical/hash guarantees. Full cross-language numeric/Unicode canonicalization conformance, timestamp anchoring, trusted key lifecycle, ledger inclusion and downstream consumer adoption remain release-readiness work. Do not infer those controls from this patch.

Validate using saved production-key receipts, synthetic forged/re-signed receipts, explicit custom issuers, revocation, malformed encodings, unsupported metadata and command exit statuses. Tests use ephemeral fixture keys and do not modify the production ledger. Before deployment, inventory consumers, rehearse the exact package/integration change in an isolated representative environment, validate rollback/fail-closed behavior, and satisfy ITS-UAIO-001.
