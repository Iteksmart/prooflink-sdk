import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import prooflink


def receipt():
    return copy.deepcopy(json.loads((Path(__file__).parent / "real_receipts.json").read_text())[0]["receipt"])


def forged():
    data = receipt()
    data["outcome"] = "FORGED TEST OUTCOME"
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    canon = prooflink.canonicalize({k: v for k, v in data.items() if k not in prooflink.EXCLUDE})
    data.update(canonical_bytes=canon.hex(), hash_sha256=hashlib.sha256(canon).hexdigest())
    data["signature"] = {"algorithm": "Ed25519", "public_key": public, "value": key.sign(canon).hex(), "signs": "canonical_bytes"}
    return data, public


def test_cryptographically_valid_impostor_is_not_a_trusted_issuer():
    data, _ = forged()
    result = prooflink.verify_receipt(data)
    assert result["signature_valid"] is True
    assert result["signer_trusted"] is False and result["valid"] is False
    assert prooflink.verify(data) is False


def test_explicit_rotation_and_revocation():
    data, public = forged()
    assert prooflink.verify(data, trusted_public_keys=[public]) is True
    assert prooflink.verify(data, trusted_public_keys=[public], revoked_public_keys=[public]) is False
    assert prooflink.verify(receipt(), revoked_public_keys=[prooflink.PUBLIC_KEY_HEX]) is False
    assert prooflink.verify(receipt(), trusted_public_keys=[]) is False


@pytest.mark.parametrize("field,value", [("algorithm", "RSA"), ("signs", "hash_sha256"), ("signed_payload", "anything_else"), ("value", "aa" * 64 + "zz"), ("public_key", prooflink.PUBLIC_KEY_HEX + "zz")])
def test_invalid_signature_metadata_and_hex_fail_closed(field, value):
    data = receipt(); data["signature"][field] = value
    assert prooflink.verify(data) is False


@pytest.mark.parametrize("value", [None, [], "receipt", {"schema_version": "99.0"}])
def test_malformed_input_is_not_verification(value):
    assert prooflink.verify_receipt(value)["valid"] is False


def test_unsigned_diagnostic_flag_never_confers_issuer_trust():
    data = receipt(); data.pop("signature")
    assert prooflink.verify_receipt(data, require_signature=False)["valid"] is False


def test_bad_canonical_encoding_and_bad_key_policy_fail_closed():
    data = receipt(); data["canonical_bytes"] += "zz"
    assert prooflink.verify(data) is False
    assert prooflink.verify(receipt(), trusted_public_keys=["not-a-key"]) is False


def test_signature_verification_does_not_claim_bitcoin_confirmation():
    result = prooflink.verify_receipt(receipt())
    assert result["valid"] and result["signer_trusted"]
    assert result["bitcoin_verified"] is False


def test_cli_rejected_receipt_returns_failure(monkeypatch, capsys):
    from prooflink.__main__ import main
    data, _ = forged()
    monkeypatch.setattr(prooflink, "fetch", lambda identifier: data)
    assert main(["verify", "offline-fixture"]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False
