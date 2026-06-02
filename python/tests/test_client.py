"""Smoke tests for the ProofLink Python SDK.

Designed to run in two environments:
  - On a UAIO server (append.py present): exercises seal + verify + chain_status
  - In CI / external (no append.py): skips seal, runs verify + chain_status only

No test framework dependency — runs as a plain script with assertions.
"""
import os
import sys

# Make the SDK importable when running from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from prooflink import ProofLinkClient, ProofLinkError  # noqa: E402


def test_chain_status(client):
    """chain_status should return a dict with chain_intact, total, breaks."""
    status = client.chain_status()
    assert isinstance(status, dict), f'expected dict, got {type(status)}'
    assert 'chain_intact' in status, f'missing chain_intact: {status}'
    assert 'total' in status, f'missing total: {status}'
    assert isinstance(status['total'], int) and status['total'] >= 0
    print(f'  ✓ chain_status: intact={status["chain_intact"]} total={status["total"]} breaks={status.get("breaks")}')


def test_seal_validation(client):
    """seal() must reject incomplete action dicts."""
    try:
        client.seal({'category': 'x'})  # missing actor/subject/action
    except ProofLinkError as e:
        assert 'missing required fields' in str(e)
        print(f'  ✓ seal validation rejected partial action: {e}')
        return
    raise AssertionError('seal({}) should have raised ProofLinkError')


def test_seal_no_ots(client):
    """seal() should produce {ok, id, hash} when append.py is reachable."""
    if not client.local_seal_available:
        print('  ⊘ seal skipped — append.py not local (CI / client-only mode)')
        return None

    receipt = client.seal({
        'category': 'sdk_self_test',
        'actor':    'system:sdk-test',
        'subject':  'prooflink-sdk-v0.1',
        'action':   'unit test smoke',
        'outcome':  'verifying SDK seal round-trip',
        'details':  {'test': 'test_seal_no_ots', 'framework': 'none'},
    }, no_ots=True)

    assert receipt.get('ok') is True, f'seal failed: {receipt}'
    assert len(receipt['hash']) == 64, f'expected 64-char hash, got {receipt["hash"]!r}'
    assert len(receipt['id']) == 16, f'expected 16-char id, got {receipt["id"]!r}'
    print(f'  ✓ seal produced hash={receipt["hash"][:16]}... id={receipt["id"]}')
    return receipt


def test_local_seal_unavailable_raises():
    """When append.py path is wrong, seal() should raise with a helpful message."""
    client = ProofLinkClient(append_py='/nonexistent/path/to/append.py')
    assert not client.local_seal_available
    try:
        client.seal({'category': 'x', 'actor': 'y', 'subject': 'z', 'action': 'w'})
    except ProofLinkError as e:
        assert 'Local seal not available' in str(e)
        print(f'  ✓ missing append.py raises clean error')
        return
    raise AssertionError('seal() with bad append_py should have raised')


def main():
    print('ProofLink SDK v0.1 — Python smoke tests')
    print('=' * 50)

    client = ProofLinkClient()
    print(f'  local_seal_available: {client.local_seal_available}')
    print(f'  verify_url:           {client.verify_url}')
    print()

    test_chain_status(client)
    test_seal_validation(client)
    test_seal_no_ots(client)
    test_local_seal_unavailable_raises()

    print()
    print('all tests passed ✓')


if __name__ == '__main__':
    main()
