"""ProofLink — cryptographic receipts for autonomous AI actions.

Each receipt is SHA-256 hash-chained, Bitcoin-anchored via OpenTimestamps,
and publicly verifiable at https://verify.itechsmart.dev.

Quick start:

    from prooflink import ProofLinkClient
    client = ProofLinkClient()
    receipt = client.seal({
        'category': 'container_restart',
        'actor':    'system:supervisor',
        'subject':  'suite-nginx',
        'action':   'restarted after OOM',
    })
    print(receipt['hash'])

`seal()` runs locally via /opt/itechsmart/audit_ledger/append.py and requires
the SDK to run on a host with append.py installed. `verify()` and
`chain_status()` are read-only and work from anywhere.
"""
from .client import ProofLinkClient, ProofLinkError

__all__ = ['ProofLinkClient', 'ProofLinkError']
__version__ = '0.1.0'
