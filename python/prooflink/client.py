"""ProofLink client — thin wrapper around append.py (seal) + verify API (read)."""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Mapping

import requests

DEFAULT_APPEND_PY = '/opt/itechsmart/audit_ledger/append.py'
DEFAULT_VERIFY_URL = 'https://verify.itechsmart.dev'
DEFAULT_PYTHON_BIN = 'python3'
DEFAULT_TIMEOUT_S = 30

REQUIRED_FIELDS = ('category', 'actor', 'subject', 'action')


class ProofLinkError(Exception):
    """Raised for any SDK-level failure (subprocess, validation, network)."""


class ProofLinkClient:
    """Thin SDK around the canonical seal/verify surface.

    `seal()` shells out to append.py — runs locally on a UAIO host.
    `verify()` and `chain_status()` call the public verify API.
    """

    def __init__(
        self,
        append_py: str = DEFAULT_APPEND_PY,
        verify_url: str = DEFAULT_VERIFY_URL,
        python_bin: str = DEFAULT_PYTHON_BIN,
        timeout: int = DEFAULT_TIMEOUT_S,
    ) -> None:
        self.append_py = append_py
        self.verify_url = verify_url.rstrip('/')
        self.python_bin = python_bin
        self.timeout = timeout
        self.local_seal_available = os.path.isfile(append_py) and os.access(append_py, os.R_OK)

    def seal(self, action: Mapping[str, Any], no_ots: bool = False) -> dict:
        """Seal a receipt locally via append.py.

        Required keys in `action`: category, actor, subject, action.
        Optional: outcome, details (dict or str), human_input (bool),
        auto_resolved (bool), verify_url (str), hash (external override).

        Returns the short form: {'ok': True, 'id': '<16-char>', 'hash': '<64-char>'}.
        Use verify(hash) to fetch the full receipt.

        Pass no_ots=True to skip Bitcoin anchoring (~70x faster). Receipt is
        still hashed, chained, and persisted to ledger.json — only the
        OpenTimestamps submission is skipped.
        """
        if not self.local_seal_available:
            raise ProofLinkError(
                f'Local seal not available — {self.append_py} not found. '
                'seal() requires the SDK to run on a host with append.py installed. '
                'verify() and chain_status() work in client-only mode.'
            )

        missing = [k for k in REQUIRED_FIELDS if not action.get(k)]
        if missing:
            raise ProofLinkError(f'action is missing required fields: {missing}')

        args = [self.python_bin, self.append_py,
                '--category', str(action['category']),
                '--actor',    str(action['actor']),
                '--subject',  str(action['subject']),
                '--action',   str(action['action'])]

        if action.get('outcome'):
            args += ['--outcome', str(action['outcome'])]

        if 'details' in action and action['details'] is not None:
            details = action['details']
            if not isinstance(details, str):
                details = json.dumps(details, separators=(',', ':'))
            args += ['--details', details]

        if 'human_input' in action:
            args += ['--human-input', 'true' if action['human_input'] else 'false']

        if 'auto_resolved' in action:
            args += ['--auto-resolved', 'true' if action['auto_resolved'] else 'false']

        if action.get('verify_url'):
            args += ['--verify-url', str(action['verify_url'])]

        if action.get('hash'):
            args += ['--hash', str(action['hash'])]

        if no_ots:
            args += ['--no-ots']

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            raise ProofLinkError(f'append.py timed out after {self.timeout}s') from e
        except FileNotFoundError as e:
            raise ProofLinkError(f'python interpreter not found: {self.python_bin}') from e

        if result.returncode != 0:
            raise ProofLinkError(
                f'append.py exited {result.returncode}: '
                f'{(result.stderr or result.stdout or "").strip()[:500]}'
            )

        # append.py may print "[OTS] ..." lines before the final JSON.
        # The JSON is always the LAST non-empty line on stdout.
        lines = [ln for ln in (result.stdout or '').splitlines() if ln.strip()]
        if not lines:
            raise ProofLinkError('append.py produced no output')
        last = lines[-1].strip()
        try:
            return json.loads(last)
        except json.JSONDecodeError as e:
            raise ProofLinkError(f'append.py output not JSON: {last!r}') from e

    def submit_to_ledger(self, payload: Mapping[str, Any], no_ots: bool = False) -> dict:
        """Alias for seal(). Provided to mirror the spec's naming."""
        return self.seal(payload, no_ots=no_ots)

    def verify(self, hash: str) -> dict:
        """Look up a receipt by full 64-char SHA-256 hash via the verify API.

        Note: as of 2026-06-02, the /api/receipts JSON endpoint is incomplete
        (sprint item H3). Until that ships, this method may return HTML or
        raise ProofLinkError. chain_status() is the production-stable read path.
        """
        if not hash or len(hash) < 16:
            raise ProofLinkError(f'invalid hash: {hash!r}')

        url = f'{self.verify_url}/api/receipts'
        try:
            r = requests.get(url, params={'hash': hash}, timeout=self.timeout)
        except requests.RequestException as e:
            raise ProofLinkError(f'verify request failed: {e}') from e

        if not r.ok:
            raise ProofLinkError(f'verify returned HTTP {r.status_code}')

        ctype = r.headers.get('content-type', '')
        if 'application/json' not in ctype:
            raise ProofLinkError(
                f'verify returned non-JSON content-type {ctype!r}. '
                'See README: /api/receipts JSON endpoint is in progress (H3).'
            )
        return r.json()

    def chain_status(self) -> dict:
        """Get current ledger chain integrity status.

        Returns: {'chain_intact': bool, 'total': int, 'breaks': int}
        """
        url = f'{self.verify_url}/api/chain'
        try:
            r = requests.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            raise ProofLinkError(f'chain_status request failed: {e}') from e

        if not r.ok:
            raise ProofLinkError(f'chain_status returned HTTP {r.status_code}')

        try:
            return r.json()
        except json.JSONDecodeError as e:
            raise ProofLinkError(f'chain_status returned non-JSON: {r.text[:200]}') from e
