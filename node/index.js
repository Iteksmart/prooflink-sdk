// ProofLink Node SDK — thin wrapper around append.py (seal) + verify API (read).
// CommonJS entry point. ESM consumers import from ./index.mjs (same surface).
//
// Requires Node 18+ for global fetch. No third-party dependencies.

'use strict'

const { existsSync, accessSync, constants: fsConstants } = require('fs')
const { execFile } = require('child_process')
const { promisify } = require('util')

const execFileP = promisify(execFile)

const DEFAULT_APPEND_PY  = '/opt/itechsmart/audit_ledger/append.py'
const DEFAULT_VERIFY_URL = 'https://verify.itechsmart.dev'
const DEFAULT_PYTHON_BIN = 'python3'
const DEFAULT_TIMEOUT_MS = 30_000

const REQUIRED_FIELDS = ['category', 'actor', 'subject', 'action']

class ProofLinkError extends Error {
  constructor(message) {
    super(message)
    this.name = 'ProofLinkError'
  }
}

class ProofLinkClient {
  constructor(options = {}) {
    this.appendPy   = options.appendPy   || DEFAULT_APPEND_PY
    this.verifyUrl  = (options.verifyUrl || DEFAULT_VERIFY_URL).replace(/\/+$/, '')
    this.pythonBin  = options.pythonBin  || DEFAULT_PYTHON_BIN
    this.timeout    = options.timeout    || DEFAULT_TIMEOUT_MS

    this.localSealAvailable = false
    try {
      if (existsSync(this.appendPy)) {
        accessSync(this.appendPy, fsConstants.R_OK)
        this.localSealAvailable = true
      }
    } catch (_) {
      this.localSealAvailable = false
    }
  }

  // --- seal ---------------------------------------------------------------

  async seal(action, opts = {}) {
    if (!this.localSealAvailable) {
      throw new ProofLinkError(
        `Local seal not available — ${this.appendPy} not found. ` +
        'seal() requires the SDK to run on a host with append.py installed. ' +
        'verify() and chainStatus() work in client-only mode.'
      )
    }

    if (!action || typeof action !== 'object') {
      throw new ProofLinkError('action must be a non-null object')
    }
    const missing = REQUIRED_FIELDS.filter(k => !action[k])
    if (missing.length) {
      throw new ProofLinkError(`action is missing required fields: ${missing.join(', ')}`)
    }

    const args = [
      this.appendPy,
      '--category', String(action.category),
      '--actor',    String(action.actor),
      '--subject',  String(action.subject),
      '--action',   String(action.action),
    ]

    if (action.outcome) args.push('--outcome', String(action.outcome))

    if (action.details !== undefined && action.details !== null) {
      const details = typeof action.details === 'string'
        ? action.details
        : JSON.stringify(action.details)
      args.push('--details', details)
    }

    if (action.humanInput !== undefined) {
      args.push('--human-input', action.humanInput ? 'true' : 'false')
    }
    if (action.autoResolved !== undefined) {
      args.push('--auto-resolved', action.autoResolved ? 'true' : 'false')
    }
    if (action.verifyUrl) args.push('--verify-url', String(action.verifyUrl))
    if (action.hash) args.push('--hash', String(action.hash))
    if (opts.noOts || action.noOts) args.push('--no-ots')

    let stdout
    try {
      const result = await execFileP(this.pythonBin, args, {
        timeout: this.timeout,
        maxBuffer: 4 * 1024 * 1024,
      })
      stdout = result.stdout || ''
    } catch (e) {
      if (e.code === 'ENOENT') {
        throw new ProofLinkError(`python interpreter not found: ${this.pythonBin}`)
      }
      const msg = (e.stderr || e.message || String(e)).slice(0, 500)
      throw new ProofLinkError(`append.py exited ${e.code ?? '?'}: ${msg}`)
    }

    // append.py may print [OTS] lines before the final JSON.
    // The JSON line is always the LAST non-empty line on stdout.
    const lines = stdout.split('\n').map(l => l.trim()).filter(Boolean)
    if (lines.length === 0) {
      throw new ProofLinkError('append.py produced no output')
    }
    const last = lines[lines.length - 1]
    try {
      return JSON.parse(last)
    } catch (_) {
      throw new ProofLinkError(`append.py output not JSON: ${last.slice(0, 200)}`)
    }
  }

  async submitToLedger(payload, opts) {
    return this.seal(payload, opts)
  }

  // --- verify -------------------------------------------------------------

  async verify(hash) {
    if (typeof hash !== 'string' || hash.length < 16) {
      throw new ProofLinkError(`invalid hash: ${hash}`)
    }
    const url = `${this.verifyUrl}/api/receipts?hash=${encodeURIComponent(hash)}`
    let r
    try {
      r = await fetch(url, { signal: AbortSignal.timeout(this.timeout) })
    } catch (e) {
      throw new ProofLinkError(`verify request failed: ${e.message || e}`)
    }
    if (!r.ok) {
      throw new ProofLinkError(`verify returned HTTP ${r.status}`)
    }
    const ctype = r.headers.get('content-type') || ''
    if (!ctype.includes('application/json')) {
      throw new ProofLinkError(
        `verify returned non-JSON content-type "${ctype}". ` +
        'See README: /api/receipts JSON endpoint is in progress (H3).'
      )
    }
    return await r.json()
  }

  // --- chain_status -------------------------------------------------------

  async chainStatus() {
    const url = `${this.verifyUrl}/api/chain`
    let r
    try {
      r = await fetch(url, { signal: AbortSignal.timeout(this.timeout) })
    } catch (e) {
      throw new ProofLinkError(`chainStatus request failed: ${e.message || e}`)
    }
    if (!r.ok) {
      throw new ProofLinkError(`chainStatus returned HTTP ${r.status}`)
    }
    try {
      return await r.json()
    } catch (e) {
      throw new ProofLinkError(`chainStatus returned non-JSON: ${e.message}`)
    }
  }
}

module.exports = { ProofLinkClient, ProofLinkError }
