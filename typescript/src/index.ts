/**
 * ProofLink TypeScript SDK — iTechSmart
 * Cryptographic verification of ProofLink v3 audit receipts.
 *
 * A ProofLink v3 receipt is a tamper-evident, Ed25519-signed, SHA256-hash-chained
 * record of an action. This SDK reproduces the canonical live verification exactly,
 * with zero third-party dependencies (Node 18+ built-in `crypto`).
 *
 * Quickstart (verify a receipt in <=5 lines):
 *   import { verify, fetchReceipt } from "@itechsmart/prooflink";
 *   const ok = verify(receipt);            // boolean, true if all crypto checks pass
 *   // or, for detail:
 *   import { verifyReceipt } from "@itechsmart/prooflink";
 *   const result = verifyReceipt(receipt); // { valid, checks[], errors[] }
 *
 * Sealing (creating) receipts happens SERVER-SIDE via append.py against the canonical
 * ledger; the private Ed25519 signing key never leaves the server. This SDK deliberately
 * does NOT sign locally. A thin remote-seal helper (`sealRemote`) is provided as an
 * explicit HTTP call to a ProofLink seal endpoint — it does not produce signatures itself.
 */

import { createHash, createPublicKey, verify as edVerify, KeyObject } from "node:crypto";

/** The Ed25519 signature block carried on every v3 receipt. */
export interface ReceiptSignature {
  /** Always "Ed25519" for v3. */
  algorithm: string;
  /** 32-byte Ed25519 public key, lowercase hex. */
  public_key: string;
  /** 64-byte Ed25519 signature over the canonical bytes, lowercase hex. */
  value: string;
  /** What the signature covers — "canonical_bytes" for v3. */
  signs: string;
}

/**
 * A ProofLink v3 receipt. Core fields are always present; receipts may also
 * carry arbitrary additive data fields (details, human_input, verify_url, ...),
 * captured by the index signature.
 */
export interface Receipt {
  id: string;
  timestamp: string;
  category: string;
  subject: string;
  action: string;
  actor: string;
  outcome: string;
  /** "3.0" for v3. */
  schema_version: string;
  /** SHA256 of the previous receipt's canonical bytes (hash chain link). */
  prev_hash: string;
  chain_position: number;
  /** Hex-encoded canonical JSON bytes that were hashed and signed. */
  canonical_bytes: string;
  /** Lowercase hex SHA256 of canonical_bytes. */
  hash_sha256: string;
  signature: ReceiptSignature;
  /** Optional compliance annotations. */
  compliance_tags?: string[];
  supersedes?: string;
  learned_from?: string[];
  /** Any additional additive fields present on the receipt. */
  [k: string]: unknown;
}

/** Result of a single verification check. */
export interface CheckResult {
  name: string;
  passed: boolean;
  detail: string;
}

/** Structured result of verifying a receipt. Never thrown — inspect `valid`. */
export interface VerificationResult {
  valid: boolean;
  checks: CheckResult[];
  errors: string[];
  signer_trusted?: boolean;
  signature_valid?: boolean;
  bitcoin_verified?: false;
  verification_scope?: string;
}

/** Trust configuration comes from the caller, never from the receipt. Empty lists deny all keys. */
export interface TrustOptions {
  trustedPublicKeys?: readonly string[];
  revokedPublicKeys?: readonly string[];
}

/**
 * The three fields that are COMPUTED from the payload and therefore excluded
 * when re-deriving the canonical bytes.
 */
const COMPUTED_FIELDS = ["canonical_bytes", "signature", "hash_sha256"] as const;

/**
 * Recursively produce canonical JSON bytes byte-for-byte identical to Python's:
 *   json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")
 *
 * Rules honored:
 *  - object keys sorted lexicographically (by UTF-16 code unit, matching CPython's
 *    default string ordering for the ASCII/BMP keys used by ProofLink),
 *  - no whitespace between tokens,
 *  - non-ASCII left as literal UTF-8 (NOT \uXXXX escaped),
 *  - control chars < 0x20 escaped as \b \t \n \f \r or \u00XX,
 *  - forward slash NOT escaped.
 * JS's native JSON.stringify already matches Python for primitive escaping and
 * leaves non-ASCII literal, so we delegate primitive serialization to it and only
 * override object key ordering and separators.
 */
export function canonicalize(payload: unknown): Buffer {
  return Buffer.from(canonicalString(payload), "utf-8");
}

function canonicalString(value: unknown): string {
  if (value === null || typeof value !== "object") {
    // Primitives: string, number, boolean, null, undefined.
    // JSON.stringify escapes strings exactly like Python's ensure_ascii=False
    // (literal non-ASCII, \uXXXX only for control chars, no slash escaping).
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalString(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const v = obj[key];
    if (v === undefined) continue; // Python has no `undefined`; skip to match dict semantics.
    parts.push(JSON.stringify(key) + ":" + canonicalString(v));
  }
  return "{" + parts.join(",") + "}";
}

/** Build the signable payload: the receipt minus the three computed fields. */
function payloadOf(receipt: Receipt): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(receipt)) {
    if ((COMPUTED_FIELDS as readonly string[]).includes(k)) continue;
    out[k] = v;
  }
  return out;
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Import a raw 32-byte Ed25519 public key (hex) as a Node KeyObject via SPKI DER. */
export function importEd25519PublicKey(publicKeyHex: string): KeyObject {
  if (typeof publicKeyHex !== "string" || !/^[0-9a-f]{64}$/i.test(publicKeyHex)) {
    throw new Error("Ed25519 public key must be exactly 32 hexadecimal bytes");
  }
  const raw = Buffer.from(publicKeyHex, "hex");
  if (raw.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  const der = Buffer.concat([SPKI_ED25519_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Verify a ProofLink v3 receipt. Performs 4 checks and NEVER throws on a failed
 * check — malformed structure is recorded in `errors` and reflected as failed checks.
 *
 *  1. HASH               — sha256(canonical_bytes) === hash_sha256
 *  2. CANONICAL RE-DERIVE — canonicalize(payload) === canonical_bytes
 *  3. ED25519 SIGNATURE   — signature.value verifies over canonical_bytes with signature.public_key
 *  4. CHAIN LINK          — (optional) receipt.prev_hash === prevHash
 *
 * @param receipt  the v3 receipt object
 * @param prevHash optional expected prev_hash for chain-link verification
 */
export function verifyReceipt(receipt: Receipt, prevHash?: string, options: TrustOptions = {}): VerificationResult {
  const checks: CheckResult[] = [];
  const errors: string[] = [];

  // Basic structural sanity (throwing only for wholly malformed input).
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) {
    return { valid: false, checks, errors: ["receipt must be an object"], bitcoin_verified: false };
  }

  let canon: Buffer | null = null;

  const schemaV3 = String(receipt.schema_version ?? "") === "3.0";
  if (!schemaV3 && receipt.schema_version !== "2.0") {
    return { valid: false, checks, errors: ["unsupported receipt schema"], bitcoin_verified: false };
  }
  let trusted: string[] = [];
  let revoked: string[] = [];
  try {
    const parseKeys = (keys: readonly string[]) => {
      if (!Array.isArray(keys) || keys.some(k => typeof k !== "string" || !/^[0-9a-f]{64}$/i.test(k))) throw new Error("invalid trusted/revoked key policy");
      return keys.map(k => k.toLowerCase());
    };
    trusted = parseKeys(options.trustedPublicKeys === undefined ? [PUBLISHED_PUBLIC_KEY] : options.trustedPublicKeys);
    revoked = parseKeys(options.revokedPublicKeys === undefined ? [] : options.revokedPublicKeys);
  } catch (error) {
    return { valid: false, checks, errors: [(error as Error).message], bitcoin_verified: false };
  }

  // --- Check 1: HASH (v3 only — v2 hash_sha256 is a ledger-internal link,
  //     computed pre-chain and not recomputable from the public form) ---
  try {
    if (typeof receipt.canonical_bytes !== "string" || !/^(?:[0-9a-f]{2})+$/i.test(receipt.canonical_bytes)) {
      throw new Error("missing/invalid canonical_bytes");
    }
    canon = Buffer.from(receipt.canonical_bytes, "hex");
    if (schemaV3) {
      const computed = sha256Hex(canon);
      const expected = String(receipt.hash_sha256 ?? "").toLowerCase();
      const passed = computed === expected;
      checks.push({
        name: "hash",
        passed,
        detail: passed
          ? `sha256(canonical_bytes) matches hash_sha256 (${computed.slice(0, 16)}...)`
          : `sha256(canonical_bytes)=${computed} != hash_sha256=${expected}`,
      });
      if (!passed) errors.push("hash mismatch");
    } else {
      // v2: bind via signature + signed-payload consistency instead.
      try {
        const signed = JSON.parse(canon.toString("utf-8")) as Record<string, unknown>;
        const core = ["category", "actor", "subject", "action", "outcome", "timestamp"];
        const mism = core.filter(
          (k) => k in signed && (receipt as Record<string, unknown>)[k] !== undefined &&
                 signed[k] !== (receipt as Record<string, unknown>)[k]);
        const passed = mism.length === 0;
        checks.push({
          name: "payload_consistency",
          passed,
          detail: passed
            ? "displayed core fields match the signed canonical payload"
            : `signed-payload mismatch on: ${mism.join(", ")}`,
        });
        if (!passed) errors.push("signed-payload mismatch");
      } catch (e) {
        checks.push({ name: "payload_consistency", passed: false, detail: `error: ${(e as Error).message}` });
        errors.push(`payload_consistency: ${(e as Error).message}`);
      }
    }
  } catch (e) {
    checks.push({ name: "hash", passed: false, detail: `error: ${(e as Error).message}` });
    errors.push(`hash: ${(e as Error).message}`);
  }

  // --- Check 2: CANONICAL RE-DERIVATION (v3 normative only) ---
  if (schemaV3) {
    try {
      const rederived = canonicalize(payloadOf(receipt));
      const rederivedHex = rederived.toString("hex");
      const expectedHex = String(receipt.canonical_bytes ?? "");
      const passed = rederivedHex === expectedHex;
      checks.push({
        name: "canonical_rederivation",
        passed,
        detail: passed
          ? `re-derived canonical bytes equal receipt.canonical_bytes (${rederived.length} bytes)`
          : `re-derived bytes differ (got ${rederived.length}B, expected ${expectedHex.length / 2}B)`,
      });
      if (!passed) errors.push("canonical re-derivation mismatch");
    } catch (e) {
      checks.push({ name: "canonical_rederivation", passed: false, detail: `error: ${(e as Error).message}` });
      errors.push(`canonical_rederivation: ${(e as Error).message}`);
    }
  }

  // --- Check 3: ED25519 SIGNATURE ---
  const signer = typeof receipt.signature?.public_key === "string" ? receipt.signature.public_key.toLowerCase() : "";
  const signerTrusted = /^[0-9a-f]{64}$/.test(signer) && trusted.includes(signer) && !revoked.includes(signer);
  checks.push({ name: "signer_trust", passed: signerTrusted, detail: signerTrusted ? "signer matches a configured trusted, non-revoked key" : "signer is missing, malformed, untrusted or revoked" });
  if (!signerTrusted) errors.push("untrusted or revoked signing key");
  try {
    const sig = receipt.signature;
    if (!sig || typeof sig !== "object") throw new Error("missing signature block");
    if (sig.algorithm !== "Ed25519") {
      throw new Error(`unsupported signature algorithm: ${sig.algorithm}`);
    }
    const metadata = sig as unknown as Record<string, unknown>;
    for (const field of ["signs", "signed_payload"]) {
      if (field in metadata && metadata[field] !== "canonical_bytes") throw new Error("signature must cover canonical_bytes");
    }
    if (typeof sig.value !== "string" || !/^[0-9a-f]{128}$/i.test(sig.value)) throw new Error("invalid signature encoding");
    if (!canon) throw new Error("no canonical bytes to verify against");
    const key = importEd25519PublicKey(sig.public_key);
    const passed = edVerify(null, canon, key, Buffer.from(sig.value, "hex"));
    checks.push({
      name: "ed25519_signature",
      passed,
      detail: passed
        ? `Ed25519 signature valid under public_key ${sig.public_key.slice(0, 16)}...`
        : `Ed25519 signature INVALID under public_key ${sig.public_key.slice(0, 16)}...`,
    });
    if (!passed) errors.push("signature verification failed");
  } catch (e) {
    checks.push({
      name: "ed25519_signature",
      passed: false,
      detail: `error: ${(e as Error).message}`,
    });
    errors.push(`ed25519_signature: ${(e as Error).message}`);
  }

  // --- Check 4: CHAIN LINK (optional) ---
  if (prevHash !== undefined) {
    const passed = receipt.prev_hash === prevHash;
    checks.push({
      name: "chain_link",
      passed,
      detail: passed
        ? `prev_hash matches expected (${prevHash.slice(0, 16)}...)`
        : `prev_hash=${receipt.prev_hash} != expected=${prevHash}`,
    });
    if (!passed) errors.push("chain link mismatch");
  }

  const valid = checks.every((c) => c.passed);
  return { valid, checks, errors, signer_trusted: signerTrusted,
    signature_valid: checks.some(c => c.name === "ed25519_signature" && c.passed), bitcoin_verified: false,
    verification_scope: "receipt integrity and configured signer trust; Bitcoin and ledger inclusion not assessed" };
}

/**
 * Convenience one-liner: returns true iff all verification checks pass.
 * Never throws for a failed check; only for wholly malformed input.
 */
export function verify(receipt: Receipt, prevHash?: string, options: TrustOptions = {}): boolean {
  return verifyReceipt(receipt, prevHash, options).valid;
}

/** The published ProofLink v3 Ed25519 public key (lowercase hex). */
export const PUBLISHED_PUBLIC_KEY =
  "21102eaa68ea9ed42c05a2253aa953d33c59b5348ff8659018146e59fb061b97";

/**
 * Thin remote-seal helper. Sealing is a SERVER-SIDE operation (append.py holds the
 * private key); this is a plain HTTP POST to a ProofLink seal endpoint and performs
 * NO local cryptography. Returns the sealed receipt the server produced.
 *
 * @param endpoint full URL of the seal endpoint (e.g. https://verify.itechsmart.dev/api/seal)
 * @param payload  the action payload to seal (server assigns id/hash/signature)
 */
export async function sealRemote(
  endpoint: string,
  payload: Record<string, unknown>,
  init?: Record<string, unknown>,
): Promise<Receipt> {
  // `fetch` is a Node 18+ global. Typed loosely so the SDK compiles under
  // lib:["ES2020"] without pulling in the DOM lib.
  const f = (globalThis as unknown as {
    fetch: (input: string, init?: unknown) => Promise<{
      ok: boolean;
      status: number;
      text(): Promise<string>;
      json(): Promise<unknown>;
    }>;
  }).fetch;
  const headers = { "Content-Type": "application/json", ...(init?.["headers"] as object) };
  const res = await f(endpoint, { method: "POST", body: JSON.stringify(payload), ...init, headers });
  if (!res.ok) {
    throw new Error(`sealRemote failed: HTTP ${res.status} ${await res.text()}`);
  }
  return (await res.json()) as Receipt;
}

// ─────────────────────────────────────────────────────────────────────────
// Public-ledger convenience layer (verify.itechsmart.dev, no account needed)
// ─────────────────────────────────────────────────────────────────────────

export const DEFAULT_LEDGER = "https://verify.itechsmart.dev";

function nodeFetch() {
  const f = (globalThis as unknown as {
    fetch?: (input: string, init?: unknown) => Promise<{
      ok: boolean; status: number; text(): Promise<string>; json(): Promise<unknown>;
    }>;
  }).fetch;
  if (!f) throw new Error("global fetch unavailable — requires Node 18+");
  return f;
}

async function getJson(url: string): Promise<unknown> {
  const res = await nodeFetch()(url, { headers: { "User-Agent": "prooflink-sdk/1.1.0" } });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return res.json();
}

/** Fetch a single receipt from the public verifier by id or hash prefix. */
export async function fetchReceipt(idOrHash: string, base = DEFAULT_LEDGER): Promise<Receipt> {
  const d = (await getJson(`${base}/api/verify/${encodeURIComponent(idOrHash)}`)) as
    { receipt?: Receipt } & Receipt;
  return (d.receipt ?? d) as Receipt;
}

/** Fetch a receipt from the public ledger and fully verify it in one call. */
export async function fetchAndVerify(idOrHash: string, base = DEFAULT_LEDGER):
  Promise<VerificationResult & { id: string }> {
  const r = await fetchReceipt(idOrHash, base);
  return { id: idOrHash, ...verifyReceipt(r) };
}

/** Live ledger statistics: { total, chain_intact, ... }. */
export async function stats(base = DEFAULT_LEDGER): Promise<Record<string, unknown>> {
  return (await getJson(`${base}/api/stats`)) as Record<string, unknown>;
}

/** The newest N receipts (summary form) from the public ledger. */
export async function recent(limit = 25, base = DEFAULT_LEDGER): Promise<Receipt[]> {
  const d = (await getJson(`${base}/api/receipts?limit=${Math.floor(limit)}`)) as
    { receipts?: Receipt[] };
  return d.receipts ?? [];
}

