// Real verification test against live ProofLink v3 receipts.
// Run: node test/verify.test.mjs
// Loads the compiled SDK from ../dist/index.js and the saved live-receipt corpus.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyReceipt } from "../dist/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const CORPUS =
  process.env.PL_CORPUS ||
  join(__dirname, "fixtures", "v3_samples.json");

const samples = JSON.parse(readFileSync(CORPUS, "utf-8"));

let allPass = true;

function printResult(label, result) {
  const badge = result.valid ? "PASS" : "FAIL";
  console.log(`\n[${badge}] ${label}`);
  for (const c of result.checks) {
    console.log(`   ${c.passed ? "ok  " : "FAIL"} ${c.name.padEnd(24)} ${c.detail}`);
  }
  if (result.errors.length) {
    console.log(`   errors: ${result.errors.join("; ")}`);
  }
}

console.log(`ProofLink v3 SDK verification test`);
console.log(`corpus: ${CORPUS}`);
console.log(`receipts: ${samples.length}`);

// --- 1. Verify each real live receipt (with expected prev_hash) ---
for (const entry of samples) {
  const r = entry.receipt;
  const prev = entry.prev_hash_expected;
  const label = `receipt id=${r.id} chain_position=${r.chain_position}` +
    (r.compliance_tags ? ` [compliance_tags: ${r.compliance_tags.length}]` : "");
  const result = verifyReceipt(r, prev);
  printResult(label, result);
  if (!result.valid) allPass = false;
}

// --- 2. TAMPERED receipt: mutate `outcome` WITHOUT recomputing canonical/hash/signature ---
const original = samples[0].receipt;
const tampered = JSON.parse(JSON.stringify(original));
tampered.outcome = tampered.outcome === "TAMPERED" ? "STILL_TAMPERED" : "TAMPERED";
console.log(`\n--- TAMPER TEST ---`);
console.log(`mutated outcome: "${original.outcome}" -> "${tampered.outcome}" (canonical_bytes/hash/signature left unchanged)`);
const tamperResult = verifyReceipt(tampered, samples[0].prev_hash_expected);
printResult(`TAMPERED receipt id=${tampered.id}`, tamperResult);

// A tampered receipt MUST fail. It should fail canonical re-derivation (the payload no
// longer produces the stored canonical_bytes). The stored hash/signature still match the
// stored (stale) canonical_bytes, which is exactly why re-derivation is the tamper trap.
const tamperCorrectlyRejected =
  tamperResult.valid === false &&
  tamperResult.checks.find((c) => c.name === "canonical_rederivation")?.passed === false;

console.log(`\n--- SUMMARY ---`);
console.log(`live receipts all valid : ${allPass}`);
console.log(`tamper correctly rejected: ${tamperCorrectlyRejected} (reason: ${tamperResult.errors.join("; ")})`);

if (allPass && tamperCorrectlyRejected) {
  console.log(`\nRESULT: PASS — all live receipts verified, tampered receipt rejected.`);
  process.exit(0);
} else {
  console.log(`\nRESULT: FAIL`);
  process.exit(1);
}
