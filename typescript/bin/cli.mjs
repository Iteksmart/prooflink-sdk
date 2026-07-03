#!/usr/bin/env node
/* @itechsmart/prooflink CLI — verify ProofLink receipts from the public ledger.
 *   npx @itechsmart/prooflink <receipt_id>     full crypto verify of one receipt
 *   npx @itechsmart/prooflink --stats          live ledger stats
 */
import { fetchAndVerify, stats } from "../dist/index.js";

const G = "\x1b[32m", R = "\x1b[31m", D = "\x1b[2m", B = "\x1b[1m", X = "\x1b[0m";

async function main() {
  const a = process.argv.slice(2);
  if (!a.length || a[0] === "-h" || a[0] === "--help") {
    console.log(`${B}ProofLink SDK${X} — don't trust the AI, trust the math.
  npx @itechsmart/prooflink <receipt_id>   verify one receipt (hash/payload + Ed25519)
  npx @itechsmart/prooflink --stats        live ledger totals
Ledger: https://verify.itechsmart.dev  (no account required)`);
    process.exit(0);
  }
  if (a[0] === "--stats") {
    const s = await stats();
    console.log(`${B}ProofLink ledger${X}: ${s.total ?? s.total_receipts} receipts · chain_intact=${s.chain_intact}`);
    process.exit(0);
  }
  const res = await fetchAndVerify(a[0]);
  console.log(`${B}ProofLink receipt ${a[0]}${X}`);
  for (const c of res.checks) console.log(`  ${c.passed ? G + "✓" : R + "✗"} ${c.name}${X} ${D}${c.detail}${X}`);
  console.log(res.valid ? `${G}${B}VERIFIED${X}` : `${R}${B}NOT VERIFIED${X}`);
  process.exit(res.valid ? 0 : 1);
}
main().catch((e) => { console.error(`${R}Error: ${e.message}${X}`); process.exit(3); });
