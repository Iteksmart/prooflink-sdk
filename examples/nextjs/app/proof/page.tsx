// ProofLink × Next.js — a server component that shows LIVE ledger integrity.
//
//   npm i @itechsmart/prooflink
//   // renders at /proof — fetched server-side, no client JS, no account.

import { stats, recent } from "@itechsmart/prooflink";

export const dynamic = "force-dynamic"; // always fetch fresh ledger state

export default async function ProofPage() {
  const [s, latest] = await Promise.all([stats(), recent(5)]);
  const total = (s.total_receipts ?? s.total) as number;

  return (
    <main style={{ fontFamily: "system-ui", padding: 32, maxWidth: 720 }}>
      <h1>ProofLink — live ledger</h1>
      <p>
        <strong>{total.toLocaleString()}</strong> cryptographic receipts ·{" "}
        chain intact: <strong>{String(s.chain_intact)}</strong> ·{" "}
        breaks: <strong>{String(s.breaks ?? 0)}</strong>
      </p>
      <h2>Newest actions</h2>
      <ul>
        {latest.map((r) => (
          <li key={r.receipt_id}>
            <a href={`https://verify.itechsmart.dev/${r.receipt_id}`}>
              {r.receipt_id}
            </a>{" "}
            — {(r as { action?: string }).action ?? "sealed"}
          </li>
        ))}
      </ul>
      <p style={{ color: "#666", fontSize: 13 }}>
        Don&apos;t trust this page — verify any receipt yourself at
        verify.itechsmart.dev.
      </p>
    </main>
  );
}
