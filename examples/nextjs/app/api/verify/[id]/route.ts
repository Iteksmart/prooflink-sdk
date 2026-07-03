// ProofLink × Next.js — a public receipt-verification API route.
//
//   npm i @itechsmart/prooflink
//   // GET /api/verify/c58347c60394a21f  ->  { valid, checks, ... }
//
// Works in any Next.js App Router project (Node runtime). No account needed —
// verification runs against the public ProofLink ledger.

import { fetchAndVerify } from "@itechsmart/prooflink";
import { NextResponse } from "next/server";

export const runtime = "nodejs"; // node:crypto is used for Ed25519

export async function GET(
  _req: Request,
  { params }: { params: { id: string } },
) {
  try {
    const result = await fetchAndVerify(params.id);
    return NextResponse.json({
      receipt_id: params.id,
      valid: result.valid,
      checks: result.checks,
      verify_url: `https://verify.itechsmart.dev/${params.id}`,
    });
  } catch (e) {
    return NextResponse.json(
      { error: (e as Error).message },
      { status: 404 },
    );
  }
}
