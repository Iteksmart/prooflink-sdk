// TypeScript declarations for @itechsmart/prooflink.

export interface SealAction {
  category: string
  actor: string
  subject: string
  action: string
  outcome?: string
  details?: Record<string, unknown> | string
  humanInput?: boolean
  autoResolved?: boolean
  verifyUrl?: string
  hash?: string
  noOts?: boolean
}

export interface SealResult {
  ok: true
  id: string       // 16-char hex
  hash: string     // 64-char SHA-256
}

export interface ChainStatus {
  chain_intact: boolean
  total: number
  breaks: number
}

export interface Receipt {
  id: string
  timestamp: string
  category: string
  actor: string
  subject: string
  action: string
  outcome: string
  details: Record<string, unknown>
  hash_sha256: string
  prev_hash?: string
  verify_url?: string
  tamper_detected: boolean
  human_input: boolean
  auto_resolved: boolean
  recomputed?: boolean
  recomputed_at?: string
}

export interface ProofLinkClientOptions {
  appendPy?: string
  verifyUrl?: string
  pythonBin?: string
  timeout?: number
}

export class ProofLinkError extends Error {}

export class ProofLinkClient {
  constructor(options?: ProofLinkClientOptions)
  readonly localSealAvailable: boolean
  readonly appendPy: string
  readonly verifyUrl: string
  readonly pythonBin: string
  readonly timeout: number

  seal(action: SealAction, opts?: { noOts?: boolean }): Promise<SealResult>
  submitToLedger(payload: SealAction, opts?: { noOts?: boolean }): Promise<SealResult>
  verify(hash: string): Promise<Receipt>
  chainStatus(): Promise<ChainStatus>
}
