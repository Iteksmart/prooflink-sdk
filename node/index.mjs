// ESM facade — re-exports the CommonJS implementation so consumers can
// `import { ProofLinkClient } from '@itechsmart/prooflink'` or the equivalent default import.
import cjs from './index.js'

export const ProofLinkClient = cjs.ProofLinkClient
export const ProofLinkError = cjs.ProofLinkError
export default cjs
