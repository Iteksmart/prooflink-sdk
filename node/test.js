// Smoke tests for the ProofLink Node SDK.
// No test framework — runs as a plain script with assertions.
// Skips seal() if append.py isn't local (CI / external mode).

'use strict'

const assert = require('assert')
const { ProofLinkClient, ProofLinkError } = require('./index.js')

async function testChainStatus(client) {
  const s = await client.chainStatus()
  assert.strictEqual(typeof s, 'object')
  assert.ok('chain_intact' in s, 'missing chain_intact')
  assert.ok('total' in s, 'missing total')
  assert.strictEqual(typeof s.total, 'number')
  console.log(`  ✓ chainStatus: intact=${s.chain_intact} total=${s.total} breaks=${s.breaks}`)
}

async function testSealValidation(client) {
  try {
    await client.seal({ category: 'x' })  // missing actor/subject/action
  } catch (e) {
    assert.ok(e instanceof ProofLinkError, 'expected ProofLinkError')
    assert.ok(/missing required fields/i.test(e.message), `unexpected msg: ${e.message}`)
    console.log(`  ✓ seal validation rejected partial action`)
    return
  }
  throw new Error('seal({}) should have thrown ProofLinkError')
}

async function testSealNoOts(client) {
  if (!client.localSealAvailable) {
    console.log('  ⊘ seal skipped — append.py not local (CI / client-only mode)')
    return
  }
  const receipt = await client.seal({
    category: 'sdk_self_test',
    actor:    'system:sdk-test',
    subject:  'prooflink-sdk-v0.1',
    action:   'unit test smoke (node)',
    outcome:  'verifying SDK seal round-trip',
    details:  { test: 'testSealNoOts', framework: 'node' },
    noOts:    true,
  })
  assert.strictEqual(receipt.ok, true, `seal failed: ${JSON.stringify(receipt)}`)
  assert.strictEqual(receipt.hash.length, 64, `expected 64-char hash, got ${receipt.hash}`)
  assert.strictEqual(receipt.id.length, 16, `expected 16-char id, got ${receipt.id}`)
  console.log(`  ✓ seal produced hash=${receipt.hash.slice(0, 16)}... id=${receipt.id}`)
}

async function testLocalSealUnavailableRaises() {
  const client = new ProofLinkClient({ appendPy: '/nonexistent/path/to/append.py' })
  assert.strictEqual(client.localSealAvailable, false)
  try {
    await client.seal({ category: 'x', actor: 'y', subject: 'z', action: 'w' })
  } catch (e) {
    assert.ok(e instanceof ProofLinkError)
    assert.ok(/Local seal not available/.test(e.message))
    console.log('  ✓ missing append.py raises clean error')
    return
  }
  throw new Error('seal with bad appendPy should have thrown')
}

async function main() {
  console.log('ProofLink SDK v0.1 — Node smoke tests')
  console.log('='.repeat(50))

  const client = new ProofLinkClient()
  console.log(`  localSealAvailable: ${client.localSealAvailable}`)
  console.log(`  verifyUrl:          ${client.verifyUrl}\n`)

  await testChainStatus(client)
  await testSealValidation(client)
  await testSealNoOts(client)
  await testLocalSealUnavailableRaises()

  console.log('\nall tests passed ✓')
}

main().catch(err => {
  console.error('TEST FAILED:', err.message)
  console.error(err.stack)
  process.exit(1)
})
