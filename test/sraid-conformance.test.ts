// sraid-conformance.test.ts - run the SRAID conformance suite against the
// @synoi/sraid reference impl. Every vector must pass - this is the
// "reference impl is conformant to its own vectors" smoke test.

import { runProtocol } from '../src/runner.ts'
import type { Reporter, RunReport, VectorResult, Protocol } from '../src/types.ts'
import { writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

class SilentReporter implements Reporter {
  onVector(_p: Protocol, _r: VectorResult): void {}
  onProtocolDone(_r: RunReport): void {}
  finish(_reps: RunReport[]): number { return 0 }
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' - ' + detail : ''}\n`) }
}

async function main(): Promise<void> {
  // Stage a tiny ESM module that re-exports @synoi/sraid so the runner
  // can `import(file:...)` it the same way an external candidate would.
  const dir  = mkdtempSync(join(tmpdir(), 'synoi-conf-sraid-'))
  const impl = join(dir, 'impl.mjs')
  // Resolve @synoi/sraid via the module resolver rather than a hardcoded
  // node_modules path. This works whether deps are installed in cwd or
  // resolved upward (e.g. when this suite runs from a git worktree, where
  // node_modules lives in the primary checkout).
  const sraidIndexUrl = await import.meta.resolve('@synoi/sraid')
  writeFileSync(impl,
    `import * as m from ${JSON.stringify(sraidIndexUrl)}\n` +
    `export const canonicalize    = m.canonicalize\n` +
    `export const oidOf           = m.oidOf\n` +
    `export const verifySignature = m.verifySignature\n` +
    `export const verifyAttestation = m.verifyAttestation\n` +
    `export const verifyAuthority = m.verifyAuthority\n` +
    `export const lineageLinks    = m.lineageLinks\n` +
    `export const latestWins      = m.latestWins\n` +
    `export const sensitivityCarryForward = m.sensitivityCarryForward\n` +
    `export const cdroOid         = m.cdroOid\n` +
    `export const cdroContentCore = m.cdroContentCore\n` +
    `export const verifyDelegationChain = m.verifyDelegationChain\n` +
    // K1 Receipt v2: @synoi/sraid does not ship verifyReceiptV2 - it ships the
    // L0 primitives (cdroContentCore, canonicalize, verifyAttestation) the
    // verifier composes. Define it here from those primitives. This is the same
    // 12-line algorithm as @synoi/verify verifyReceiptV2, proving the vectors
    // are satisfiable from sraid alone (the suite's only reference dependency).
    `export function verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub }) {\n` +
    `  const env = receipt.attestation\n` +
    `  if (!env || typeof env !== 'object') return { valid: false, reasons: ['missing-attestation'] }\n` +
    `  const expected = m.canonicalize(m.cdroContentCore(receipt))\n` +
    `  if (env.payload !== expected) return { valid: false, reasons: ['payload-core-mismatch'] }\n` +
    `  const res = m.verifyAttestation({ envelope: env, ed25519_pub, ml_dsa_pub, expectedPayloadType: 'application/vnd.synoi.gap+json' })\n` +
    `  return { valid: res.valid, reasons: res.reasons }\n` +
    `}\n`,
    'utf8')

  const report = await runProtocol({
    protocol:    'sraid',
    implPath:    impl,
    reporter:    new SilentReporter(),
    vectorsDir:  join(process.cwd(), 'vectors', 'sraid'),
  })

  ok('sraid:vectors_run > 0',                report.vectors_run > 0)
  ok('sraid:all vectors passed',             report.failed === 0,
     report.failures.map(f => `${f.vector_name}: ${f.reason}`).join(' / '))
  ok('sraid:canonicalize+edge+reject+oid+signature+authority+lineage+attestation+sensitivity+receipt_v2+chain all loaded',
     report.vectors_run >= 9 + 6 + 3 + 9 + 4 + 5 + 8 + 5 + 9 + 10 + 7) // 75: + K2 delegation-chain(7)

  process.stdout.write(`\n${passed} passed, ${failed} failed (${report.vectors_run} SRAID vectors)\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
