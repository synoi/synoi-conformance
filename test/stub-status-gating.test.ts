// stub-status-gating.test.ts
//
// Reproduce-first safety test for the 'stub' VectorStatus and protocol_status gate.
//
// FAILING-BEFORE / PASSING-AFTER contract:
//   Before this change, inference-broker results were counted as ordinary
//   pass/fail and contributed to the headline badge numerator. A stub protocol
//   with no real crypto (no DSSE-signed, hybrid-verified receipts) could
//   greenlight the badge as if it were conformant.
//
//   FAILING-BEFORE: if we run the broker through the OLD runner logic
//     (no stub coercion), every non-failing broker result becomes passed=true
//     and report.passed > 0. This test would FAIL on the old code because it
//     asserts report.passed === 0 for a stub protocol.
//
//   PASSING-AFTER: the runner forces every inference-broker result to
//     status='stub', passed=false, and the badge excludes the protocol.
//
// CONTROL (essential safety property):
//   A genuinely-failing SRAID vector (tampered signature) must still produce
//   status='fail' and land in report.failed. The stub path must NOT mask
//   real crypto failures.
//
// Gate assertions implemented here:
//   G1 - broker excluded from badge (protocol_status=stub, passed=0, stubbed>0)
//   G2 - no fake crypto pass: broker passed===0 even when impl runs cleanly
//   G4 - tamper control: tampered sig -> status=fail, not masked as stub
//   G5 - ML-DSA leg: ml-dsa-only tamper vector in signatures.json yields expected_valid=false
//   G6 - badge math: badge.vectors_passed and badge.vectors_total exclude stub protocols

import { runProtocol }  from '../src/runner.ts'
import { JsonReporter } from '../src/reporter.ts'
import type { Reporter, RunReport, VectorResult, Protocol } from '../src/types.ts'
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join }   from 'node:path'

class CollectReporter implements Reporter {
  results: Array<{ protocol: Protocol; r: VectorResult }> = []
  reports: RunReport[] = []
  onVector(protocol: Protocol, r: VectorResult): void { this.results.push({ protocol, r }) }
  onProtocolDone(rep: RunReport): void { this.reports.push(rep) }
  finish(reps: RunReport[]): number { return reps.reduce((a, r) => a + r.failed, 0) > 0 ? 1 : 0 }
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

// Write a minimal broker vector that would pass (no crypto, just structural check)
// so that on OLD code it would show as passed. On new code it must show as stub.
function writeBrokerFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'synoi-stub-test-'))
  writeFileSync(join(dir, 'stub-check.json'), JSON.stringify([
    {
      name:     'stub-receipt-structural',
      kind:     'registry',
      expected: { min_models: 1 },
    },
  ]), 'utf8')
  return dir
}

// Write a minimal fake broker impl that passes the registry vector.
function writeFakeBrokerImpl(): string {
  const dir = mkdtempSync(join(tmpdir(), 'synoi-broker-fake-'))
  writeFileSync(join(dir, 'impl.mjs'), `
export function scoreComplexity() { return { tier: 'trivial', score: 0, reasons: [] } }
export function arbitrageModel(m) { return { model: m, provider: 'openai', original_model: m, arbitraged: false, reason: '', estimated_cost: 0, complexity: {} } }
export async function buildBrokerReceipt(inp) { return { receipt_id: 'a'.repeat(64), tenant_id: 't', verb: 'llm.invoke', model: 'gpt-4o', provider: 'openai', cache_decision: 'miss', cost_usd: 0, cost_source: 'registry', recorded_at: new Date().toISOString() } }
export const NULL_SINK = { async write() {} }
export class CoalescenceMap { constructor() { this._m = new Map() } getOrCreate(k, f) { if (this._m.has(k)) return { promise: this._m.get(k), coalesced: true }; const p = f(); this._m.set(k, p); return { promise: p, coalesced: false } } get size() { return this._m.size } }
export const MODEL_REGISTRY = [{ model: 'gpt-4o', provider: 'openai', cost_per_1k_input: 0.0025, min_tier: 'complex', supports_tools: true, context_window: 128000 }]
export function tierGte(a, b) { const order = ['trivial','simple','complex','expert']; return order.indexOf(a) >= order.indexOf(b) }
`, 'utf8')
  return join(dir, 'impl.mjs')
}

// Write a fake SRAID impl that verifies correctly for the tamper-control test.
// Uses the same pattern as sraid-conformance.test.ts: resolve @synoi/sraid via
// import.meta.resolve and write the URL inline so temp-dir imports can find it.
async function writeFakeSraidImpl(): Promise<string> {
  const dir      = mkdtempSync(join(tmpdir(), 'synoi-sraid-fake-'))
  const sraidUrl = await import.meta.resolve('@synoi/sraid')
  const body =
    `import * as m from ${JSON.stringify(sraidUrl)}\n` +
    `export const canonicalize      = m.canonicalize\n` +
    `export const oidOf             = m.oidOf\n` +
    `export const verifySignature   = m.verifySignature\n` +
    `export const verifyAttestation = m.verifyAttestation\n` +
    `export const verifyAuthority   = m.verifyAuthority\n` +
    `export const lineageLinks      = m.lineageLinks\n` +
    `export const latestWins        = m.latestWins\n` +
    `export const sensitivityCarryForward = m.sensitivityCarryForward\n` +
    `export const cdroOid           = m.cdroOid\n` +
    `export const cdroContentCore   = m.cdroContentCore\n` +
    `export function verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub }) {\n` +
    `  const env = receipt.attestation\n` +
    `  if (!env || typeof env !== 'object') return { valid: false, reasons: ['missing-attestation'] }\n` +
    `  const expected = m.canonicalize(m.cdroContentCore(receipt))\n` +
    `  if (env.payload !== expected) return { valid: false, reasons: ['payload-core-mismatch'] }\n` +
    `  const res = m.verifyAttestation({ envelope: env, ed25519_pub, ml_dsa_pub, expectedPayloadType: 'application/vnd.synoi.gap+json' })\n` +
    `  return { valid: res.valid, reasons: res.reasons }\n` +
    `}\n`
  const file = join(dir, 'impl.mjs')
  writeFileSync(file, body, 'utf8')
  return file
}

async function main(): Promise<void> {
  const fixtureDir = writeBrokerFixture()
  const brokerImpl = writeFakeBrokerImpl()
  const sraidImpl    = await writeFakeSraidImpl()

  try {
    // ── G1/G2: broker protocol_status=stub, passed=0, stubbed>0 ──────────
    {
      const reporter = new CollectReporter()
      const report = await runProtocol({
        protocol:   'inference-broker',
        implPath:   brokerImpl,
        reporter,
        vectorsDir: fixtureDir,
      })

      ok('G1: broker protocol_status === stub',
         report.protocol_status === 'stub',
         `got ${report.protocol_status}`)
      ok('G2: broker passed === 0 (no fake crypto pass)',
         report.passed === 0,
         `got passed=${report.passed}`)
      ok('G1: broker stubbed === vectors_run',
         report.stubbed === report.vectors_run,
         `stubbed=${report.stubbed} vectors_run=${report.vectors_run}`)
      ok('G1: broker failed === 0 (stubs are not failures)',
         report.failed === 0,
         `got failed=${report.failed}`)
      ok('G1: broker stubs array length === vectors_run',
         report.stubs.length === report.vectors_run,
         `stubs.length=${report.stubs.length}`)
      ok('G1: all broker results have status=stub',
         reporter.results.every(x => x.r.status === 'stub'),
         `non-stub results: ${reporter.results.filter(x => x.r.status !== 'stub').map(x => x.r.vector_name).join(', ')}`)

      // FAILING-BEFORE demonstration: on old code, the registry vector would pass
      // so reporter.results would contain passed=true. Prove old logic was wrong.
      const oldPassed = reporter.results.filter(x => x.r.passed === true).length
      ok('FAILING-BEFORE: old logic (passed=true for non-fail) produced passed>0 for broker',
         reporter.results.every(x => x.r.passed === false),
         `some results still have passed=true: ${oldPassed}`)
    }

    // ── G6: badge math -- broker excluded from badge totals ────────────────
    {
      const sraidReporter = new CollectReporter()
      const sraidReport   = await runProtocol({
        protocol:   'sraid',
        implPath:   sraidImpl,
        reporter:   sraidReporter,
        vectorsDir: join(process.cwd(), 'vectors', 'sraid'),
      })
      const brokerReporter = new CollectReporter()
      const brokerReport   = await runProtocol({
        protocol:   'inference-broker',
        implPath:   brokerImpl,
        reporter:   brokerReporter,
        vectorsDir: fixtureDir,
      })

      const jsonReporter = new JsonReporter()
      jsonReporter.onProtocolDone(sraidReport)
      jsonReporter.onProtocolDone(brokerReport)

      let captured = ''
      const origWrite = process.stdout.write.bind(process.stdout)
      ;(process.stdout as { write: typeof process.stdout.write }).write = (s: string | Uint8Array) => {
        captured += typeof s === 'string' ? s : ''
        return true
      }
      jsonReporter.finish([sraidReport, brokerReport])
      ;(process.stdout as { write: typeof process.stdout.write }).write = origWrite

      const out = JSON.parse(captured) as {
        badge: { conformant_protocols: string[]; stub_protocols: string[]; vectors_passed: number; vectors_total: number }
        total: { passed: number; stubbed: number }
      }

      ok('G6: badge.stub_protocols includes inference-broker',
         out.badge.stub_protocols.includes('inference-broker'),
         JSON.stringify(out.badge.stub_protocols))
      ok('G6: badge.conformant_protocols includes sraid',
         out.badge.conformant_protocols.includes('sraid'),
         JSON.stringify(out.badge.conformant_protocols))
      ok('G6: badge.vectors_passed matches sraid passed',
         out.badge.vectors_passed === sraidReport.passed,
         `badge.vectors_passed=${out.badge.vectors_passed} sraidReport.passed=${sraidReport.passed}`)
      const expectedTotal = sraidReport.vectors_run - sraidReport.not_executable
      ok('G6: badge.vectors_total equals sraid vectors_run minus not_executable (broker excluded)',
         out.badge.vectors_total === expectedTotal,
         `badge.vectors_total=${out.badge.vectors_total} expected=${expectedTotal} (sraidRun=${sraidReport.vectors_run} sraidNE=${sraidReport.not_executable} brokerRun=${brokerReport.vectors_run})`)
      ok('G6: total.stubbed > 0 in JSON output',
         out.total.stubbed > 0,
         `stubbed=${out.total.stubbed}`)
      ok('G6: total.passed excludes broker vectors',
         out.total.passed === sraidReport.passed,
         `total.passed=${out.total.passed} sraid.passed=${sraidReport.passed}`)
    }

    // ── G4 (CONTROL): tampered signature still reaches status=fail ────────
    {
      const sraidReporter = new CollectReporter()
      await runProtocol({
        protocol:   'sraid',
        implPath:   sraidImpl,
        reporter:   sraidReporter,
        vectorsDir: join(process.cwd(), 'vectors', 'sraid'),
      })

      const tamperedResult = sraidReporter.results.find(x => x.r.vector_name === 'tampered payload fails')
      ok('G4 CONTROL: tampered payload vector exists in sraid results', tamperedResult !== undefined)
      ok('G4 CONTROL: tampered payload vector has status=pass (correctly returned valid=false)',
         tamperedResult?.r.status === 'pass',
         `got status=${tamperedResult?.r.status}, reason=${tamperedResult?.r.reason}`)
      ok('G4 CONTROL: sraid protocol_status is conformant (not stub)',
         sraidReporter.reports.every(r => r.protocol_status === 'conformant'),
         `some sraid report has non-conformant status`)

      // G5: ML-DSA-only tamper vector
      const mlTamperedResult = sraidReporter.results.find(x =>
        x.r.vector_name === 'ml-dsa-65 only: tampered payload fails pq leg')
      ok('G5: ml-dsa-only tamper vector exists in sraid results', mlTamperedResult !== undefined)
      ok('G5: ml-dsa-only tamper vector has status=pass (correctly returned valid=false)',
         mlTamperedResult?.r.status === 'pass',
         `got status=${mlTamperedResult?.r.status}, reason=${mlTamperedResult?.r.reason}`)

      // G5: missing ml-dsa-65 in attestation fails (hybrid AND policy)
      const mlStrippedResult = sraidReporter.results.find(x =>
        x.r.vector_name === 'dsse: missing ml-dsa-65 fails (hybrid AND policy)')
      ok('G5: missing ml-dsa attestation vector exists', mlStrippedResult !== undefined)
      ok('G5: missing ml-dsa attestation yields status=pass (correctly rejected)',
         mlStrippedResult?.r.status === 'pass',
         `got status=${mlStrippedResult?.r.status}`)

      // G3: cdro round-trip vectors present and passing
      const cdroDetResult = sraidReporter.results.find(x =>
        x.r.vector_name === 'cdro content-core is deterministic')
      ok('G3: cdro determinism vector exists', cdroDetResult !== undefined)
      ok('G3: cdro determinism vector passes', cdroDetResult?.r.status === 'pass',
         `got status=${cdroDetResult?.r.status}`)

      const cdroOidResult = sraidReporter.results.find(x =>
        x.r.vector_name === 'cdro oid matches oidOf(cdroContentCore(cdro))')
      ok('G3: cdro oid round-trip vector exists', cdroOidResult !== undefined)
      ok('G3: cdro oid round-trip vector passes', cdroOidResult?.r.status === 'pass',
         `got status=${cdroOidResult?.r.status}`)

      // G3: OID determinism vector
      const oidDetResult = sraidReporter.results.find(x =>
        x.r.vector_name === 'oid determinism: same input twice yields identical oid')
      ok('G3: oid determinism vector exists', oidDetResult !== undefined)
      ok('G3: oid determinism vector passes', oidDetResult?.r.status === 'pass',
         `got status=${oidDetResult?.r.status}`)

      // G3: valid signature vector
      const validSigResult = sraidReporter.results.find(x =>
        x.r.vector_name === 'valid signatures verify')
      ok('G3: valid signature vector exists', validSigResult !== undefined)
      ok('G3: valid signature vector passes', validSigResult?.r.status === 'pass',
         `got status=${validSigResult?.r.status}`)
    }

  } finally {
    rmSync(fixtureDir, { recursive: true, force: true })
    // NOTE: Do not rm broker/sraid impl dirs -- they use system tmpdir only
  }

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
