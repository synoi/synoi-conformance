// runner.test.ts - meta-tests for the runner itself.
//
// Feeds the runner a deliberately-broken implementation, then a correct one,
// and asserts the reports + exit codes are what we expect.

import { runProtocol } from '../src/runner.ts'
import type { Reporter, RunReport, VectorResult, Protocol } from '../src/types.ts'
import { writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

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
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' - ' + detail : ''}\n`) }
}

/** Materialize a fake SRAID impl in a temp dir so the runner can import it. */
function writeFakeSraidImpl(returns: 'correct' | 'wrong'): string {
  const dir = mkdtempSync(join(tmpdir(), 'synoi-conf-meta-'))
  // The runner expects a *.js file with ESM exports. Use a tiny one.
  // For 'correct', delegate to @synoi/sraid's actual exports.
  // For 'wrong', stub canonicalize to return a constant.
  const body = returns === 'correct'
    ? `export { canonicalize, oidOf, verifySignature } from '@synoi/sraid'`
    : `export function canonicalize(_x) { return '<WRONG>' }
       export function oidOf(_x) { return 'sha256:dead' }
       export function verifySignature(_args) { return { valid: false, reasons: ['stubbed'] } }`
  // To resolve '@synoi/sraid' from this temp dir, write a package.json that
  // points NODE_RESOLVE at the conformance repo's node_modules. Simpler:
  // write a relative URL to the @synoi/sraid dist file.
  const correctBody = `import sraid from 'file:///${process.cwd().replace(/\\/g, '/')}/node_modules/@synoi/sraid/dist/index.js'\nexport const canonicalize = sraid.canonicalize\nexport const oidOf = sraid.oidOf\nexport const verifySignature = sraid.verifySignature\n`
  const file = join(dir, 'impl.mjs')
  writeFileSync(file, returns === 'correct' ? correctBody : body, 'utf8')
  return file
}

async function main(): Promise<void> {
  // ── Wrong impl produces failures ────────────────────────────────────
  {
    const implPath = writeFakeSraidImpl('wrong')
    const reporter = new CollectReporter()
    const report = await runProtocol({
      protocol: 'sraid',
      implPath,
      reporter,
      vectorsDir: join(process.cwd(), 'vectors', 'sraid'),
    })
    ok('wrong impl: every canonicalize vector fails',
       report.failures.filter(f => f.reason?.includes('canonical bytes')).length > 0)
    ok('wrong impl: every oid vector fails',
       report.failures.filter(f => f.reason?.includes('oid mismatch')).length > 0)
    ok('wrong impl: report.failed > 0',                    report.failed > 0)
    ok('wrong impl: reporter received all results',        reporter.results.length === report.vectors_run)
    rmSync(implPath, { force: true })
  }

  // ── Inference broker without --impl throws clear error ───────────────
  {
    const reporter = new CollectReporter()
    let threw = false
    try {
      await runProtocol({ protocol: 'inference-broker', reporter })
    } catch (err) {
      threw = (err as Error).message.includes('requires --impl')
    }
    ok('inference-broker without --impl throws clear error', threw)
  }

  // ── Missing required input throws cleanly ──────────────────────────
  {
    const reporter = new CollectReporter()
    let threw = false
    try {
      await runProtocol({ protocol: 'sraid', reporter })
    } catch (err) {
      threw = (err as Error).message.includes('requires --impl')
    }
    ok('sraid without --impl throws clear error',         threw)
  }

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
