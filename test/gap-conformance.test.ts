// gap-conformance.test.ts -- run the GAP conformance suite against the
// @synoi/gap reference impl. Every vector must pass.
// ADR_007: renamed from agp-conformance.test.ts; vectors/agp/ -> vectors/gap/.

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
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

async function main(): Promise<void> {
  const dir  = mkdtempSync(join(tmpdir(), 'synoi-conf-gap-'))
  const impl = join(dir, 'impl.mjs')
  const agpIndex = `${process.cwd().replace(/\\/g, '/')}/node_modules/@synoi/gap/dist/index.js`
  writeFileSync(impl,
    `import * as m from 'file:///${agpIndex}'\n` +
    `export const computeGapOid                  = m.computeGapOid\n` +
    `export const validateCapabilityDeclaration  = m.validateCapabilityDeclaration\n` +
    `export const validateCapabilityGrant        = m.validateCapabilityGrant\n` +
    `export const validateCapabilityInvocation   = m.validateCapabilityInvocation\n` +
    `export const validateWorkflowDefinition     = m.validateWorkflowDefinition\n` +
    `export const validateWorkflowInstance       = m.validateWorkflowInstance\n` +
    `export const validateGapDecisionReceipt     = m.validateGapDecisionReceipt\n` +
    `export const validateRevocationEvent        = m.validateRevocationEvent\n`,
    'utf8')

  const report = await runProtocol({
    protocol:    'gap',
    implPath:    impl,
    reporter:    new SilentReporter(),
    vectorsDir:  join(process.cwd(), 'vectors', 'gap'),
  })

  ok('gap: vectors_run > 0',          report.vectors_run > 0)
  ok('gap: all vectors passed',       report.failed === 0,
     report.failures.map(f => `${f.vector_name}: ${f.reason}`).join(' / '))
  ok('gap: at least 24 validate + 6 oid vectors',
     report.vectors_run >= 30)

  process.stdout.write(`\n${passed} passed, ${failed} failed (${report.vectors_run} GAP vectors)\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
