// inference-broker-conformance.test.ts - run the Inference Broker conformance
// suite against the @synoi/broker reference implementation.

import { runProtocol } from '../src/runner.ts'
import type { Reporter, RunReport, VectorResult, Protocol } from '../src/types.ts'
import { existsSync } from 'node:fs'
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
  // Locate the @synoi/broker dist - it's a sibling repo.
  const brokerDist = join(process.cwd(), '..', 'synoi-broker', 'dist', 'index.js')
  if (!existsSync(brokerDist)) {
    // @synoi/broker is not published / not checked out (closed L2 component).
    // The inference-broker conformance vectors can only run against its impl,
    // so treat an absent broker as PENDING (skipped), not a failure.
    process.stdout.write(
      `PENDING  inference-broker conformance: @synoi/broker dist not present at ` +
      `${brokerDist}; suite skipped (build the sibling to run it locally).\n`,
    )
    process.exit(0)
  }

  const report = await runProtocol({
    protocol:   'inference-broker',
    implPath:   brokerDist,
    reporter:   new SilentReporter(),
    vectorsDir: join(process.cwd(), 'vectors', 'inference-broker'),
  })

  ok('inference-broker: vectors_run > 0', report.vectors_run > 0,
     `got ${report.vectors_run}`)
  ok('inference-broker: all vectors passed', report.failed === 0,
     report.failures.map(f => `${f.vector_name}: ${f.reason}`).join(' / '))
  ok('inference-broker: at least 17 vectors',
     report.vectors_run >= 17,
     `got ${report.vectors_run}`)

  process.stdout.write(`\n${passed} passed, ${failed} failed (${report.vectors_run} inference-broker vectors)\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
