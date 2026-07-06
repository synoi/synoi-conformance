// reporter.ts - text + JSON reporters.

import type { ConformanceBadge, Protocol, Reporter, RunReport, VectorResult } from './types.js'

function buildBadge(reports: RunReport[]): ConformanceBadge {
  const conformant = reports.filter(r => r.protocol_status === 'conformant')
  const stubs      = reports.filter(r => r.protocol_status === 'stub')
  return {
    conformant_protocols: conformant.map(r => r.protocol),
    stub_protocols:       stubs.map(r => r.protocol),
    vectors_passed:       conformant.reduce((a, r) => a + r.passed,      0),
    vectors_total:        conformant.reduce((a, r) => a + r.vectors_run - r.not_executable, 0),
  }
}

export class TextReporter implements Reporter {
  onVector(protocol: Protocol, r: VectorResult): void {
    let tag: string
    if (r.status === 'not-executable') {
      tag = 'SKIP'
    } else if (r.status === 'stub') {
      tag = 'STUB'
    } else if (r.passed) {
      tag = 'PASS'
    } else {
      tag = 'FAIL'
    }
    let line = `${tag} ${protocol} [${r.vector_name}]`
    if (r.status !== 'pass' && r.reason) line += ` -- ${r.reason}`
    process.stdout.write(line + '\n')
  }
  onProtocolDone(rep: RunReport): void {
    const parts: string[] = []
    if (rep.protocol_status === 'stub') {
      parts.push(`${rep.stubbed} stub (excluded from badge)`)
    } else {
      parts.push(`${rep.passed}/${rep.vectors_run} passed`)
      if (rep.failed > 0)         parts.push(`${rep.failed} failed`)
      if (rep.not_executable > 0) parts.push(`${rep.not_executable} not-executable`)
    }
    process.stdout.write(`\n${rep.protocol}: ${parts.join(', ')}\n\n`)
  }
  finish(reports: RunReport[]): number {
    const badge      = buildBadge(reports)
    const conformant = reports.filter(r => r.protocol_status === 'conformant')
    const stubProtos = reports.filter(r => r.protocol_status === 'stub')
    const failed  = conformant.reduce((a, r) => a + r.failed, 0)
    const notExec = conformant.reduce((a, r) => a + r.not_executable, 0)

    const parts: string[] = [`${badge.vectors_passed}/${badge.vectors_total} passed`]
    if (notExec > 0)           parts.push(`${notExec} not-executable`)
    if (stubProtos.length > 0) parts.push(`${stubProtos.map(r => r.protocol).join(', ')} stub (excluded)`)
    process.stdout.write(`\n=== ${parts.join(', ')} across ${conformant.length} conformant protocol(s) ===\n`)
    return failed > 0 ? 1 : 0
  }
}

export class JsonReporter implements Reporter {
  private collected: RunReport[] = []
  onVector(_protocol: Protocol, _r: VectorResult): void { /* batched */ }
  onProtocolDone(rep: RunReport): void { this.collected.push(rep) }
  finish(reports: RunReport[]): number {
    const all = this.collected.length > 0 ? this.collected : reports
    const badge      = buildBadge(all)
    const conformant = all.filter(r => r.protocol_status === 'conformant')
    const failed = conformant.reduce((a, r) => a + r.failed, 0)
    process.stdout.write(JSON.stringify({
      protocols: all,
      total: {
        vectors_run:    all.reduce((a, r) => a + r.vectors_run,    0),
        passed:         conformant.reduce((a, r) => a + r.passed,         0),
        failed,
        not_executable: conformant.reduce((a, r) => a + r.not_executable, 0),
        stubbed:        all.reduce((a, r) => a + r.stubbed, 0),
      },
      badge,
    }, null, 2) + '\n')
    return failed > 0 ? 1 : 0
  }
}

export function makeReporter(kind: 'text' | 'json'): Reporter {
  return kind === 'json' ? new JsonReporter() : new TextReporter()
}
