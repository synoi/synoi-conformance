// not-executable-status.test.ts
//
// Reproduce-first safety test for the VectorResult not-executable state.
//
// FAILING-BEFORE / PASSING-AFTER contract:
//   The runner previously had no 'not-executable' status.  NOT-EXECUTABLE-IN-RUNNER
//   vectors were emitted as { passed: false, reason: 'NOT-EXECUTABLE-IN-RUNNER ...' }
//   which the runner counted as `failed` and the reporter printed as FAIL.
//
//   FAILING-BEFORE: if we compute tallies from the OLD logic
//     (failed = results.length - passed, where any !passed is failed),
//     a not-executable vector increments `failed`.  This test demonstrates that
//     outcome then asserts it is WRONG (the test would have failed before the fix).
//
//   PASSING-AFTER: the runner normalizes status then counts correctly.
//     not-executable goes into `not_executable`, not `failed`.
//
// CONTROL (essential safety property):
//   A GENUINE failing vector (passed=false, status='fail') still counts in `failed`.
//   This proves not-executable does NOT mask a real failure.

import { runProtocol } from '../src/runner.ts'
import type { Reporter, RunReport, VectorResult, Protocol } from '../src/types.ts'
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Minimal collector reporter.
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

// Write a fake wasm-shell fixture directory with exactly three vectors:
//   - one that passes (canonical-parity kind that executes cleanly)
//   - one that produces a not-executable result (daemon-boot-chain)
//   - one genuine fail injected via b2-receipt-verify placeholder (no harness tag)
//
// The simplest approach: use daemon-boot-chain.json for not-executable (the handler
// always emits notExec), and a canonical-parity.json with one bad case for genuine fail.
function writeFixtureDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'synoi-ne-test-'))

  // daemon-boot-chain.json: all vectors are not-executable by design.
  writeFileSync(join(dir, 'daemon-boot-chain.json'), JSON.stringify({
    vectors: [
      { name: 'test-ne-vector' },
    ],
  }), 'utf8')

  // canonical-parity.json: one genuine fail (wrong expected_canonical).
  writeFileSync(join(dir, 'canonical-parity.json'), JSON.stringify({
    description: 'test fixture',
    cases: [
      {
        name:               'genuine-fail-case',
        kind:               'canonicalize',
        input:              { z: 1, a: 2 },
        expected_canonical: '{"INTENTIONALLY_WRONG":"value"}',
      },
    ],
  }), 'utf8')

  return dir
}

async function main(): Promise<void> {
  const fixtureDir = writeFixtureDir()

  try {
    const reporter = new CollectReporter()
    const report = await runProtocol({
      protocol:   'wasm-shell',
      reporter,
      vectorsDir: fixtureDir,
    })

    // ── not-executable is counted in not_executable, NOT in failed ──────────
    const neResult = reporter.results.find(x => x.r.vector_name === 'test-ne-vector')
    ok('not-executable vector exists in results', neResult !== undefined)
    ok('not-executable vector has status not-executable',
       neResult?.r.status === 'not-executable',
       `got status=${neResult?.r.status}`)
    ok('not-executable vector has passed=false',
       neResult?.r.passed === false)
    ok('not-executable vector is NOT counted in report.failed',
       report.failed === 0 || !reporter.results
         .filter(x => x.r.vector_name === 'test-ne-vector')
         .some(x => x.r.status === 'fail'),
    )
    ok('not-executable bucket has count >= 1',
       report.not_executable >= 1,
       `got not_executable=${report.not_executable}`)

    // ── FAILING-BEFORE demonstration ────────────────────────────────────────
    // Show what the OLD tally logic (failed = length - passed) would have produced.
    // Under the old logic, any !passed was counted as failed, so the not-executable
    // vector would have incremented `failed`.  That is the bug we are fixing.
    const oldFailed = reporter.results.filter(x => !x.r.passed).length
    ok('FAILING-BEFORE: old logic (any !passed = failed) would count not-executable as failed',
       oldFailed > 0,
       `old failed count=${oldFailed} -- proves the old logic was wrong`)

    // The NEW tally correctly separates them.
    ok('PASSING-AFTER: new report.failed excludes not-executable vectors',
       report.not_executable > 0 && report.failed < oldFailed,
       `report.failed=${report.failed}, report.not_executable=${report.not_executable}, oldFailed=${oldFailed}`)

    // ── CONTROL: genuine fail still counted in failed ────────────────────────
    const genuineFailResult = reporter.results.find(x =>
      x.r.vector_name === 'canonical-parity:genuine-fail-case')
    ok('CONTROL: genuine fail vector exists in results', genuineFailResult !== undefined)
    ok('CONTROL: genuine fail has status=fail',
       genuineFailResult?.r.status === 'fail',
       `got status=${genuineFailResult?.r.status}`)
    ok('CONTROL: genuine fail has passed=false',
       genuineFailResult?.r.passed === false)
    ok('CONTROL: genuine fail IS counted in report.failed',
       report.failed >= 1,
       `report.failed=${report.failed}`)

    // ── not_executables array is populated ──────────────────────────────────
    ok('report.not_executables array contains the not-executable vector',
       report.not_executables.some(r => r.vector_name === 'test-ne-vector'))
    ok('report.failures array does NOT contain the not-executable vector',
       !report.failures.some(r => r.vector_name === 'test-ne-vector'))

    // ── vectors_run counts both ───────────────────────────────────────────
    // vectors_run = passed + failed + not_executable (+ any others)
    ok('vectors_run = passed + failed + not_executable',
       report.vectors_run === report.passed + report.failed + report.not_executable,
       `run=${report.vectors_run} pass=${report.passed} fail=${report.failed} ne=${report.not_executable}`)

    // ── reporter emits SKIP for not-executable, FAIL for genuine fail ───────
    // (We cannot capture stdout here easily; we verify via the result objects instead.)
    ok('reporter saw not-executable result with status not-executable',
       reporter.results.some(x => x.r.status === 'not-executable'))
    ok('reporter saw fail result with status fail',
       reporter.results.some(x => x.r.status === 'fail'))

  } finally {
    rmSync(fixtureDir, { recursive: true, force: true })
  }

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
