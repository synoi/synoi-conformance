// cited-oracle-inputs-conformance.test.ts
//
// Sprint 1 Story S1.12 conformance gate for C2 (cited_oracle_inputs schema)
// and C3 (PIP wrapper).
//
// EXPECTED STATE before S1.1 ships: the entry-schema vectors pass (the
// standalone verifier in the runner is self-contained); the pip_wrapper_fetch
// and pip_wrapper_gate_boundary vectors FAIL because no impl is present. That
// is correct and expected -- these vectors are the spec encoded ahead of the
// implementation. Do not weaken them to make them pass.
//
// EXPECTED STATE after S1.1 ships: all vectors pass when run against the
// real impl via --impl=<path>.

import { runCitedOracleInputsVectors } from '../src/protocols/cited-oracle-inputs.js'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { Vector } from '../src/types.js'

let passed = 0
let failed = 0
const pendingS11: string[] = []

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++
    process.stdout.write(`OK   ${label}\n`)
  } else {
    failed++
    process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`)
  }
}

function loadVectors(dir: string): Vector[] {
  if (!existsSync(dir)) return []
  const out: Vector[] = []
  for (const f of readdirSync(dir)) {
    if (!f.endsWith('.json')) continue
    if (f.startsWith('_')) continue
    const raw = readFileSync(join(dir, f), 'utf8')
    const parsed = JSON.parse(raw) as unknown
    if (Array.isArray(parsed)) {
      for (const v of parsed) {
        if (typeof v === 'object' && v !== null) out.push(v as Vector)
      }
    }
  }
  return out
}

async function main(): Promise<void> {
  const vectorsDir = join(process.cwd(), 'vectors', 'cited-oracle-inputs')
  const vectors    = loadVectors(vectorsDir)

  ok('cited-oracle-inputs: vectors directory exists', existsSync(vectorsDir))
  ok('cited-oracle-inputs: at least 10 vectors loaded', vectors.length >= 10,
    `loaded ${vectors.length}`)

  // Count by kind for reporting.
  const entryVectors   = vectors.filter(v => v['kind'] === 'cited_oracle_input_entry')
  const fetchVectors   = vectors.filter(v => v['kind'] === 'pip_wrapper_fetch')
  const boundaryVectors = vectors.filter(v => v['kind'] === 'pip_wrapper_gate_boundary')

  ok('cited-oracle-inputs: at least 5 entry vectors (spec Section 1.7.1 + 1.7.2)',
    entryVectors.length >= 5, `found ${entryVectors.length}`)
  ok('cited-oracle-inputs: at least 2 negative entry vectors',
    entryVectors.filter(v => v['expect'] === 'invalid').length >= 2,
    `found ${entryVectors.filter(v => v['expect'] === 'invalid').length} negative`)
  ok('cited-oracle-inputs: at least 5 positive entry vectors (one per oracle)',
    entryVectors.filter(v => v['expect'] === 'valid').length >= 5,
    `found ${entryVectors.filter(v => v['expect'] === 'valid').length} positive`)

  // Oracle subject_type coverage.
  const validEntries = entryVectors.filter(v => v['expect'] === 'valid')
  for (const st of ['weather', 'ofac', 'time', 'sms_hitl', 'webhook']) {
    const entry = validEntries.find(v => {
      const e = v['entry'] as Record<string, unknown> | undefined
      return e && e['subject_type'] === st
    })
    ok(`cited-oracle-inputs: positive vector covers oracle '${st}'`, entry !== undefined)
  }

  ok('cited-oracle-inputs: at least 8 pip_wrapper vectors (C3)',
    fetchVectors.length + boundaryVectors.length >= 8,
    `fetch=${fetchVectors.length} boundary=${boundaryVectors.length}`)

  // Run all vectors in standalone mode (no impl path). Entry vectors must pass.
  // PIP wrapper vectors will fail as expected.
  const results = await runCitedOracleInputsVectors(undefined, vectors)

  const entryResults   = results.filter((_, i) => vectors[i] && vectors[i]!['kind'] === 'cited_oracle_input_entry')
  const wrapperResults = results.filter((_, i) => vectors[i] && (vectors[i]!['kind'] === 'pip_wrapper_fetch' || vectors[i]!['kind'] === 'pip_wrapper_gate_boundary'))

  const entryPassed = entryResults.filter(r => r.passed).length
  const entryFailed = entryResults.filter(r => !r.passed)

  ok('cited-oracle-inputs: all entry schema vectors pass in standalone mode',
    entryFailed.length === 0,
    entryFailed.map(r => `${r.vector_name}: ${r.reason ?? ''}`).join(' / '))

  // PIP wrapper vectors are expected to fail pre-S1.1 -- record them as pending,
  // not as test failures of THIS test file.
  for (const r of wrapperResults) {
    if (!r.passed) {
      const reason = r.reason ?? ''
      // Accept as pending only if the reason is the expected "S1.1 pending" message.
      if (reason.includes('S1.1 pending')) {
        pendingS11.push(r.vector_name)
      } else {
        // An unexpected failure -- real test failure.
        ok(`pip_wrapper: ${r.vector_name}`, false, reason)
      }
    } else {
      ok(`pip_wrapper: ${r.vector_name}`, true)
    }
  }

  if (pendingS11.length > 0) {
    process.stdout.write(`\nPENDING (S1.1 not yet shipped, ${pendingS11.length} vectors):\n`)
    for (const name of pendingS11) {
      process.stdout.write(`  PENDING  ${name}\n`)
    }
  }

  // Canonicalization edge-case assertions (verifying the standalone JCS).
  process.stdout.write('\n--- Canonicalization discipline self-check ---\n')

  // Keys in an entry must sort lexicographically in JCS canonical form before hashing.
  // weather raw_value: {temp_f, observed_at} -- 'o' < 't' so observed_at comes first.
  const weatherEntry = validEntries.find(v => {
    const e = v['entry'] as Record<string, unknown> | undefined
    return e && e['subject_type'] === 'weather'
  })
  if (weatherEntry) {
    const e = weatherEntry['entry'] as Record<string, unknown>
    const rawValue = e['raw_value'] as Record<string, unknown>
    const keys = Object.keys(rawValue)
    // In the vector JSON, raw_value is already in JCS order.
    // We check: JCS of the as-parsed object still matches the claimed hash.
    const r = results.find(res => res.vector_name === weatherEntry.name)
    ok('canonicalization: weather raw_value JCS matches claimed value_hash',
      r !== undefined && r.passed,
      r ? (r.reason ?? '') : 'no result')
    ok('canonicalization: weather raw_value has observed_at before temp_f (JCS key order)',
      keys[0] === 'observed_at' && keys[1] === 'temp_f',
      `keys: ${keys.join(', ')}`)
  }

  process.stdout.write(`\n${passed} passed, ${failed} failed, ${pendingS11.length} pending-S1.1 (${results.length} vectors run)\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
