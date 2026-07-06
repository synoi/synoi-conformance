// replay-chain-conformance.test.ts
//
// Conformance gate for C9 (2-receipt replay chain).
//
// Vectors live at: vectors/replay-chain.json
// Kinds:
//   replay_chain_pair  -- verifies the D1+E1 pair structure (fields, Merkle edge, status)
//   replay_chain_gate  -- verifies gate rejection rules (cross-principal, window, HITL signal)
//
// These vectors are self-contained (no external impl required): the runner validates
// the structural invariants declared in each vector's assertions block and
// notes the expected_error_kind for rejection vectors.

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++
    process.stdout.write(`OK   ${label}\n`)
  } else {
    failed++
    process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`)
  }
}

interface ReplayChainVector {
  name: string
  kind: string
  expect: string
  expected_error_kind?: string
  expected_error_detail?: string
  d1?: Record<string, unknown>
  e1?: Record<string, unknown>
  assertions?: Array<{ field: string; op: string; value: unknown; note: string }>
  denial_principal?: string
  replay_principal?: string
  d1_oid?: string
  d1_age_ms_over_window?: number
  window_ms?: number
  hitl_approval_signal_oid?: string
}

function loadVectors(): ReplayChainVector[] {
  const path = join(process.cwd(), 'vectors', 'replay-chain.json')
  ok('replay-chain: vectors file exists', existsSync(path), path)
  if (!existsSync(path)) return []
  const raw = readFileSync(path, 'utf8')
  const parsed = JSON.parse(raw) as unknown
  ok('replay-chain: file parses as JSON array', Array.isArray(parsed))
  return Array.isArray(parsed) ? (parsed as ReplayChainVector[]) : []
}

function get(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.')
  let cur: unknown = obj
  for (const part of parts) {
    if (cur === null || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[part]
  }
  return cur
}

function runPairVector(v: ReplayChainVector): void {
  const label = v.name
  const expectValid = v.expect === 'valid'
  const expectInvalid = v.expect === 'invalid'

  if (!v.d1 || !v.e1) {
    ok(`${label}: d1 and e1 present`, false, 'missing d1 or e1')
    return
  }

  const d1 = v.d1 as Record<string, unknown>
  const e1 = v.e1 as Record<string, unknown>

  if (expectValid) {
    // Structural checks for valid pair.
    const d1oid = String(d1['oid'] ?? '')
    const e1ReplayedAfter = get(e1, 'body.replayed_after')
    const e1Prev = e1['prev']
    const e1AuthSubjectOid = get(e1, 'body.authority.subject_oid')
    const d1Status = get(d1, 'body.status')
    const e1Status = get(e1, 'body.status')

    ok(`${label}: D1.oid is a sha256: OID`,
      d1oid.startsWith('sha256:') && d1oid.length === 71)
    ok(`${label}: D1.body.status === 'denied'`,
      d1Status === 'denied',
      `got ${String(d1Status)}`)
    ok(`${label}: E1.body.status === 'ok'`,
      e1Status === 'ok',
      `got ${String(e1Status)}`)
    ok(`${label}: E1.body.replayed_after === D1.oid`,
      e1ReplayedAfter === d1oid,
      `replayed_after=${String(e1ReplayedAfter)} d1oid=${d1oid}`)
    ok(`${label}: E1.prev === D1.oid (Merkle parent)`,
      e1Prev === d1oid,
      `prev=${String(e1Prev)} d1oid=${d1oid}`)
    ok(`${label}: E1.prev === E1.body.replayed_after (invariant)`,
      e1Prev === e1ReplayedAfter,
      `prev=${String(e1Prev)} replayed_after=${String(e1ReplayedAfter)}`)
    if (e1AuthSubjectOid !== undefined) {
      ok(`${label}: E1.body.authority.subject_oid === D1.oid`,
        e1AuthSubjectOid === d1oid,
        `authority.subject_oid=${String(e1AuthSubjectOid)}`)
    }

  } else if (expectInvalid) {
    const kind = v.expected_error_kind ?? ''
    // Structurally verify the vector matches the expected broken condition.
    if (kind === 'merkle_edge_mismatch') {
      const e1ReplayedAfter = get(e1, 'body.replayed_after')
      const e1Prev = e1['prev']
      ok(`${label}: E1.prev !== E1.body.replayed_after (broken Merkle edge present)`,
        e1Prev !== e1ReplayedAfter,
        `prev=${String(e1Prev)} replayed_after=${String(e1ReplayedAfter)}`)
    } else if (kind === 'missing_replayed_after') {
      const e1ReplayedAfter = get(e1, 'body.replayed_after')
      ok(`${label}: E1.body.replayed_after is absent (chain-length-1 gap present)`,
        e1ReplayedAfter === undefined,
        `replayed_after=${String(e1ReplayedAfter)}`)
    } else if (kind === 'replayed_after_not_found') {
      const d1oid = String(d1['oid'] ?? '')
      const e1ReplayedAfter = get(e1, 'body.replayed_after')
      const e1Prev = e1['prev']
      ok(`${label}: E1.body.replayed_after does not equal D1.oid (tampered)`,
        e1ReplayedAfter !== d1oid,
        `replayed_after=${String(e1ReplayedAfter)} d1oid=${d1oid}`)
      // Verify that prev also equals the random OID (not D1), consistent tamper.
      ok(`${label}: E1.prev equals the tampered OID (consistent tamper)`,
        e1Prev === e1ReplayedAfter,
        `prev=${String(e1Prev)} replayed_after=${String(e1ReplayedAfter)}`)
    } else {
      ok(`${label}: invalid pair vector has known expected_error_kind`,
        kind !== '',
        'expected_error_kind missing or empty')
    }
  }
}

function runGateVector(v: ReplayChainVector): void {
  const label = v.name
  const kind = v.expected_error_kind ?? ''

  ok(`${label}: expected_error_kind present`, kind !== '', 'gate vector missing expected_error_kind')

  if (kind === 'cross_principal_mismatch') {
    ok(`${label}: denial_principal and replay_principal are different`,
      v.denial_principal !== v.replay_principal &&
      typeof v.denial_principal === 'string' &&
      typeof v.replay_principal === 'string',
      `denial=${v.denial_principal} replay=${v.replay_principal}`)
    ok(`${label}: d1_oid present`, typeof v.d1_oid === 'string' && (v.d1_oid ?? '').startsWith('sha256:'))
  } else if (kind === 'provisional_window_expired') {
    ok(`${label}: d1_age_ms_over_window > 0`,
      typeof v.d1_age_ms_over_window === 'number' && (v.d1_age_ms_over_window ?? 0) > 0,
      `d1_age_ms_over_window=${String(v.d1_age_ms_over_window)}`)
    ok(`${label}: window_ms matches 72hr (259200000)`,
      v.window_ms === 259200000,
      `window_ms=${String(v.window_ms)}`)
  } else if (kind === 'hitl_signal_missing') {
    // The vector itself has no hitl_approval_signal_oid field (or it is empty).
    const sig = v.hitl_approval_signal_oid
    ok(`${label}: hitl_approval_signal_oid absent or empty (trigger condition)`,
      sig === undefined || sig === '',
      `hitl_approval_signal_oid=${String(sig)}`)
  } else {
    ok(`${label}: gate vector kind '${kind}' is a known gate error`,
      ['cross_principal_mismatch', 'provisional_window_expired', 'hitl_signal_missing'].includes(kind),
      `unknown kind: ${kind}`)
  }
}

async function main(): Promise<void> {
  const vectors = loadVectors()

  const pairVectors = vectors.filter(v => v.kind === 'replay_chain_pair')
  const gateVectors = vectors.filter(v => v.kind === 'replay_chain_gate')

  ok('replay-chain: at least 5 vectors loaded', vectors.length >= 5, `loaded ${vectors.length}`)
  ok('replay-chain: at least 1 valid pair vector', pairVectors.filter(v => v.expect === 'valid').length >= 1)
  ok('replay-chain: at least 2 invalid pair vectors (broken Merkle, tampered OID, missing replayed_after)',
    pairVectors.filter(v => v.expect === 'invalid').length >= 2,
    `found ${pairVectors.filter(v => v.expect === 'invalid').length}`)
  ok('replay-chain: at least 3 gate rejection vectors',
    gateVectors.length >= 3,
    `found ${gateVectors.length}`)
  ok('replay-chain: missing_replayed_after vector present',
    pairVectors.some(v => v.expected_error_kind === 'missing_replayed_after'))
  ok('replay-chain: replayed_after_not_found vector present',
    pairVectors.some(v => v.expected_error_kind === 'replayed_after_not_found'))

  process.stdout.write('\n--- Pair vectors ---\n')
  for (const v of pairVectors) runPairVector(v)

  process.stdout.write('\n--- Gate vectors ---\n')
  for (const v of gateVectors) runGateVector(v)

  process.stdout.write(`\n${passed} passed, ${failed} failed (${vectors.length} vectors)\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
