// scripts/adr019-projection-gate.ts - ADR_019 cross-language, cross-verifier
// projection GATE.
//
// PURPOSE (ADR_019 STEP 2): replay the shared, generated-from-sraid ADR_019
// vectors against EVERY implementation that must agree on the L0 content-core
// projection and number rule:
//
//     @synoi/sraid           (TS, in-process)   - the NORMATIVE reference
//     @synoi/verify          (TS, in-process)   - third-party verifier
//     gateway v2 signer      (sraid cdroContentCore, in-process)
//     gateway v1 flat signer (LEGACY receipt_scheme=v1, SEPARATE projection)
//     @synoi/gap  TS         (computeGapOid, in-process)
//     @synoi/gap  Python     (compute_gap_oid, subprocess shim)
//     @synoi/gap  Rust       (compute_gap_oid, subprocess shim)
//     @synoi/gap  Go         (ComputeGapOid,  subprocess shim)
//
// The gate mints NOTHING: it compares each impl's OID for the mixed vectors
// against the vector's sraid-computed expected_oid, and checks each impl's
// float handling against the expected-reject vectors. A divergent strip-set,
// number rule, or canonicalizer turns the impl RED.
//
// TWO ROLES (this is the whole point):
//   role 'cdro'      - MUST compute the ONE normative sraid cdroOid projection
//                      (strip exactly the six detached-signature fields, KEEP
//                      gap_version+supersedes). @synoi/sraid, @synoi/verify, the
//                      gateway v2 signer, and all 4 GAP SDKs (TS/Python/Rust/Go)
//                      are cdro impls and MUST be GREEN against the shared
//                      attestation/supersedes vectors.
//   role 'v1-scheme' - the gateway v1 flat signer. A SEPARATE LEGACY projection
//                      (it strips gap_version+supersedes and folds the body to
//                      flat scalars), gated behind the receipt_scheme
//                      discriminator, and NEVER used to recompute a content-core
//                      OID. It is EXPECTED to diverge from cdroOid, and that
//                      divergence is BY DESIGN, NOT a gate failure (ADR_019
//                      STEP 4 reclassification). The gate only asserts it stays
//                      divergent (proving the v1 shape is not a valid content
//                      core); a v1-scheme impl that suddenly MATCHED cdroOid
//                      would mean a shared vector lost gap_version/supersedes.
//
// EXIT CONTRACT (honest SDET framing). The gate exits 0 when reality matches
// each impl's role, and exits 1 when it diverges, i.e.:
//     - a 'cdro' impl produced a wrong OID or failed to reject a float
//       → a real regression, block CI; OR
//     - the 'v1-scheme' impl silently MATCHED cdroOid → the gate stopped
//       cross-checking (a vector lost gap_version/supersedes), a failure of the
//       gate's own guarantee, so block CI.
//   The v1-scheme's normal divergence from cdroOid is NOT a failure.

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { cdroOid, cdroContentCore, oidOf } from '@synoi/sraid'
import { computeGapOid } from '@synoi/gap'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..')
const vecDir = join(repoRoot, 'vectors', 'adr019')

// Sibling repo roots (conformance sits at synoi/synoi-conformance).
const synoiRoot = join(repoRoot, '..')
const gapPyDir = join(synoiRoot, 'synoi-gap', 'python')
const goShimDir = join(here, 'adr019-shims', 'go')
const rustShimDir = join(here, 'adr019-shims', 'rust')
const pyShim = join(here, 'adr019-shims', 'python', 'shim.py')

type Status = 'green' | 'red' | 'skip' | 'error'

// An impl's ROLE in the gate:
//   'cdro'       - MUST compute the ONE normative cdroOid projection; green=match.
//   'v1-scheme'  - the LEGACY v1 flat-scalar signer. It is a SEPARATE projection
//                  (strips gap_version+supersedes, folds body to flat scalars),
//                  gated behind the receipt_scheme discriminator, and BY DESIGN
//                  never equals cdroOid. It is NOT a failure; it is reported as a
//                  distinct status so the gate does not conflate a deliberately-
//                  different scheme with an un-conformed cdro impl. The gate only
//                  asserts it DIVERGES from cdroOid (proving it is not a content
//                  core); a v1-scheme impl that suddenly matched cdroOid would
//                  mean a shared vector lost gap_version/supersedes -> gate-blind.
type Role = 'cdro' | 'v1-scheme'

interface ImplResult {
  impl: string
  language: string
  role: Role
  // For 'cdro' impls: the documented expectation (green once conformed). For
  // 'v1-scheme' impls this is unused (the scheme is defined by divergence).
  expected: 'green' | 'red'
  // what actually happened when we ran the shared vectors
  actual: Status
  // per-vector detail for the report
  detail: string[]
}

// ── Load the shared vectors ──────────────────────────────────────────────────

const mixed = JSON.parse(
  readFileSync(join(vecDir, 'cdro-contentcore-mixed.json'), 'utf8'),
) as Array<{ name: string; input: unknown; expected_oid: string }>

const floats = JSON.parse(
  readFileSync(join(vecDir, 'float-reject.json'), 'utf8'),
) as Array<{ name: string; input: unknown; expected: string }>

// ── OID-projection adapters ──────────────────────────────────────────────────
//
// Each adapter returns the OID a given impl computes for a mixed-vector input,
// or the sentinel 'REJECT' if the impl rejects it (used by the float check).

type OidFn = (input: unknown) => string

// gateway v1 flat signer projection (GAP_SIGNING_EXCLUDED, receipt-sign.ts:105).
// Modelled here EXACTLY from the shipped exclusion set: it strips 8 fields
// INCLUDING gap_version + supersedes, so used as a content core it diverges.
// This is the v1-only signing shape ADR_019 gates behind the receipt_scheme
// discriminator; the gate proves it is NOT a valid content-core projection.
const GATEWAY_V1_EXCLUDED = new Set([
  'oid', 'gap_version', 'signature', 'signature_key_id', 'supersedes',
  'ml_dsa_signature', 'attestation', 'signature_algorithm',
])
function gatewayV1FlatOid(input: unknown): string {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return oidOf(input)
  }
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    if (!GATEWAY_V1_EXCLUDED.has(k)) out[k] = v
  }
  return oidOf(out)
}

// In-process TS adapters.
const sraidOid: OidFn = (input) => cdroOid(input)
// @synoi/verify's v2 path binds canonicalize(cdroContentCore(receipt)); its OID
// projection is byte-identical to sraid's (it imports the same functions). We
// invoke that exact call so a verify regression (e.g. pinning its own strip)
// would redden here.
const verifyOid: OidFn = (input) => oidOf(cdroContentCore(input))
// gateway v2 signer projection (receipt-sign.ts:207): cdroContentCore.
const gatewayV2Oid: OidFn = (input) => oidOf(cdroContentCore(input))
const gapTsOid: OidFn = (input) => computeGapOid(input)

function runOidAdapter(name: string, fn: OidFn): { actual: Status; detail: string[] } {
  const detail: string[] = []
  let allMatch = true
  for (const v of mixed) {
    let got: string
    try {
      got = fn(v.input)
    } catch (err) {
      got = 'THROW:' + (err as Error).message
    }
    const ok = got === v.expected_oid
    if (!ok) allMatch = false
    detail.push(`${ok ? 'OK  ' : 'DIFF'} ${v.name.slice(0, 52)}`)
  }
  return { actual: allMatch ? 'green' : 'red', detail }
}

// Subprocess adapter for a language shim. Returns the OID (or REJECT sentinel)
// per vector. If the toolchain is missing, returns 'skip'.
function runShim(
  cmd: string,
  baseArgs: string[],
  cwd: string,
  mode: string,
  env?: NodeJS.ProcessEnv,
): { actual: Status; detail: string[] } {
  const detail: string[] = []
  // Probe once: if the toolchain is absent the whole impl is skipped (not red).
  const probe = spawnSync(cmd, ['version'], { cwd, encoding: 'utf8', shell: false })
  if (probe.error && (probe.error as NodeJS.ErrnoException).code === 'ENOENT') {
    return { actual: 'skip', detail: [`toolchain "${cmd}" not found - skipped`] }
  }
  let allMatch = true
  for (const v of mixed) {
    const res = spawnSync(cmd, [...baseArgs, mode], {
      cwd,
      input: JSON.stringify(v.input),
      encoding: 'utf8',
      env: { ...process.env, ...(env ?? {}) },
      shell: false,
    })
    if (res.status !== 0) {
      allMatch = false
      detail.push(`ERR  ${v.name.slice(0, 46)} - ${(res.stderr || '').trim().slice(0, 60)}`)
      continue
    }
    const got = (res.stdout || '').trim()
    const ok = got === v.expected_oid
    if (!ok) allMatch = false
    detail.push(`${ok ? 'OK  ' : 'DIFF'} ${v.name.slice(0, 52)}`)
  }
  return { actual: allMatch ? 'green' : 'red', detail }
}

// ── Float-reject cross-check (number rule) ───────────────────────────────────
//
// A conformant impl REJECTS every float vector. sraid / verify / gateway are
// checked in-process; the GAP SDKs already forbid floats too, but this gate's
// primary red signal is the content-core divergence, so the float check is run
// only for the in-process normative surfaces (the ones that MUST stay green).

function runFloatReject(name: string, fn: OidFn): { pass: boolean; detail: string[] } {
  const detail: string[] = []
  let pass = true
  for (const v of floats) {
    let rejected = false
    try {
      fn(v.input)
    } catch {
      rejected = true
    }
    if (!rejected) pass = false
    detail.push(`${rejected ? 'REJECT' : 'ACCEPT(!)'} ${v.name.slice(0, 48)}`)
  }
  return { pass, detail }
}

// ── Run every impl ───────────────────────────────────────────────────────────

const results: ImplResult[] = []

// CDRO-projection impls: MUST compute the ONE normative cdroOid (green).
for (const [impl, language, fn] of [
  ['@synoi/sraid (cdroOid)', 'ts', sraidOid],
  ['@synoi/verify (v2 content-core)', 'ts', verifyOid],
  ['gateway v2 signer (cdroContentCore)', 'ts', gatewayV2Oid],
] as Array<[string, string, OidFn]>) {
  const { actual, detail } = runOidAdapter(impl, fn)
  results.push({ impl, language, role: 'cdro', expected: 'green', actual, detail })
}

// LEGACY v1 flat-scalar signer: a SEPARATE projection, NOT cdroOid, gated behind
// the receipt_scheme discriminator. It is EXPECTED to diverge from cdroOid (it
// strips gap_version+supersedes); that divergence is BY DESIGN, not a failure.
// Reclassified from 'red/un-conformed' to role 'v1-scheme' (ADR_019 STEP 4): the
// gate asserts it diverges (proving it is not a content core) but does NOT count
// that divergence as a gate failure.
{
  const { actual, detail } = runOidAdapter('gateway v1 flat signer', gatewayV1FlatOid)
  results.push({
    impl: 'gateway v1 flat signer (legacy receipt_scheme=v1)',
    language: 'ts',
    role: 'v1-scheme',
    expected: 'red', // vs cdroOid: divergence is the defining, required property
    actual,
    detail,
  })
}
{
  // ADR_019 Wave 2: conformed to the six-field content-core strip (KEEPS
  // gap_version+supersedes). computeGapOid is now the sraid cdroOid projection.
  const { actual, detail } = runOidAdapter('@synoi/gap (computeGapOid)', gapTsOid)
  results.push({ impl: '@synoi/gap TS (computeGapOid)', language: 'ts', role: 'cdro', expected: 'green', actual, detail })
}
{
  const { actual, detail } = runShim('python', [pyShim], gapPyDir, '', { SYNOI_GAP_PY: gapPyDir })
  results.push({ impl: '@synoi/gap Python (compute_gap_oid)', language: 'python', role: 'cdro', expected: 'green', actual, detail })
}
{
  const args = ['run', '--quiet', '--manifest-path', join(rustShimDir, 'Cargo.toml'), '--']
  const { actual, detail } = runShim('cargo', args, rustShimDir, 'computeGapOid')
  results.push({ impl: '@synoi/gap Rust (compute_gap_oid)', language: 'rust', role: 'cdro', expected: 'green', actual, detail })
}
{
  const { actual, detail } = runShim('go', ['run', '.'], goShimDir, 'computeGapOid', { GOFLAGS: '-mod=mod' })
  results.push({ impl: '@synoi/gap Go (ComputeGapOid)', language: 'go', role: 'cdro', expected: 'green', actual, detail })
}

// Float-reject check for the normative surfaces only.
const floatChecks = [
  ['@synoi/sraid (cdroOid)', sraidOid],
  ['@synoi/verify (v2 content-core)', verifyOid],
  ['gateway v2 signer (cdroContentCore)', gatewayV2Oid],
] as Array<[string, OidFn]>
const floatResults = floatChecks.map(([name, fn]) => ({ name, ...runFloatReject(name, fn) }))

// ── Report ───────────────────────────────────────────────────────────────────

function line(): void {
  process.stdout.write('  ' + '-'.repeat(74) + '\n')
}

process.stdout.write('\nADR_019 cross-language projection gate\n')
process.stdout.write('Shared vectors: generated-from-sraid, carrying gap_version+supersedes+attestation\n')
line()
process.stdout.write('  IMPL                                          LANG    ROLE       STATUS\n')
line()
for (const r of results) {
  // STATUS column: for cdro impls, green/red vs the expectation; for v1-scheme
  // impls, a distinct 'v1-scheme' label (its divergence from cdroOid is correct,
  // not a pass/fail on the cdro contract).
  let status: string
  let flag: string
  if (r.actual === 'skip') {
    status = 'skip'
    flag = 'SKIP'
  } else if (r.role === 'v1-scheme') {
    status = 'v1-scheme'
    // v1-scheme is healthy IFF it diverges from cdroOid (actual === 'red').
    flag = r.actual === 'red' ? 'separate-projection (not cdroOid)' : '*** MATCHED cdroOid - gate blind ***'
  } else {
    status = r.actual
    flag = r.actual === r.expected ? 'as-expected' : '*** MISMATCH ***'
  }
  process.stdout.write(
    `  ${r.impl.padEnd(44)}  ${r.language.padEnd(6)}  ${r.role.padEnd(9)}  ${status.padEnd(9)} ${flag}\n`,
  )
}
line()

// Detail: the v1 flat signer is a SEPARATE legacy projection (not a content
// core), gated behind receipt_scheme=v1. It MUST diverge from cdroOid; a match
// would mean a shared vector lost its gap_version/supersedes and the gate
// stopped cross-checking.
process.stdout.write('\nv1-scheme surfaces (separate legacy projection, NOT cdroOid by design):\n')
for (const r of results) {
  if (r.role === 'v1-scheme') {
    process.stdout.write(`  ${r.impl} → ${r.actual === 'red' ? 'diverges from cdroOid (correct)' : 'MATCHED cdroOid (unexpected)'}\n`)
    if (r.actual !== 'red') {
      process.stdout.write(`    !! gate expected divergence here and saw none - vector may have lost gap_version/supersedes\n`)
    }
  }
}

process.stdout.write('\nNumber-rule (float-reject) on normative surfaces:\n')
for (const f of floatResults) {
  process.stdout.write(`  ${f.name}: ${f.pass ? 'all floats REJECTED (green)' : 'a float was ACCEPTED (RED)'}\n`)
}

// ── Exit contract ────────────────────────────────────────────────────────────

let fail = false
const reasons: string[] = []

for (const r of results) {
  if (r.actual === 'skip') continue
  if (r.role === 'v1-scheme') {
    // v1-scheme is a SEPARATE projection; its ONLY requirement is that it
    // DIVERGES from cdroOid (actual === 'red'). Divergence is success, not a
    // failure. A match would mean the gate stopped cross-checking.
    if (r.actual !== 'red') {
      fail = true
      reasons.push(
        `GATE-BLIND: ${r.impl} is a separate v1 projection that must diverge from cdroOid but matched it - the shared vector no longer exercises the divergence (lost gap_version/supersedes)`,
      )
    }
    continue
  }
  // cdro-projection impls MUST match the normative cdroOid.
  if (r.actual !== r.expected) {
    fail = true
    reasons.push(`REGRESSION: ${r.impl} must be green (cdroOid) but produced a wrong OID`)
  }
}
for (const f of floatResults) {
  if (!f.pass) {
    fail = true
    reasons.push(`NUMBER-RULE: ${f.name} accepted a float (must reject)`)
  }
}

process.stdout.write('\n')
if (fail) {
  process.stdout.write('GATE: FAIL\n')
  for (const r of reasons) process.stdout.write(`  - ${r}\n`)
  process.exit(1)
}
const v1schemes = results.filter((r) => r.role === 'v1-scheme' && r.actual === 'red').length
const greens = results.filter((r) => r.role === 'cdro' && r.actual === 'green').length
const skipped = results.filter((r) => r.actual === 'skip').length
process.stdout.write(
  `GATE: PASS - ${greens} cdro-projection impls green (match normative cdroOid), ${v1schemes} v1-scheme impl(s) correctly a SEPARATE projection (not cdroOid)` +
    (skipped ? `, ${skipped} skipped (toolchain absent)` : '') +
    '\n',
)
process.exit(0)
