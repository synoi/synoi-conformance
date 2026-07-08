// verify-chain.ts
//
// Standalone OFFLINE chain-walk verifier. Imports the SHIPPED
// @synoi/verify-core bundle verifier (verifyEvidenceBundle) -- not a
// reimplementation -- and runs it against R1 (Runtime A, game) + R2
// (Runtime B, work) assembled into one evidence bundle. Asserts:
//
//   1. The bundle verifies (both Ed25519 AND ML-DSA-65, AND-enforced, for
//      EACH receipt, under each receipt's OWN signer key).
//   2. R2.prev === R1.oid, i.e. the two receipts form ONE linked chain
//      across the game/work environment boundary, not two unrelated
//      objects that happen to sit in the same file.
//   3. A tamper test: flip one byte in R1's signed payload and show the
//      bundle now FAILS to verify (content-digest AND receipt signature
//      both break).
//
// No gateway process is required or contacted. This script only reads JSON
// files from ./out and calls the open @synoi/verify-core library.
//
// Run: npx tsx verify-chain.ts
//
// NO em dashes. NO AI attribution.

import { readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  verifyEvidenceBundle,
  bundleContentDigestPreimage,
  EVIDENCE_BUNDLE_VERSION,
  type EvidenceBundle,
  type PublicKeyBundle,
} from '../../../synoi-verify-core/dist/index.js'
import { canonicalize } from '@synoi/sraid'
import { createHash } from 'node:crypto'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, 'out')

function readJson<T>(name: string): T {
  return JSON.parse(readFileSync(join(outDir, name), 'utf8')) as T
}

const r1 = readJson<Record<string, unknown>>('r1.json')
const r2 = readJson<Record<string, unknown>>('r2.json')
const keyA = readJson<PublicKeyBundle>('runtime-a-keys.pub.json')
const keyB = readJson<PublicKeyBundle>('runtime-b-keys.pub.json')

const TENANT_ID = 'demo-fabric-crossenv'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++
    process.stdout.write(`PASS  ${label}\n`)
  } else {
    failed++
    process.stdout.write(`FAIL  ${label}${detail ? '  -- ' + detail : ''}\n`)
  }
}

function buildBundle(receipts: Record<string, unknown>[]): EvidenceBundle {
  const base = {
    bundle_version: EVIDENCE_BUNDLE_VERSION,
    generated_at_ms: Date.now(),
    tenant_id: TENANT_ID,
    filter: { demo: 'fabric-crossenv' },
    receipts,
    absence_statements: [],
    key_history: [keyA, keyB],
    honesty: {
      tamper_evident: true,
      independently_verifiable_offline: true,
      court_admissible: false,
      regulator_accepted: false,
      truncated: false,
      body_filtered_omission: false,
      note:
        'minimal proof bundle: two independent non-gateway runtimes, one operator identity, ' +
        'not a production evidence export, not legal or regulatory evidence',
    },
  }
  const preimage = bundleContentDigestPreimage({
    bundle_version: base.bundle_version,
    tenant_id: base.tenant_id,
    receipt_count: receipts.length,
    absence_count: 0,
    truncated: base.honesty.truncated,
    body_filtered_omission: base.honesty.body_filtered_omission,
    filter: base.filter,
    receipts: base.receipts,
    absence_statements: base.absence_statements,
  })
  const digest = 'sha256:' + createHash('sha256').update(canonicalize(preimage), 'utf8').digest('hex')
  const manifest = {
    receipt_count: receipts.length,
    absence_count: 0,
    content_digest: digest,
  }
  return { ...base, manifest } as EvidenceBundle
}

process.stdout.write('=== fabric-crossenv: cross-environment, cross-implementation chain verify ===\n\n')
process.stdout.write(`R1 (game, Runtime A) oid = ${String(r1.oid)}\n`)
process.stdout.write(`R2 (work, Runtime B) oid = ${String(r2.oid)}\n`)
process.stdout.write(`R2.prev                  = ${String((r2 as { prev?: unknown }).prev)}\n\n`)

// ── 1 + 2: positive chain verify ────────────────────────────────────────────
const bundle = buildBundle([r1, r2])
const result = verifyEvidenceBundle(bundle)

ok('bundle-valid', result.valid, JSON.stringify(result.reasons))
ok(
  'r1-verifies-both-algs',
  result.receipt_results[0]?.valid === true &&
    result.receipt_results[0]?.ed25519_valid === true &&
    result.receipt_results[0]?.ml_dsa_valid === true,
  JSON.stringify(result.receipt_results[0]),
)
ok(
  'r2-verifies-both-algs',
  result.receipt_results[1]?.valid === true &&
    result.receipt_results[1]?.ed25519_valid === true &&
    result.receipt_results[1]?.ml_dsa_valid === true,
  JSON.stringify(result.receipt_results[1]),
)
ok(
  'r1-and-r2-different-signer-keys',
  result.receipt_results[0]?.verifying_key_id === keyA.key_id &&
    result.receipt_results[1]?.verifying_key_id === keyB.key_id,
  `r1_key=${result.receipt_results[0]?.verifying_key_id} r2_key=${result.receipt_results[1]?.verifying_key_id}`,
)
ok(
  'chain-linked-r2-prev-equals-r1-oid',
  (r2 as { prev?: unknown }).prev === r1.oid,
  `r2.prev=${String((r2 as { prev?: unknown }).prev)} r1.oid=${String(r1.oid)}`,
)
ok(
  'chain-crosses-game-and-work-environments',
  (r1 as { body?: { environment?: unknown } }).body?.environment === 'game' &&
    (r2 as { body?: { environment?: unknown } }).body?.environment === 'work',
  `r1.env=${(r1 as { body?: { environment?: unknown } }).body?.environment} r2.env=${(r2 as { body?: { environment?: unknown } }).body?.environment}`,
)

process.stdout.write('\n')

// ── 3: tamper test. Flip one byte in R1's signed canonical payload. ────────
const tamperedR1 = JSON.parse(JSON.stringify(r1)) as Record<string, unknown>
const att = tamperedR1.attestation as { payload?: unknown }
const origPayload = String(att.payload)
att.payload = origPayload.slice(0, 1) === '{' ? '}' + origPayload.slice(1) : origPayload.slice(0, -1) + '_'

const tamperedBundle = buildBundle([tamperedR1, r2])
const tamperedResult = verifyEvidenceBundle(tamperedBundle)

ok(
  'tamper-r1-payload-byte-flip-rejected',
  !tamperedResult.valid,
  `valid=${tamperedResult.valid} reasons=${JSON.stringify(tamperedResult.reasons)}`,
)
ok(
  'tamper-r1-signature-invalid-not-vacuously-skipped',
  tamperedResult.receipt_results[0]?.valid === false,
  JSON.stringify(tamperedResult.receipt_results[0]),
)

// Second tamper vector: flip one byte in the OTHER receipt's OID field
// directly (not just the attestation payload), to show the payload-binding
// re-derivation (cdroContentCore recompute) catches a body edit too.
const tamperedR2 = JSON.parse(JSON.stringify(r2)) as Record<string, unknown>
const body = tamperedR2.body as { amount_minor_units?: number; environment?: string }
body.environment = 'game' // flip work -> game post-signing, without re-signing
const tamperedBundle2 = buildBundle([r1, tamperedR2])
const tamperedResult2 = verifyEvidenceBundle(tamperedBundle2)
ok(
  'tamper-r2-body-field-edit-without-resign-rejected',
  !tamperedResult2.valid && tamperedResult2.receipt_results[1]?.valid === false,
  `valid=${tamperedResult2.valid} r2=${JSON.stringify(tamperedResult2.receipt_results[1])}`,
)

process.stdout.write(`\n--- ${passed} passed, ${failed} failed ---\n`)

writeFileSync(
  join(outDir, 'receipts.json'),
  JSON.stringify({ OID_op: readJson<{ oid: string }>('operator-identity.json').oid, r1, r2 }, null, 2) + '\n',
)

if (failed > 0) process.exit(1)
