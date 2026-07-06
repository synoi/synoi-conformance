// test/adr019-projection-conformance.test.ts - execute the ADR_019
// generated-from-sraid projection vectors against the reference @synoi/sraid
// and the third-party @synoi/verify verifier. This proves the vectors are
// EXECUTABLE (not just data) and that the two normative-surface invariants
// hold byte-for-byte:
//
//   1. Mixed vector (cdro-contentcore-mixed.json): cdroContentCore
//      strips exactly the six detached fields, KEEPS gap_version+supersedes,
//      and yields the vector's expected_oid; the pre-attestation and
//      post-attestation objects share ONE OID (the keystone invariant).
//   2. receipt-v2-supersedes (receipt-v2-supersedes.json): a receipt
//      carrying gap_version+supersedes verifies TRUE through @synoi/verify
//      verifyReceiptV2, and a post-signing tamper of supersedes/gap_version is
//      REJECTED (payload-core-mismatch) - proving those fields are inside the
//      signed content core.
//   3. float-reject (float-reject.json): every float-bearing input is
//      rejected by the sraid canonicalizer before hashing (ADR_019 number rule).
//
// This is the "reference impl is conformant to its own ADR_019 vectors" smoke
// test; the cross-LANGUAGE gate (scripts/adr019-projection-gate.ts) additionally
// replays them against the GAP SDKs and reports the un-conformed ones RED.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  cdroOid,
  cdroContentCore,
  canonicalize,
  oidOf,
  CDRO_ENVELOPE_FIELDS,
} from '@synoi/sraid'
import { verifyReceiptV2 } from '@synoi/verify'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++
    process.stdout.write(`OK   ${label}\n`)
  } else {
    failed++
    process.stdout.write(`FAIL ${label}${detail ? ' - ' + detail : ''}\n`)
  }
}

const vecDir = join(process.cwd(), 'vectors', 'adr019')

// ── 1. Mixed content-core vectors ────────────────────────────────────────────

interface MixedVector {
  name: string
  input: Record<string, unknown>
  expected_content_core: string
  expected_oid: string
  detached_fields?: string[]
  identity_fields_present?: string[]
  equals_oid_of?: string
  must_differ_from_oid?: string
  keystone?: boolean
}

const mixed = JSON.parse(
  readFileSync(join(vecDir, 'cdro-contentcore-mixed.json'), 'utf8'),
) as MixedVector[]

const byName = new Map(mixed.map((v) => [v.name, v]))

for (const v of mixed) {
  // The reference canonical content core must equal the vector's expected bytes.
  const core = canonicalize(cdroContentCore(v.input))
  ok(`mixed[${v.name.slice(0, 40)}]: content core bytes match`, core === v.expected_content_core,
    `got ${core.slice(0, 60)}…`)
  // The reference OID must equal the vector's expected OID.
  const oid = cdroOid(v.input)
  ok(`mixed[${v.name.slice(0, 40)}]: OID matches`, oid === v.expected_oid, `${oid} vs ${v.expected_oid}`)
  // cdroOid === oidOf(cdroContentCore) (the round-trip identity).
  ok(`mixed[${v.name.slice(0, 40)}]: cdroOid === oidOf(core)`, oid === oidOf(cdroContentCore(v.input)))

  if (v.detached_fields) {
    // Every declared detached field must be absent from the content core, and
    // must exactly equal the frozen normative set.
    const coreObj = cdroContentCore(v.input)
    for (const f of v.detached_fields) {
      ok(`mixed[${v.name.slice(0, 30)}]: detached "${f}" stripped`, !(f in coreObj))
    }
    ok(
      `mixed[${v.name.slice(0, 30)}]: detached set === CDRO_ENVELOPE_FIELDS`,
      JSON.stringify([...v.detached_fields].sort()) ===
        JSON.stringify([...CDRO_ENVELOPE_FIELDS].sort()),
    )
  }
  if (v.identity_fields_present) {
    const coreObj = cdroContentCore(v.input)
    for (const f of v.identity_fields_present) {
      ok(`mixed[${v.name.slice(0, 30)}]: identity field "${f}" kept`, f in coreObj)
    }
  }
  if (v.equals_oid_of) {
    const other = byName.get(v.equals_oid_of)
    ok(
      `mixed[keystone]: OID equals pre-attestation OID (pre/post identity)`,
      other !== undefined && cdroOid(v.input) === other.expected_oid,
    )
  }
  if (v.must_differ_from_oid) {
    ok(
      `mixed[${v.name.slice(0, 40)}]: OID differs from base (field IS in identity)`,
      cdroOid(v.input) !== v.must_differ_from_oid,
    )
  }
}

// Explicit keystone assertion: the mixed vector carrying ALL six detached
// fields must project to the SAME OID as the bare object.
{
  const pre = mixed.find((v) => v.name.includes('pre-attestation'))!
  const post = mixed.find((v) => v.keystone === true)!
  ok(
    'KEYSTONE: post-attestation (all detached fields present) OID === pre-attestation OID',
    cdroOid(pre.input) === cdroOid(post.input),
    `${cdroOid(pre.input)} vs ${cdroOid(post.input)}`,
  )
  // And the post object really does carry every detached field (so the strip is
  // exercised, not vacuous).
  for (const f of CDRO_ENVELOPE_FIELDS) {
    ok(`KEYSTONE: post object carries detached field "${f}"`, f in post.input)
  }
}

// ── 2. receipt-v2 carrying gap_version+supersedes ────────────────────────────

interface ReceiptVector {
  name: string
  mode?: string
  receipt: Record<string, unknown>
  expected_content_core?: string
  expected_oid?: string
  ed25519_pub_b64?: string
  ml_dsa_pub_b64?: string
  expected_valid?: boolean
  expected_reason?: string
}

const receipts = JSON.parse(
  readFileSync(join(vecDir, 'receipt-v2-supersedes.json'), 'utf8'),
) as ReceiptVector[]

const b64ToBytes = (b64: string): Uint8Array => Uint8Array.from(Buffer.from(b64, 'base64'))

for (const v of receipts) {
  if (v.mode === 'canonical') {
    // The signed content core INCLUDES gap_version + supersedes.
    const core = canonicalize(cdroContentCore(v.receipt))
    ok(`receipt-v2[canonical]: core includes gap_version`, core.includes('"gap_version"'))
    ok(`receipt-v2[canonical]: core includes supersedes`, core.includes('"supersedes"'))
    ok(`receipt-v2[canonical]: core bytes match`, core === v.expected_content_core)
    ok(`receipt-v2[canonical]: OID matches`, cdroOid(v.receipt) === v.expected_oid)
    continue
  }
  // Crypto vectors: run through the REAL @synoi/verify verifyReceiptV2.
  const res = await verifyReceiptV2({
    receipt: v.receipt as Parameters<typeof verifyReceiptV2>[0]['receipt'],
    ed25519_pub: b64ToBytes(v.ed25519_pub_b64!),
    ml_dsa_pub: b64ToBytes(v.ml_dsa_pub_b64!),
  })
  ok(
    `receipt-v2[${v.name.slice(0, 44)}]: valid === ${v.expected_valid}`,
    res.valid === v.expected_valid,
    `got valid=${res.valid} reasons=${JSON.stringify(res.reasons)}`,
  )
  if (v.expected_reason !== undefined) {
    ok(
      `receipt-v2[${v.name.slice(0, 40)}]: reason includes "${v.expected_reason}"`,
      res.reasons.some((r) => r.includes(v.expected_reason!)),
      `reasons=${JSON.stringify(res.reasons)}`,
    )
  }
}

// ── 3. float-reject vectors (number rule) ────────────────────────────────────

interface FloatVector {
  name: string
  input: unknown
  expected: string
}

const floats = JSON.parse(
  readFileSync(join(vecDir, 'float-reject.json'), 'utf8'),
) as FloatVector[]

for (const v of floats) {
  let rejected = false
  try {
    cdroOid(v.input)
  } catch {
    rejected = true
  }
  ok(`float-reject[${v.name.slice(0, 44)}]: rejected before hashing`, rejected && v.expected === 'reject')
}

// ── Done ─────────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
