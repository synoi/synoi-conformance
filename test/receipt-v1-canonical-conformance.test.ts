// receipt-v1-canonical-conformance.test.ts
//
// CROSS-PACKAGE byte-for-byte proof that the v1 Decision Receipt canonical form
// is ONE canonical truth across the signer and the offline verifier:
//
//   For every vector in vectors/receipt-v1/canonical.json:
//     (A) @synoi/verify   canonicalPayload(receipt)                 === expected_canonical
//     (B) @synoi/sraid     canonicalize(scalar projection of receipt) === expected_canonical
//
// (A) is the offline verifier third parties run; (B) is the signer's canonical
// truth. If they ever diverge, a valid receipt would verify as INVALID (or
// vice-versa). This test fails loudly on any drift. A reimplementation in any
// language proves agreement by reproducing expected_canonical from `receipt`.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { canonicalPayload } from '@synoi/verify'
import { canonicalize } from '@synoi/sraid'

interface V1Vector {
  name: string
  kind: string
  canonical_fields: string[]
  optional_canonical_fields: string[]
  receipt: Record<string, unknown>
  expected_canonical: string
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' - ' + detail : ''}\n`) }
}

const vectorsPath = join(process.cwd(), 'vectors', 'receipt-v1', 'canonical.json')
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as V1Vector[]

ok('receipt-v1-canonical: loaded a non-empty vector set', vectors.length > 0,
   `count=${vectors.length}`)

// Build the sorted scalar projection the signer canonicalizes.
function scalarProjection(v: V1Vector): Record<string, unknown> {
  const fields = [...v.canonical_fields, ...v.optional_canonical_fields].sort()
  const obj: Record<string, unknown> = {}
  for (const k of fields) {
    const val = v.receipt[k]
    if (val !== undefined && val !== null) obj[k] = val
  }
  return obj
}

for (const v of vectors) {
  // (A) The offline verifier reproduces the pinned canonical bytes.
  let got: string | undefined
  try { got = canonicalPayload(v.receipt) } catch (err) {
    ok(`[A] @synoi/verify canonicalPayload: ${v.name}`, false,
       'threw: ' + (err as Error).message)
    continue
  }
  ok(`[A] @synoi/verify canonicalPayload == expected: ${v.name}`,
     got === v.expected_canonical,
     `got=${JSON.stringify(got)} expected=${JSON.stringify(v.expected_canonical)}`)

  // (B) The signer canonicalizer reproduces the same bytes.
  const sraidBytes = canonicalize(scalarProjection(v))
  ok(`[B] @synoi/sraid canonicalize == expected: ${v.name}`,
     sraidBytes === v.expected_canonical,
     `got=${JSON.stringify(sraidBytes)} expected=${JSON.stringify(v.expected_canonical)}`)

  // (A) === (B): the offline verifier and the signer agree byte-for-byte.
  ok(`[A==B] verify.ts and signer agree byte-for-byte: ${v.name}`,
     got === sraidBytes)
}

// Coverage sanity: the M2 edge cases must actually be present in the fixture.
ok('covers a unicode vector', vectors.some((v) => v.name.includes('unicode')))
ok('covers a large-int vector', vectors.some((v) => v.name.includes('large_int')))
ok('covers a manifest vector', vectors.some((v) => v.name.includes('manifest')))

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
