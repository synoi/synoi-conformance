// completeness-assertion-conformance.test.ts
//
// Language-neutral conformance proof for the signed population-completeness
// assertion (build1-completeness-witnessing, P4). Governed-path scope only: the
// assertion certifies in-scope governed-path completeness, never universal or
// unqualified completeness.
//
// What this pins (ADR_023 D3, irreversible once the first assertion's root is
// witnessed):
//   - The synoi.completeness.v1 body canonicalizes via RFC 8785 JCS (@synoi/sraid
//     canonicalize) to exactly canonical_payload. Object keys are re-sorted
//     lexicographically, so the freeze surface is field NAMES, presence/absence,
//     and value encodings (ms units, bare-hex roots), NOT source field order.
//   - assertion_id = SHA-256(canonical_payload), bare hex, and is EXCLUDED from
//     the signed bytes.
//   - The hybrid attestation carries BOTH ed25519 AND ml-dsa-65 over
//     PAE(payloadType, canonical) and binds the completeness payloadType, so it
//     verifies under that type and NOT under the GAP receipt type (SRAID F7/A4).
//   - Flipping any body field changes the canonical bytes and assertion_id, so
//     the pinned signature can never verify against a mutated body.
//
// Depends on @synoi/sraid (canonicalize, verifyAttestation) and node:crypto
// ONLY. A reimplementation reproduces canonical_payload and assertion_id from
// body alone and verifies the envelope the same way.
//
// No em dashes.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { canonicalize, verifyAttestation, type AttestationEnvelope } from '@synoi/sraid'

const GAP_RECEIPT_PAYLOAD_TYPE = 'application/vnd.synoi.gap+json'

interface SignedCase {
  name: string
  body: Record<string, unknown>
  expected: {
    canonical_payload?: string
    assertion_id?: string
    payload_type?: string
    signature_algs?: string[]
    verifies_under_completeness_type?: boolean
    verifies_under_gap_receipt_type?: boolean
    differs_from_signed_case?: boolean
  }
  envelope?: AttestationEnvelope
  ed25519_pub_b64?: string
  ml_dsa_pub_b64?: string
}
interface AssertionVector {
  kind: string
  constants: Record<string, string>
  cases: SignedCase[]
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

const vectorsPath = join(process.cwd(), 'vectors', 'completeness-assertion', 'assertion.json')
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8')) as AssertionVector

ok('completeness-assertion: loaded a non-empty case set', vector.cases.length > 0, `count=${vector.cases.length}`)
ok('completeness-assertion: schema constant is synoi.completeness.v1',
   vector.constants['schema'] === 'synoi.completeness.v1', vector.constants['schema'])
ok('completeness-assertion: payload_type constant is the frozen completeness type',
   vector.constants['payload_type'] === 'application/vnd.synoi.completeness+json', vector.constants['payload_type'])

const byName = new Map(vector.cases.map(c => [c.name, c]))

for (const c of vector.cases) {
  const canonical = canonicalize(c.body)
  const assertionId = createHash('sha256').update(canonical).digest('hex')

  if (c.expected.canonical_payload !== undefined) {
    ok(`[${c.name}] canonicalize(body) reproduces pinned canonical_payload`,
       canonical === c.expected.canonical_payload,
       `got ${canonical.slice(0, 80)}...`)
  }
  if (c.expected.assertion_id !== undefined) {
    ok(`[${c.name}] assertion_id == sha256(canonical_payload)`,
       assertionId === c.expected.assertion_id,
       `got ${assertionId} expected ${c.expected.assertion_id}`)
    ok(`[${c.name}] assertion_id is bare 64-hex`, /^[0-9a-f]{64}$/.test(c.expected.assertion_id))
  }

  // assertion_id and attestation must NOT be part of the signed bytes.
  ok(`[${c.name}] canonical body excludes assertion_id and attestation`,
     !canonical.includes('assertion_id') && !canonical.includes('attestation'))

  // The schema (KIND) must be bound INTO the signed bytes.
  ok(`[${c.name}] schema is bound into the signed bytes`,
     canonical.includes('"schema":"synoi.completeness.v1"'))

  if (c.envelope && c.ed25519_pub_b64 && c.ml_dsa_pub_b64) {
    const ed25519_pub = new Uint8Array(Buffer.from(c.ed25519_pub_b64, 'base64'))
    const ml_dsa_pub  = new Uint8Array(Buffer.from(c.ml_dsa_pub_b64, 'base64'))

    // The envelope's payload IS the canonical body bytes.
    ok(`[${c.name}] envelope.payload == canonical body`, c.envelope.payload === canonical)

    // Both hybrid signatures present.
    const algs = c.envelope.signatures.map(s => s.alg).sort()
    ok(`[${c.name}] envelope carries BOTH ed25519 AND ml-dsa-65`,
       algs.includes('ed25519') && algs.includes('ml-dsa-65'), algs.join(','))

    // Verifies under the completeness payloadType.
    const asCompleteness = verifyAttestation({
      envelope: c.envelope, ed25519_pub, ml_dsa_pub,
      expectedPayloadType: 'application/vnd.synoi.completeness+json',
    })
    ok(`[${c.name}] verifies under the completeness payloadType`,
       asCompleteness.valid === (c.expected.verifies_under_completeness_type ?? true),
       JSON.stringify(asCompleteness.reasons ?? []))

    // Does NOT verify when the payloadType pin is the GAP receipt type.
    const asReceipt = verifyAttestation({
      envelope: c.envelope, ed25519_pub, ml_dsa_pub,
      expectedPayloadType: GAP_RECEIPT_PAYLOAD_TYPE,
    })
    ok(`[${c.name}] does NOT verify under the GAP receipt payloadType (binding holds)`,
       asReceipt.valid === (c.expected.verifies_under_gap_receipt_type ?? false))

    // Tampering any body field breaks verification: re-canonicalize a mutated
    // body and confirm the pinned envelope no longer matches those bytes.
    const mutated = canonicalize({ ...c.body, unreceipted: 424242 })
    ok(`[${c.name}] a mutated body no longer matches the signed payload`,
       c.envelope.payload !== mutated)
  }
}

// Field-flip lock: the flipped case must produce DIFFERENT canonical bytes and a
// DIFFERENT assertion_id than the signed case, proving any field flip changes the
// signed bytes.
{
  const signed  = byName.get('signed_assertion_verifies')
  const flipped = byName.get('field_flip_changes_signed_bytes')
  ok('field-flip: both signed and flipped cases present', !!signed && !!flipped)
  if (signed && flipped) {
    const signedCanonical  = canonicalize(signed.body)
    const flippedCanonical = canonicalize(flipped.body)
    ok('field-flip: canonical bytes differ after a single field flip',
       signedCanonical !== flippedCanonical)
    const signedId  = createHash('sha256').update(signedCanonical).digest('hex')
    const flippedId = createHash('sha256').update(flippedCanonical).digest('hex')
    ok('field-flip: assertion_id differs after a single field flip', signedId !== flippedId)
    ok('field-flip: pinned flipped assertion_id reproduces',
       flipped.expected.assertion_id === flippedId,
       `pinned=${flipped.expected.assertion_id} computed=${flippedId}`)
  }
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
