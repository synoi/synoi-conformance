// perimeter-conformance.test.ts
//
// Language-neutral conformance proof for the signed perimeter declaration
// (`synoi.perimeter.v1`), the scope statement a completeness assertion is
// complete WITHIN.
//
// WHY THIS ONE MATTERS PARTICULARLY. Every other object in this suite proves
// something happened. This one states what the record COVERS, so if a third
// party cannot check it offline then the completeness claim reduces to "trust
// the party being audited", which is the position the whole product exists to
// escape. That makes the honesty properties, not just the crypto, part of
// conformance.
//
// What this pins:
//   - The declaration canonicalizes via RFC 8785 JCS over the CDRO content
//     core (the envelope minus the six detached fields) to exactly
//     canonical_payload.
//   - oid = 'sha256:' + SHA-256(canonical_payload). The perimeter object hashes
//     the SAME core it signs, so the OID is re-derivable from the signature
//     payload a verifier already holds. A forged OID is caught even though the
//     OID is not covered by the signature, which matters because `prev` chains
//     by OID and a forged OID forges chain position.
//   - The hybrid attestation carries BOTH ed25519 AND ml-dsa-65 over
//     PAE(payloadType, canonical) and binds the perimeter payloadType, so it
//     verifies under that type and NOT under the GAP receipt type (SRAID F7/A4).
//   - The enforcement ceiling: a chokepoint may claim WEAKER enforcement than
//     its class allows, never stronger. "C7, structural" is rejected by the
//     shared validator, signed or not.
//   - `prev` chaining across two declarations.
//   - Dropping a blind spot, the highest-value tamper against this object,
//     breaks both the OID and the payload binding.
//
// Depends on @synoi/sraid, @synoi/gap, and node:crypto only.
//
// No em dashes.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { canonicalize, cdroContentCore, verifyAttestation, type AttestationEnvelope } from '@synoi/sraid'
import {
  classifySurface,
  renderPerimeterDeclaration,
  validatePerimeterDeclaration,
  verifyPerimeterChain,
} from '@synoi/gap'

const GAP_RECEIPT_PAYLOAD_TYPE = 'application/vnd.synoi.gap+json'

interface Case {
  name: string
  declaration: Record<string, unknown>
  expected: Record<string, unknown>
}
interface PerimeterVector {
  kind: string
  constants: Record<string, string>
  ed25519_pub_b64: string
  ml_dsa_pub_b64: string
  cases: Case[]
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

const vector = JSON.parse(
  readFileSync(join(process.cwd(), 'vectors', 'perimeter', 'declaration.json'), 'utf8'),
) as PerimeterVector

const edPub = new Uint8Array(Buffer.from(vector.ed25519_pub_b64, 'base64'))
const mlPub = new Uint8Array(Buffer.from(vector.ml_dsa_pub_b64, 'base64'))

function canonicalOf(decl: Record<string, unknown>): string {
  return canonicalize(cdroContentCore(decl))
}
function oidOf(canonical: string): string {
  return 'sha256:' + createHash('sha256').update(canonical, 'utf8').digest('hex')
}
function byName(name: string): Case {
  const c = vector.cases.find(x => x.name === name)
  if (!c) { throw new Error(`vector case missing: ${name}`) }
  return c
}

// ── Constants ───────────────────────────────────────────────────────────────

ok('vector: kind is perimeter_declaration_v1', vector.kind === 'perimeter_declaration_v1')
ok('vector: schema constant is synoi.perimeter.v1',
  vector.constants['schema'] === 'synoi.perimeter.v1')
ok('vector: object type is gap:perimeter_declaration',
  vector.constants['object_type'] === 'gap:perimeter_declaration')
ok('vector: payloadType is the perimeter type, not the receipt type',
  vector.constants['payload_type'] === 'application/vnd.synoi.perimeter+json')
ok('vector: records the binding direction',
  (vector.constants['binding_direction'] ?? '').includes('references NEITHER'),
  'completeness must not reference perimeter, or its frozen canonical bytes change')

// ── Case 1: the genesis declaration ─────────────────────────────────────────

{
  const c = byName('genesis_declaration_verifies')
  const decl = c.declaration
  const canonical = canonicalOf(decl)

  ok('genesis: canonical bytes reproduce from the declaration alone',
    canonical === c.expected['canonical_payload'])
  ok('genesis: oid is the sha256 of those same bytes',
    oidOf(canonical) === decl['oid'] && decl['oid'] === c.expected['oid'])

  const shape = validatePerimeterDeclaration(decl)
  ok('genesis: validates against the shared validator', shape.ok, shape.errors.join('; '))

  const att = decl['attestation'] as AttestationEnvelope
  ok('genesis: the attestation payload is the canonical bytes', att.payload === canonical)
  ok('genesis: both algs are present',
    att.signatures.length === 2 &&
    att.signatures.some(s => s.alg === 'ed25519') &&
    att.signatures.some(s => s.alg === 'ml-dsa-65'))

  const good = verifyAttestation({
    envelope: att, ed25519_pub: edPub, ml_dsa_pub: mlPub,
    expectedPayloadType: 'application/vnd.synoi.perimeter+json',
  })
  ok('genesis: verifies under the perimeter payloadType', good.valid)

  const crossType = verifyAttestation({
    envelope: att, ed25519_pub: edPub, ml_dsa_pub: mlPub,
    expectedPayloadType: GAP_RECEIPT_PAYLOAD_TYPE,
  })
  ok('genesis: does NOT verify under the GAP receipt type', !crossType.valid,
    'a perimeter declaration must never be replayable as a decision receipt')

  // The blind-spot list is the product artifact, so it is conformance surface.
  const body = decl['body'] as { blind_spots: Array<{ surface: string; reason: string }> }
  const surfaces = body.blind_spots.map(s => s.surface)
  ok('genesis: the blind-spot surfaces match the vector',
    JSON.stringify(surfaces) === JSON.stringify(c.expected['blind_spot_surfaces']))
  ok('genesis: every blind spot carries a non-empty reason',
    body.blind_spots.every(s => s.reason.length > 0),
    'an unexplained blind spot is a disclaimer, not a disclosure')

  const classification = c.expected['surface_classification'] as Record<string, string>
  for (const [surface, expectedClass] of Object.entries(classification)) {
    ok(`genesis: "${surface}" classifies as ${expectedClass}`,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      classifySurface(decl['body'] as any, surface) === expectedClass)
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rendered = renderPerimeterDeclaration(decl as any)
  ok('genesis: the rendered form lists every blind spot',
    surfaces.every(s => rendered.includes(s)),
    'the list is never truncated to a count')
  ok('genesis: the rendered form states the scope limit',
    rendered.includes('evidence that it did not happen'))
}

// ── Case 2: the successor, and the prev chain ───────────────────────────────

{
  const genesis = byName('genesis_declaration_verifies').declaration
  const c = byName('successor_chains_to_genesis')
  const decl = c.declaration
  const canonical = canonicalOf(decl)

  ok('successor: canonical bytes reproduce', canonical === c.expected['canonical_payload'])
  ok('successor: oid is the sha256 of those bytes', oidOf(canonical) === decl['oid'])
  ok('successor: validates', validatePerimeterDeclaration(decl).ok)

  const body = decl['body'] as { prev?: string; blind_spots: Array<{ surface: string }> }
  ok('successor: prev is the genesis oid', body.prev === genesis['oid'])

  const att = decl['attestation'] as AttestationEnvelope
  ok('successor: verifies under the perimeter payloadType',
    verifyAttestation({
      envelope: att, ed25519_pub: edPub, ml_dsa_pub: mlPub,
      expectedPayloadType: 'application/vnd.synoi.perimeter+json',
    }).valid)

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const chain = verifyPerimeterChain([genesis, decl] as any)
  ok('chain: genesis then successor holds', chain.ok, chain.reasons.join(','))

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const reversed = verifyPerimeterChain([decl, genesis] as any)
  ok('chain: the reversed order is rejected', !reversed.ok)

  const forgedLink = JSON.parse(JSON.stringify(decl)) as Record<string, unknown>
  ;(forgedLink['body'] as { prev: string }).prev = 'sha256:' + '0'.repeat(64)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const brokenChain = verifyPerimeterChain([genesis, forgedLink] as any)
  ok('chain: a broken prev link is rejected',
    brokenChain.reasons.includes('broken-prev-link'))

  ok('successor: closing a blind spot removes it from the list',
    body.blind_spots.length === 1 &&
    JSON.stringify(body.blind_spots.map(s => s.surface)) ===
      JSON.stringify(c.expected['blind_spot_surfaces']))
}

// ── Case 3: the enforcement overclaim ──────────────────────────────────────

{
  const c = byName('enforcement_overclaim_rejected')
  const shape = validatePerimeterDeclaration(c.declaration)
  ok('overclaim: "C7, structural" is rejected by the shared validator', !shape.ok)
  ok('overclaim: the error names the ceiling',
    shape.errors.some(e => e.includes(String(c.expected['error_contains']))),
    shape.errors.join('; '))
}

// ── Case 4: the forged OID ─────────────────────────────────────────────────

{
  const c = byName('forged_oid_rejected')
  const decl = c.declaration
  const canonical = canonicalOf(decl)

  ok('forged oid: the body still validates', validatePerimeterDeclaration(decl).ok,
    'shape validation says nothing about the OID, which is why it is checked separately')

  const att = decl['attestation'] as AttestationEnvelope
  ok('forged oid: the signature STILL verifies',
    verifyAttestation({
      envelope: att, ed25519_pub: edPub, ml_dsa_pub: mlPub,
      expectedPayloadType: 'application/vnd.synoi.perimeter+json',
    }).valid,
    'the OID is a detached envelope field, so no signature check catches it')
  ok('forged oid: re-deriving the OID catches it',
    oidOf(canonical) !== decl['oid'],
    'prev chains by OID, so a forged OID forges chain position')
}

// ── Case 5: the dropped blind spot ─────────────────────────────────────────

{
  const c = byName('tampered_blind_spot_rejected')
  const decl = c.declaration
  const canonical = canonicalOf(decl)
  const att = decl['attestation'] as AttestationEnvelope

  ok('tampered blind spot: the OID no longer matches the content',
    oidOf(canonical) !== decl['oid'])
  ok('tampered blind spot: the attestation payload no longer matches the body',
    att.payload !== canonical,
    'dropping a blind spot silently widens the coverage claim, so it must break the binding')
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
