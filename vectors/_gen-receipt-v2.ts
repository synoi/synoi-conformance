// vectors/_gen-receipt-v2.ts - produce Receipt v2 hybrid DSSE conformance
// vectors against the @synoi/sraid reference primitives. Run with
// `npm run gen:receipt-v2`. Output: vectors/sraid/receipt-v2.json.
//
// A v2 receipt is an L0 CDRO carrying a DSSE `attestation` envelope. Verifying
// it is two checks: (1) bind canonicalize(cdroContentCore(receipt)) to the
// envelope payload, and (2) hybrid-verify the envelope (ed25519 AND ml-dsa-65,
// both required) over PAE(payloadType, payload). These vectors mirror the
// merged @synoi/verify verifyReceiptV2 path 1:1.
//
// Keys are DETERMINISTIC (fixed seeds) so the emitted vectors are byte-stable
// across regeneration; the canonical bytes and OID are load-bearing.

import { writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize, cdroContentCore, cdroOid, pae } from '@synoi/sraid'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

const here = dirname(fileURLToPath(import.meta.url))
const sraidDir = join(here, 'sraid')

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')

// ── Constants (mirror @synoi/verify; conformance stays dependency-free of it) ─

const RECEIPT_SCHEME_V2 = 'synoi.receipt/v2'
const V2_PAYLOAD_TYPE   = 'application/vnd.synoi.gap+json' // migrated per ADR_007 payloadType split

// ── Deterministic keys ───────────────────────────────────────────────────────

// Ed25519 32-byte seed and ML-DSA-65 32-byte seed, both fixed.
const ed_priv = new Uint8Array(32)
for (let i = 0; i < 32; i++) ed_priv[i] = (i * 7 + 3) & 0xff
const ed_pub = ed25519.getPublicKey(ed_priv)

const ml = ml_dsa65.keygen(new Uint8Array(32).fill(7))

// A second ML-DSA key (different seed) for the wrong-key vector.
const mlOther = ml_dsa65.keygen(new Uint8Array(32).fill(9))

// ── Receipt body (CDRO-shaped, matches @synoi/verify verify-v2.test.ts) ───────

function buildReceipt(): Record<string, unknown> {
  return {
    type:           'gap:decision_receipt',
    sraid_version:  '2.0',
    tenant_id:      'founder',
    created_at_ms:  1747584000000,
    created_by:     'sha256:' + 'a'.repeat(64),
    receipt_scheme: RECEIPT_SCHEME_V2,
    body: {
      decision:     'allow',
      action_class: 'B',
      risk_level:   'low',
      settlement:   { cost: { amount: 1200, currency: 'usd' } },
    },
  }
}

interface Envelope {
  payloadType: string
  payload:     string
  signatures:  Array<{ alg: string; sig: string }>
}

function mintEnvelope(receipt: Record<string, unknown>): Envelope {
  const payload = canonicalize(cdroContentCore(receipt))
  const message = pae(V2_PAYLOAD_TYPE, payload)
  const edSig = ed25519.sign(message, ed_priv)
  const mlSig = ml_dsa65.sign(message, ml.secretKey)
  return {
    payloadType: V2_PAYLOAD_TYPE,
    payload,
    signatures: [
      { alg: 'ed25519',   sig: b64(edSig) },
      { alg: 'ml-dsa-65', sig: b64(mlSig) },
    ],
  }
}

const ed_pub_b64 = b64(ed_pub)
const ml_pub_b64 = b64(ml.publicKey)

// Reference canonical bytes + OID for the valid receipt (load-bearing).
const refReceipt = buildReceipt()
const refCore    = canonicalize(cdroContentCore(refReceipt))
const refOid     = cdroOid(refReceipt as Record<string, unknown>)

// ── Vectors ──────────────────────────────────────────────────────────────────

type Vector = Record<string, unknown>
const vectors: Vector[] = []

// 0. Canonical-bytes + OID binding (no crypto): proves byte-identical
//    canonicalization of the content core through @synoi/sraid. The bytes and
//    OID are asserted EXACTLY.
vectors.push({
  name:                    'receipt-v2: canonical content-core bytes + OID are byte-stable',
  kind:                    'receipt_v2',
  mode:                    'canonical',
  receipt:                 buildReceipt(),
  expected_content_core:   refCore,
  expected_oid:            refOid,
})

// 1. Valid hybrid receipt → TRUE.
{
  const receipt = buildReceipt()
  receipt.attestation = mintEnvelope(receipt)
  vectors.push({
    name:            'receipt-v2: valid hybrid receipt verifies TRUE',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  ml_pub_b64,
    expected_valid:  true,
  })
}

// 2. ml-dsa-65 STRIPPED → REJECT (proves PQ-verify actually engages).
{
  const receipt = buildReceipt()
  const env = mintEnvelope(receipt)
  env.signatures = env.signatures.filter(s => s.alg !== 'ml-dsa-65')
  receipt.attestation = env
  vectors.push({
    name:            'receipt-v2: ml-dsa-65 stripped → REJECT (PQ-verify engages)',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  ml_pub_b64,
    expected_valid:  false,
    expected_reason: 'missing-ml-dsa-65',
  })
}

// 3. ml-dsa-65 corrupted → REJECT.
{
  const receipt = buildReceipt()
  const env = mintEnvelope(receipt)
  const ml65 = env.signatures.find(s => s.alg === 'ml-dsa-65')!
  const bad = Buffer.from(ml65.sig, 'base64')
  bad[0] = (bad[0] ?? 0) ^ 0xff
  ml65.sig = bad.toString('base64')
  receipt.attestation = env
  vectors.push({
    name:            'receipt-v2: ml-dsa-65 corrupted → REJECT',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  ml_pub_b64,
    expected_valid:  false,
    expected_reason: 'ml-dsa-invalid',
  })
}

// 4. ed25519 STRIPPED → REJECT.
{
  const receipt = buildReceipt()
  const env = mintEnvelope(receipt)
  env.signatures = env.signatures.filter(s => s.alg !== 'ed25519')
  receipt.attestation = env
  vectors.push({
    name:            'receipt-v2: ed25519 stripped → REJECT',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  ml_pub_b64,
    expected_valid:  false,
    expected_reason: 'missing-ed25519',
  })
}

// 5. ed25519 corrupted → REJECT.
{
  const receipt = buildReceipt()
  const env = mintEnvelope(receipt)
  const ed = env.signatures.find(s => s.alg === 'ed25519')!
  const bad = Buffer.from(ed.sig, 'base64')
  bad[0] = (bad[0] ?? 0) ^ 0xff
  ed.sig = bad.toString('base64')
  receipt.attestation = env
  vectors.push({
    name:            'receipt-v2: ed25519 corrupted → REJECT',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  ml_pub_b64,
    expected_valid:  false,
    expected_reason: 'ed25519-invalid',
  })
}

// 6. Tampered settlement.cost.amount AFTER signing → content-core bind fails.
{
  const receipt = buildReceipt()
  receipt.attestation = mintEnvelope(receipt)
  ;(receipt.body as { settlement: { cost: { amount: number } } }).settlement.cost.amount = 9999
  vectors.push({
    name:            'receipt-v2: tampered settlement.cost.amount → REJECT (payload-core-mismatch)',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  ml_pub_b64,
    expected_valid:  false,
    expected_reason: 'payload-core-mismatch',
  })
}

// 7. Wrong payloadType (payload bytes unchanged, so bind passes) → type-pin rejects.
{
  const receipt = buildReceipt()
  const env = mintEnvelope(receipt)
  env.payloadType = 'application/vnd.someone-else+json'
  receipt.attestation = env
  vectors.push({
    name:            'receipt-v2: wrong payloadType → REJECT (payload-type-mismatch)',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  ml_pub_b64,
    expected_valid:  false,
    expected_reason: 'payload-type-mismatch',
  })
}

// 8. Missing attestation → REJECT.
{
  const receipt = buildReceipt()
  vectors.push({
    name:            'receipt-v2: missing attestation → REJECT',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  ml_pub_b64,
    expected_valid:  false,
    expected_reason: 'missing-attestation',
  })
}

// 9. Wrong ml-dsa public key → REJECT.
{
  const receipt = buildReceipt()
  receipt.attestation = mintEnvelope(receipt)
  vectors.push({
    name:            'receipt-v2: wrong ml-dsa public key → REJECT',
    kind:            'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64:  b64(mlOther.publicKey),
    expected_valid:  false,
    expected_reason: 'ml-dsa-invalid',
  })
}

writeFileSync(
  join(sraidDir, 'receipt-v2.json'),
  JSON.stringify(vectors, null, 2) + '\n',
)

process.stdout.write(`Wrote SRAID receipt-v2 vectors:\n`)
process.stdout.write(`  receipt-v2.json    ${vectors.length} vectors (1 canonical + 1 valid + 8 must-fail)\n`)
