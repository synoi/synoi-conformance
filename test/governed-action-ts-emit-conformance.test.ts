// test/governed-action-ts-emit-conformance.test.ts
//
// TS-emit / TS-verify conformance for governed-action receipt-v2 CDROs.
//
// This is the complement of governed-action-xlang-conformance.test.ts (which
// covers Rust-emit / TS-verify). This test proves the SAME receipt-v2 CDRO
// FORMAT works in the TS-emit direction: we construct a governed-action
// receipt-v2 CDRO using the same sraid primitives the gateway router uses,
// then verify it with @synoi/verify verifyReceiptV2.
//
// It uses the SAME deterministic seeds as _gen-receipt-v2.ts ([7,8] seeds)
// so results are byte-stable. No gateway HTTP layer required: the test
// directly exercises the format correctness of the receipt-v2 CDRO shape
// that _buildDecisionReceiptV2 emits.
//
// Vectors exercised:
//   POSITIVE allow   -- governed-action.allowed CDRO -> ACCEPT
//   POSITIVE deny    -- governed-action.denied  CDRO -> ACCEPT
//   POSITIVE request -- governed-action.requested CDRO -> ACCEPT
//   NEGATIVE tamper  -- body field mutated after signing -> REJECT (payload-core-mismatch)
//   NEGATIVE wrong-key -- correct CDRO under wrong public keys -> REJECT
//   NEGATIVE type-wrong -- type: 'agp:decision_receipt' (old shape) -> REJECT
//
// TAG: PARTIAL-against-test-keys. No AI attribution. No em dashes.

import { canonicalize, cdroContentCore, cdroOid, pae } from '@synoi/sraid'
import { ed25519 as nobleEd } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { verifyReceiptV2 } from '@synoi/verify'

// ── Deterministic keys (same seeds as _gen-receipt-v2.ts) ────────────────────

// Ed25519: seed with i*7+3 pattern (mirrors gen script)
const ed_priv = new Uint8Array(32)
for (let i = 0; i < 32; i++) ed_priv[i] = (i * 7 + 3) & 0xff
const ed_pub = nobleEd.getPublicKey(ed_priv)

// ML-DSA-65: all-7 seed
const ml = ml_dsa65.keygen(new Uint8Array(32).fill(7))

// Wrong keys: seeds [9,0,...,0,9] to match xlang test
const wrongEdSeed = new Uint8Array(32); wrongEdSeed[0] = 9; wrongEdSeed[31] = 9
const wrongMlSeed = new Uint8Array(32); wrongMlSeed[0] = 9; wrongMlSeed[31] = 9
const wrong_ed_pub = nobleEd.getPublicKey(wrongEdSeed)
const wrong_ml_pub = ml_dsa65.keygen(wrongMlSeed).publicKey

// ── Constants (mirror verify-router / receipt-sign) ───────────────────────────

const V2_PAYLOAD_TYPE   = 'application/vnd.synoi.gap+json' // migrated per ADR_007 payloadType split
const RECEIPT_SCHEME_V2 = 'synoi.receipt/v2'

// ── Receipt-v2 CDRO builder (mirrors _buildDecisionReceiptV2 in gateway) ──────

type Subject = 'governed-action.allowed' | 'governed-action.denied' | 'governed-action.requested'

function buildGoverningReceipt(
  subject:  Subject,
  decision: 'allow' | 'deny' | 'step_up',
  bodyExtra?: Record<string, unknown>,
): Record<string, unknown> {
  const tenant_id = 'tenant:local-test'
  const created_at_ms = 1_750_000_000_000

  const body: Record<string, unknown> = {
    subject_oid:   'sha256:' + 'b'.repeat(64),
    decision,
    action_kind:   'command',
    panel_id:      'approval',
    decision_oid:  null,
    initiator:     { actor_oid: 'oid-' + 'a'.repeat(64), actor_type: 'human_user' },
    subject_kind:  'capability_invocation',
    status:        decision === 'allow' ? 'ok' : decision === 'deny' ? 'denied' : 'pending',
    authority:     { grant_oid: 'capbundle/1', subject_oid: 'oid-' + 'a'.repeat(64) },
    capability_grant_oids: ['capbundle/1'],
    initiated_at_ms: created_at_ms,
    resolved_at_ms:  created_at_ms,
    cited_oracle_inputs: [],
    ...(bodyExtra ?? {}),
  }

  // Build the content core (without oid/attestation) -- exactly as _buildDecisionReceiptV2 does.
  const coreObj: Record<string, unknown> = {
    type:           'gap:decision_receipt',
    sraid_version:  '2.0',
    receipt_scheme: RECEIPT_SCHEME_V2,
    tenant_id,
    created_at_ms,
    created_by:     'sha256:' + 'c'.repeat(64),
    subject,
    body,
  }

  // OID = cdroOid(coreObj). coreObj has no oid/attestation so cdroContentCore is identity.
  const oid = cdroOid(coreObj)

  // Sign the content core with DSSE PAE.
  const fullCdro = { ...coreObj, oid }
  const payload  = canonicalize(cdroContentCore(fullCdro))
  const message  = pae(V2_PAYLOAD_TYPE, payload)

  const edSig = nobleEd.sign(message, ed_priv)
  const mlSig = ml_dsa65.sign(message, ml.secretKey)

  const attestation = {
    payloadType: V2_PAYLOAD_TYPE,
    payload,
    signatures: [
      { alg: 'ed25519',   sig: Buffer.from(edSig).toString('base64'), keyid: 'ts-test-key' },
      { alg: 'ml-dsa-65', sig: Buffer.from(mlSig).toString('base64'), keyid: 'ts-test-key' },
    ],
  }

  return { ...fullCdro, attestation }
}

// ── Test runner ───────────────────────────────────────────────────────────────

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

async function main(): Promise<void> {
  // ── POSITIVE 1: governed-action.allowed ─────────────────────────────────────
  {
    const receipt = buildGoverningReceipt('governed-action.allowed', 'allow')
    ok('ts-emit-allow-type',    receipt['type']           === 'gap:decision_receipt',
      `got ${String(receipt['type'])}`)
    ok('ts-emit-allow-scheme',  receipt['receipt_scheme'] === RECEIPT_SCHEME_V2,
      `got ${String(receipt['receipt_scheme'])}`)
    ok('ts-emit-allow-subject', receipt['subject']        === 'governed-action.allowed',
      `got ${String(receipt['subject'])}`)
    ok('ts-emit-allow-oid',     typeof receipt['oid'] === 'string' && (receipt['oid'] as string).startsWith('sha256:'),
      `got ${String(receipt['oid'])}`)

    const result = await verifyReceiptV2({ receipt, ed25519_pub: ed_pub, ml_dsa_pub: ml.publicKey })
    ok('ts-emit-allow-verify', result.valid,
      `valid=${result.valid} reasons=${JSON.stringify(result.reasons)}`)
  }

  // ── POSITIVE 2: governed-action.denied ──────────────────────────────────────
  {
    const receipt = buildGoverningReceipt('governed-action.denied', 'deny')
    ok('ts-emit-deny-subject', receipt['subject'] === 'governed-action.denied')

    const result = await verifyReceiptV2({ receipt, ed25519_pub: ed_pub, ml_dsa_pub: ml.publicKey })
    ok('ts-emit-deny-verify', result.valid,
      `valid=${result.valid} reasons=${JSON.stringify(result.reasons)}`)
  }

  // ── POSITIVE 3: governed-action.requested ───────────────────────────────────
  {
    const receipt = buildGoverningReceipt('governed-action.requested', 'step_up')
    ok('ts-emit-requested-subject', receipt['subject'] === 'governed-action.requested')

    const result = await verifyReceiptV2({ receipt, ed25519_pub: ed_pub, ml_dsa_pub: ml.publicKey })
    ok('ts-emit-requested-verify', result.valid,
      `valid=${result.valid} reasons=${JSON.stringify(result.reasons)}`)
  }

  // ── NEGATIVE 1: tampered body field -> REJECT (payload-core-mismatch) ───────
  {
    const receipt = buildGoverningReceipt('governed-action.allowed', 'allow')
    // Mutate a body field AFTER signing.
    ;(receipt['body'] as Record<string, unknown>)['action_kind'] = 'tampered'

    const result = await verifyReceiptV2({ receipt, ed25519_pub: ed_pub, ml_dsa_pub: ml.publicKey })
    ok('ts-emit-tamper-reject', !result.valid,
      `valid=${result.valid} reasons=${JSON.stringify(result.reasons)}`)
    ok('ts-emit-tamper-reason',
      !result.valid && result.reasons.includes('payload-core-mismatch'),
      `reasons=${JSON.stringify(result.reasons)}`)
  }

  // ── NEGATIVE 2: wrong public keys -> REJECT ──────────────────────────────────
  {
    const receipt = buildGoverningReceipt('governed-action.allowed', 'allow')

    const result = await verifyReceiptV2({ receipt, ed25519_pub: wrong_ed_pub, ml_dsa_pub: wrong_ml_pub })
    ok('ts-emit-wrong-key-reject', !result.valid,
      `valid=${result.valid} reasons=${JSON.stringify(result.reasons)}`)
  }

  // ── NEGATIVE 3: old type 'agp:decision_receipt' -> REJECT ───────────────────
  //
  // Proves the type field is bound into the content core. An object that is
  // otherwise identical but uses the old 'agp:decision_receipt' type will
  // produce a different OID and a different canonical payload, so the DSSE
  // attestation from the 'gap:decision_receipt' shape cannot verify it.
  {
    const receipt = buildGoverningReceipt('governed-action.allowed', 'allow')
    // Mutate type AFTER signing (without re-signing). The stored attestation
    // payload no longer matches cdroContentCore(receipt) because type changed.
    receipt['type'] = 'agp:decision_receipt'

    const result = await verifyReceiptV2({ receipt, ed25519_pub: ed_pub, ml_dsa_pub: ml.publicKey })
    ok('ts-emit-old-type-reject', !result.valid,
      `valid=${result.valid} reasons=${JSON.stringify(result.reasons)}`)
  }

  // ── Summary ───────────────────────────────────────────────────────────────────
  process.stdout.write(`\ngoverned-action-ts-emit: ${passed} passed, ${failed} failed\n`)
  if (failed > 0) process.exit(1)
}

main().catch(err => {
  process.stderr.write(`ERROR: ${(err as Error).message}\n${(err as Error).stack ?? ''}\n`)
  process.exit(1)
})
