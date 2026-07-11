// runtime-a-game/emit-game-receipt.ts
//
// RUNTIME A - "GAME" emitter. A standalone, independent implementation that
// signs a governed GAME action receipt (R1) under the operator identity
// OID_op, hybrid-signed Ed25519 + ML-DSA-65 as a DSSE attestation, shaped so
// it verifies under @synoi/verify-core's verifyEvidenceBundle offline.
//
// Uses ONLY @synoi/sraid (canonicalize, cdroContentCore, oidOfCanonical,
// pae) plus @noble/curves (ed25519) and @noble/post-quantum (ml-dsa-65).
// NO gateway code, NO code shared with runtime-b-work/emit-work-receipt.ts
// beyond the two open libraries both depend on independently.
//
// This runtime's key material is generated fresh here, in-process, and is
// NEVER read by or shared with Runtime B. Runtime B only ever sees this
// runtime's PUBLIC key (out/runtime-a-keys.pub.json) and R1's OID, exactly
// as a truly separate implementation would.
//
// Run: npx tsx runtime-a-game/emit-game-receipt.ts
//
// NO em dashes. NO AI attribution.

import { randomBytes, createPublicKey } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalize, cdroContentCore, oidOfCanonical, pae } from '@synoi/sraid'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, '..', 'out')
mkdirSync(outDir, { recursive: true })

// DSSE payload type pinned to the GAP decision-receipt class so this
// receipt is interoperable with the SAME @synoi/verify-core verifier the
// gateway's own receipts use (bundle.ts GAP_RECEIPT_PAYLOAD_TYPE).
const PAYLOAD_TYPE = 'application/vnd.synoi.gap+json'
const KEY_ID = 'runtime-a-game-demo-key-v1'
const TENANT_ID = 'demo-fabric-crossenv'

// ── Runtime A's own keypair, generated in-process, never shared. ───────────
const edPriv = randomBytes(32)
const edPub = ed25519.getPublicKey(edPriv)
const mlSeed = randomBytes(32)
const mlKp = ml_dsa65.keygen(new Uint8Array(mlSeed))

// Ed25519 SPKI DER prefix (RFC 8410), same fixed prefix @synoi/sraid uses to
// reconstruct a KeyObject from a raw 32-byte public key.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
function ed25519PublicKeyPem(raw: Uint8Array): string {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)])
  return createPublicKey({ key: der, format: 'der', type: 'spki' })
    .export({ format: 'pem', type: 'spki' })
    .toString()
}

const operatorIdentity = JSON.parse(
  readFileSync(join(outDir, 'operator-identity.json'), 'utf8'),
) as { oid: string }
const OID_op = operatorIdentity.oid

// ── R1: a governed GAME action, framed as an in-game purchase that reaches
// outside the game (a real-money transaction), authorized under OID_op. ────
const nowMs = Date.now()
const r1Unsigned: Record<string, unknown> = {
  type: 'gap:decision_receipt',
  sraid_version: '2.0',
  tenant_id: TENANT_ID,
  created_at_ms: nowMs,
  created_by: OID_op,
  body: {
    status: 'ok',
    decision: 'allow',
    subject_oid: oidOfCanonical(
      canonicalize({
        kind: 'game.in_app_purchase',
        game: 'demo-crossenv-mmo',
        item: 'battle-pass-season-9',
        amount_minor_units: 999,
        currency: 'USD',
        requested_at_ms: nowMs,
      }),
    ),
    action_class: 'game.in_app_purchase',
    environment: 'game',
    runtime_label: 'runtime-a-game (standalone, non-gateway)',
  },
  authority: {
    decision: 'allow',
    subject_oid: OID_op,
    rule_id: 'demo.game.purchase.auto_allow_under_cap',
  },
}

// Sign: payload = canonicalize(cdroContentCore(receipt)); PAE binds the
// payload TYPE into the signed bytes; OID is computed over the SAME
// canonical payload (cdroOid invariant: OID does not depend on attestation).
const core = cdroContentCore(r1Unsigned)
const payload = canonicalize(core)
const oid = oidOfCanonical(payload)
const message = pae(PAYLOAD_TYPE, payload)

const edSig = ed25519.sign(message, edPriv)
const mlSig = ml_dsa65.sign(message, mlKp.secretKey)

const r1 = {
  ...r1Unsigned,
  oid,
  attestation: {
    payloadType: PAYLOAD_TYPE,
    payload,
    signatures: [
      { alg: 'ed25519', sig: Buffer.from(edSig).toString('base64'), keyid: KEY_ID },
      { alg: 'ml-dsa-65', sig: Buffer.from(mlSig).toString('base64'), keyid: KEY_ID },
    ],
  },
}

writeFileSync(join(outDir, 'r1.json'), JSON.stringify(r1, null, 2) + '\n')

writeFileSync(
  join(outDir, 'runtime-a-keys.pub.json'),
  JSON.stringify(
    {
      key_id: KEY_ID,
      ed25519_public_key_pem: ed25519PublicKeyPem(edPub),
      ml_dsa_public_key_b64: Buffer.from(mlKp.publicKey).toString('base64'),
    },
    null,
    2,
  ) + '\n',
)

// Private key material is written out ONLY so the demo is reproducible and
// inspectable end to end. TEST KEYS, generated fresh per run, never reused
// for anything real. A real Runtime A would keep these in its own custody
// and export only the public bundle above.
writeFileSync(
  join(outDir, 'runtime-a-keys.secret.json'),
  JSON.stringify(
    {
      note: 'TEST KEYS ONLY. Generated fresh for this demo run. Do not reuse.',
      key_id: KEY_ID,
      ed25519_priv_hex: edPriv.toString('hex'),
      ml_dsa_seed_hex: Buffer.from(mlSeed).toString('hex'),
    },
    null,
    2,
  ) + '\n',
)

process.stdout.write(`runtime-a-game: emitted R1 oid=${oid}\n`)
