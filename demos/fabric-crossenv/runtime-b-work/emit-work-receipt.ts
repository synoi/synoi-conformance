// runtime-b-work/emit-work-receipt.ts
//
// RUNTIME B - "WORK" emitter. A SECOND, INDEPENDENT implementation that
// signs a governed WORK action receipt (R2 = calendar.write) under the SAME
// operator identity OID_op, with prev = R1.oid, linking R2 to Runtime A's
// game receipt inside the SIGNED canonical projection (cdroContentCore
// keeps `prev`, so a forged prev edge is detectable, same property
// synoi-gateway/src/gap/receipt-sign.ts documents for its own `prev` block).
//
// Uses ONLY @synoi/sraid (canonicalize, cdroContentCore, oidOfCanonical,
// pae) plus @noble/curves (ed25519) and @noble/post-quantum (ml-dsa-65).
// NO gateway code. This file does NOT import runtime-a-game's signing code;
// the signing logic below is written independently, even though it lands on
// the same open-library calls, because that is the actual open contract a
// third-party emitter must hit to interoperate.
//
// The only thing Runtime B reads that Runtime A produced is out/r1.json
// (specifically its `oid`), read as plain JSON off disk, exactly as a
// completely separate program in a completely separate process would.
//
// Run: npx tsx runtime-b-work/emit-work-receipt.ts
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

const PAYLOAD_TYPE = 'application/vnd.synoi.gap+json'
const KEY_ID = 'runtime-b-work-demo-key-v1'
const TENANT_ID = 'demo-fabric-crossenv'

// ── Runtime B's own keypair. Independent of Runtime A's; a different key
// signs this receipt, proving the chain is not "one signer wearing two
// hats." ─────────────────────────────────────────────────────────────────
const edPriv = randomBytes(32)
const edPub = ed25519.getPublicKey(edPriv)
const mlSeed = randomBytes(32)
const mlKp = ml_dsa65.keygen(new Uint8Array(mlSeed))

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

const r1 = JSON.parse(readFileSync(join(outDir, 'r1.json'), 'utf8')) as { oid: string }
if (typeof r1.oid !== 'string' || !r1.oid.startsWith('sha256:')) {
  throw new Error('runtime-b-work: r1.json missing a valid oid; run runtime-a-game first')
}

// ── R2: a governed WORK action (calendar.write), linked to R1 via `prev`. ──
const nowMs = Date.now()
const r2Unsigned: Record<string, unknown> = {
  type: 'gap:decision_receipt',
  sraid_version: '2.0',
  tenant_id: TENANT_ID,
  created_at_ms: nowMs,
  created_by: OID_op,
  prev: r1.oid,
  body: {
    status: 'ok',
    decision: 'allow',
    subject_oid: oidOfCanonical(
      canonicalize({
        kind: 'calendar.write',
        calendar: 'demo-crossenv-workday',
        event: 'quarterly-planning-sync',
        starts_at_ms: nowMs + 3_600_000,
        requested_at_ms: nowMs,
      }),
    ),
    action_class: 'calendar.write',
    environment: 'work',
    runtime_label: 'runtime-b-work (standalone, non-gateway)',
  },
  authority: {
    decision: 'allow',
    subject_oid: OID_op,
    rule_id: 'demo.work.calendar.auto_allow_owned_calendar',
  },
}

const core = cdroContentCore(r2Unsigned)
const payload = canonicalize(core)
const oid = oidOfCanonical(payload)
const message = pae(PAYLOAD_TYPE, payload)

const edSig = ed25519.sign(message, edPriv)
const mlSig = ml_dsa65.sign(message, mlKp.secretKey)

const r2 = {
  ...r2Unsigned,
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

writeFileSync(join(outDir, 'r2.json'), JSON.stringify(r2, null, 2) + '\n')

writeFileSync(
  join(outDir, 'runtime-b-keys.pub.json'),
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

writeFileSync(
  join(outDir, 'runtime-b-keys.secret.json'),
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

process.stdout.write(`runtime-b-work: emitted R2 oid=${oid} prev=${r1.oid}\n`)
