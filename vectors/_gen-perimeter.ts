// vectors/_gen-perimeter.ts -- generate the perimeter-declaration conformance
// vector. Run with `npm run gen:perimeter`.
//
// Output: vectors/perimeter/declaration.json
//
// WHAT THIS VECTOR IS FOR. `synoi.perimeter.v1` is the signed scope statement a
// completeness assertion is complete WITHIN. If a third party cannot check one
// offline, the whole apparatus reduces to "trust the party being audited",
// which is the position the product exists to escape. So the vector pins
// everything a reimplementation needs and nothing it does not:
//
//   - the canonical bytes of a fixed declaration (RFC 8785 JCS over the CDRO
//     content core, which strips the six detached envelope fields),
//   - the OID rule, oid = 'sha256:' + sha256(canonical bytes), which is
//     checkable because the perimeter object hashes the SAME core it signs,
//   - the hybrid DSSE envelope over PAE(payloadType, canonical), both algs
//     required, bound to the perimeter payloadType so it cannot be replayed as
//     a decision receipt,
//   - `prev` chaining across two declarations, and
//   - the enforcement-ceiling rule, which is the one content-integrity rule the
//     object carries: a chokepoint may claim WEAKER enforcement than its class
//     allows, never stronger.
//
// Keys are generated deterministically from a FIXED seed so the vector is
// reproducible byte for byte. These are vector keys and have no other use.
//
// No em dashes.

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto'
import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalize, cdroContentCore, pae, ALG_ED25519, ALG_ML_DSA_65 } from '@synoi/sraid'
import {
  PERIMETER_DECLARATION_SCHEMA,
  validatePerimeterDeclaration,
  verifyPerimeterChain,
} from '@synoi/gap'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, 'perimeter')
mkdirSync(outDir, { recursive: true })

const PAYLOAD_TYPE = 'application/vnd.synoi.perimeter+json'
const KEY_ID = 'perimeter-vector-key'

// ── Deterministic vector keys ────────────────────────────────────────────────
// Ed25519 seeds are 32 bytes; an RFC 8410 PKCS#8 wrapper is a fixed 16-byte
// prefix followed by the seed, so a fixed seed gives a fixed key.
const ED_SEED = Buffer.from('53796e4f4920706572696d6574657220766563746f72206b657920763120212121'.slice(0, 64), 'hex')
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const edPriv = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, ED_SEED]),
  format: 'der',
  type: 'pkcs8',
})
const edPubDer = createPublicKey(edPriv).export({ format: 'der', type: 'spki' }) as Buffer
const edPubRaw = edPubDer.subarray(edPubDer.length - 32)

const ML_SEED = new Uint8Array(createHash('sha256').update('synoi perimeter vector ml-dsa seed v1').digest())
const mlKeys = ml_dsa65.keygen(ML_SEED)

function signEnvelope(payload: string): Record<string, unknown> {
  const paeBytes = pae(PAYLOAD_TYPE, payload)
  const edSig = nodeSign(null, Buffer.from(paeBytes), edPriv)
  const mlSig = ml_dsa65.sign(paeBytes, mlKeys.secretKey)
  return {
    payloadType: PAYLOAD_TYPE,
    payload,
    signatures: [
      { keyid: KEY_ID, alg: ALG_ED25519,   sig: Buffer.from(edSig).toString('base64') },
      { keyid: KEY_ID, alg: ALG_ML_DSA_65, sig: Buffer.from(mlSig).toString('base64') },
    ],
  }
}

// ── The fixed declaration ────────────────────────────────────────────────────

const T0 = 1_750_000_000_000

const genesisBody = {
  schema: PERIMETER_DECLARATION_SCHEMA,
  governed_subject: {
    platform:      'replit',
    workspace_id:  'ws-vector',
    deployment_id: 'dep-vector',
  },
  chokepoints_active: [
    { class: 'C1', surface: 'gateway:brokered-credential:stripe', enforcement: 'structural' },
    { class: 'C5', surface: 'mcp:https://gw.example/mcp/proxy',   enforcement: 'structural' },
    { class: 'C7', surface: 'github:webhook',                     enforcement: 'observational' },
  ],
  blind_spots: [
    {
      surface:           'replit:agent-shell',
      reason:            'The workspace shell tab runs commands with no pre-execution hook a third party can register.',
      class_unavailable: 'C4',
    },
    {
      surface:           'replit:static-deployment',
      reason:            'A static deployment has no env vars and no run command, so no credential can be brokered.',
      class_unavailable: 'C1',
    },
  ],
  completeness_scope: { populations: ['action_log', 'receipts'], from_seq: 1, to_seq: 4096 },
  effective_from_ms: T0,
  effective_to_ms:   T0 + 86_400_000,
}

function buildDeclaration(body: Record<string, unknown>, created_at_ms: number): {
  declaration: Record<string, unknown>
  canonical: string
} {
  const unsigned = {
    type:          'gap:perimeter_declaration',
    gap_version:   '1.0',
    tenant_id:     'tenant:vector',
    created_at_ms,
    created_by:    'actor:gateway',
    body,
  }
  const canonical = canonicalize(cdroContentCore(unsigned))
  const oid = 'sha256:' + createHash('sha256').update(canonical, 'utf8').digest('hex')
  return {
    declaration: { oid, ...unsigned, attestation: signEnvelope(canonical) },
    canonical,
  }
}

const genesis = buildDeclaration(genesisBody, T0)

// The successor closes one blind spot: the shell surface becomes governed.
const successorBody = {
  ...genesisBody,
  chokepoints_active: [
    ...genesisBody.chokepoints_active,
    { class: 'C4', surface: 'replit:agent-shell', enforcement: 'structural' },
  ],
  blind_spots: genesisBody.blind_spots.slice(1),
  effective_from_ms: T0 + 86_400_000,
  prev: genesis.declaration['oid'] as string,
}
delete (successorBody as Record<string, unknown>)['effective_to_ms']
const successor = buildDeclaration(successorBody, T0 + 86_400_000)

// ── Self-check before writing ────────────────────────────────────────────────

for (const [label, d] of [['genesis', genesis], ['successor', successor]] as const) {
  const r = validatePerimeterDeclaration(d.declaration)
  if (!r.ok) {
    console.error(`${label} declaration failed self-check: ${r.errors.join('; ')}`)
    process.exit(1)
  }
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const chainCheck = verifyPerimeterChain([genesis.declaration, successor.declaration] as any)
if (!chainCheck.ok) {
  console.error(`chain failed self-check: ${chainCheck.reasons.join(', ')}`)
  process.exit(1)
}

// ── The vector ───────────────────────────────────────────────────────────────

const vector = {
  kind: 'perimeter_declaration_v1',
  description:
    'Signed synoi.perimeter.v1 perimeter declaration. The scope statement a completeness ' +
    'assertion is complete WITHIN: which chokepoints are active at what enforcement quality, ' +
    'and which surfaces are NOT covered. The signed bytes are RFC 8785 JCS over the CDRO ' +
    'content core (the envelope minus the six detached fields), the OID is the sha256 of those ' +
    'same bytes, and the hybrid Ed25519 + ML-DSA-65 DSSE envelope binds the perimeter ' +
    'payloadType so it can never be replayed as a decision receipt. A reimplementation ' +
    'reproduces canonical_payload and oid from the envelope alone, verifies the attestation ' +
    'with verifyAttestation, checks the prev chain, and rejects the enforcement overclaim case.',
  constants: {
    schema: PERIMETER_DECLARATION_SCHEMA,
    object_type: 'gap:perimeter_declaration',
    payload_type: PAYLOAD_TYPE,
    oid_rule:
      "oid = 'sha256:' + SHA-256(canonicalize(cdroContentCore(envelope))); the SAME bytes the " +
      'attestation signs, so a verifier re-derives the OID from the signature payload it already holds',
    canonicalization: 'RFC 8785 JCS; object keys re-sorted lexicographically',
    hybrid_rule:
      'attestation carries BOTH ed25519 AND ml-dsa-65 over PAE(payloadType, canonical); both required',
    null_omit:
      'an optional field that does not apply is OMITTED entirely, never set to null. A null key ' +
      'changes the canonical bytes and therefore the OID and the signature; an absent key does not',
    enforcement_ceiling:
      'C1 through C5 may claim structural; C6 may claim at most cooperative; C7 may claim at most ' +
      'observational. A chokepoint may claim WEAKER than its class ceiling, never stronger',
    binding_direction:
      'synoi.reconciliation.v1 references BOTH synoi.completeness.v1 and synoi.perimeter.v1. ' +
      'synoi.completeness.v1 references NEITHER, because a required new field on that frozen body ' +
      'would change its canonical bytes and make every previously signed assertion unverifiable',
  },
  ed25519_pub_b64: Buffer.from(edPubRaw).toString('base64'),
  ml_dsa_pub_b64:  Buffer.from(mlKeys.publicKey).toString('base64'),
  cases: [
    {
      name: 'genesis_declaration_verifies',
      declaration: genesis.declaration,
      expected: {
        canonical_payload: genesis.canonical,
        oid: genesis.declaration['oid'],
        payload_type: PAYLOAD_TYPE,
        validates: true,
        verifies_under_perimeter_type: true,
        verifies_under_gap_receipt_type: false,
        blind_spot_surfaces: ['replit:agent-shell', 'replit:static-deployment'],
        surface_classification: {
          'mcp:https://gw.example/mcp/proxy': 'governed',
          'replit:agent-shell':               'declared_blind_spot',
          'replit:scheduled-job':             'undeclared',
        },
      },
    },
    {
      name: 'successor_chains_to_genesis',
      declaration: successor.declaration,
      expected: {
        canonical_payload: successor.canonical,
        oid: successor.declaration['oid'],
        payload_type: PAYLOAD_TYPE,
        validates: true,
        verifies_under_perimeter_type: true,
        prev: genesis.declaration['oid'],
        chain_with_genesis_ok: true,
        // The successor closed one blind spot by adding a chokepoint for it.
        blind_spot_surfaces: ['replit:static-deployment'],
      },
    },
    {
      name: 'enforcement_overclaim_rejected',
      declaration: {
        ...genesis.declaration,
        body: {
          ...genesisBody,
          chokepoints_active: [
            { class: 'C7', surface: 'github:webhook', enforcement: 'structural' },
          ],
        },
      },
      expected: {
        validates: false,
        error_contains: 'exceeds the ceiling for C7',
        note:
          'A post-hoc event feed cannot stop anything and can be starved, so "C7, structural" is ' +
          'a false statement about the mechanism rather than a debatable characterization. Any ' +
          'conformant implementation rejects it, signed or not.',
      },
    },
    {
      name: 'forged_oid_rejected',
      declaration: { ...genesis.declaration, oid: 'sha256:' + 'f'.repeat(64) },
      expected: {
        validates: true,
        oid_matches_canonical: false,
        note:
          'The OID is one of the six detached envelope fields, so it is NOT covered by the ' +
          'signature and every signature check still passes. It has to be re-derived. This ' +
          'matters more here than on a receipt: prev chains by OID, so a forged OID forges ' +
          'chain position.',
      },
    },
    {
      name: 'tampered_blind_spot_rejected',
      declaration: (() => {
        const clone = JSON.parse(JSON.stringify(genesis.declaration)) as Record<string, unknown>
        const body = clone['body'] as { blind_spots: unknown[] }
        body.blind_spots = body.blind_spots.slice(1)
        return clone
      })(),
      expected: {
        validates: true,
        oid_matches_canonical: false,
        verifies_under_perimeter_type: false,
        note:
          'Dropping a blind spot is the highest-value tamper against this object: it silently ' +
          'widens the coverage claim. The canonical bytes change, so both the OID and the ' +
          'attestation payload binding break.',
      },
    },
  ],
}

writeFileSync(join(outDir, 'declaration.json'), JSON.stringify(vector, null, 2) + '\n')
process.stdout.write(`Wrote perimeter vector: declaration.json  ${vector.cases.length} cases\n`)
