// vectors/_gen-gate-consult-rebind.ts -- produce gate-consult rebind conformance
// vectors for the WASM/WASI gate (iteration 7, ADR_005 Sec 5.1/5.2). Run with:
//   npx tsx vectors/_gen-gate-consult-rebind.ts   (from synoi-conformance root)
// Output: vectors/wasm-shell/gate-consult-rebind.json
//
// Five fixtures: ACCEPT + transplant-REJECT + stripped-ML-DSA-REJECT +
// expired-REJECT + untrusted-signer-REJECT.
//
// Keys are RANDOM (fresh each run). The Rust runner reads pubkeys from the file
// and evaluates each fixture per its expected field.
//
// Status: DESIGN (ADR_005 Sec 5, iteration-7, 2026-06-20)
// No AI attribution.

import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, 'wasm-shell')
mkdirSync(outDir, { recursive: true })

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')
const hex  = (b: Uint8Array): string => Buffer.from(b).toString('hex')

// Dedicated GateDecision payloadType (ADR_005 Section 5.1 / ADR_011 1.3).
// Distinct from the generic SRAID receipt type; byte-identical to the TS signer
// (consult-gate-router GATE_DECISION_PAYLOAD_TYPE) and the Rust verifier
// (synoi_verify::GATE_DECISION_PAYLOAD_TYPE). PAE binds this into the signed
// bytes, so the fixture signatures here only verify under the gate-decision type.
const PAYLOAD_TYPE = 'application/vnd.synoi.gate-decision+json'

// -- Inline canonical JSON (recursive key-sort, no whitespace) ----------------

function canonicalize(obj: unknown): string {
  if (obj === null) return 'null'
  if (typeof obj !== 'object') return JSON.stringify(obj)
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']'
  const keys = Object.keys(obj as Record<string, unknown>).sort()
  const pairs = keys.map(k =>
    JSON.stringify(k) + ':' + canonicalize((obj as Record<string, unknown>)[k])
  )
  return '{' + pairs.join(',') + '}'
}

// -- PAE per DSSE spec (byte-identical to Rust pae()) -------------------------

function pae(payloadType: string, payload: string): Uint8Array {
  const enc = new TextEncoder()
  const typeBytes = enc.encode(payloadType)
  const bodyBytes = enc.encode(payload)
  const prefix = enc.encode(`DSSEv1 ${typeBytes.length} ${payloadType} ${bodyBytes.length} `)
  const out = new Uint8Array(prefix.length + bodyBytes.length)
  out.set(prefix, 0)
  out.set(bodyBytes, prefix.length)
  return out
}

// -- Helper: build a signed attestation envelope ------------------------------

function buildEnvelope(
  payload: string,
  edPriv: Uint8Array,
  mlSec: Uint8Array,
  opts: { stripMlDsa?: boolean } = {}
): object {
  const paeBytes = pae(PAYLOAD_TYPE, payload)
  const edSig = ed25519.sign(paeBytes, edPriv)
  const mlSig = ml_dsa65.sign(paeBytes, mlSec)
  const sigs: object[] = [
    { alg: 'ed25519',   sig: b64(edSig), keyid: 'test-fixture' },
  ]
  if (!opts.stripMlDsa) {
    sigs.push({ alg: 'ml-dsa-65', sig: b64(mlSig), keyid: 'test-fixture' })
  }
  return { payloadType: PAYLOAD_TYPE, payload, signatures: sigs }
}

// -- Keypair: main gate signer ------------------------------------------------

const edPriv  = new Uint8Array(randomBytes(32))
const edPub   = ed25519.getPublicKey(edPriv)
const mlSeed  = new Uint8Array(randomBytes(32))
const ml      = ml_dsa65.keygen(mlSeed)

// -- Keypair: ephemeral untrusted signer (case 5) -----------------------------

const edPriv2 = new Uint8Array(randomBytes(32))
const mlSeed2 = new Uint8Array(randomBytes(32))
const ml2     = ml_dsa65.keygen(mlSeed2)

// -- Base content_core shared across most fixtures ----------------------------
//
// GateDecisionContentCore field names match the TS gateway schema exactly so
// canonicalize (sorted keys) produces a stable, interoperable payload.

const bundleOid    = 'sha256:' + 'a'.repeat(64)
const principalOid = 'sha256:' + 'b'.repeat(64)

const baseLiveTuple = {
  bundle_oid:              bundleOid,
  principal_oid:           principalOid,
  panel_id:                'receipt-verify',
  action_kind:             'render',
  originating_receipt_oid: null as string | null,
}

const baseContentCore = {
  schema_version:          'gate-decision/1',
  bundle_oid:              bundleOid,
  principal_oid:           principalOid,
  panel_id:                'receipt-verify',
  action_kind:             'render',
  originating_receipt_oid: null as string | null,
  decision:                'allow' as const,
  axes_consulted:          [1, 2, 3, 4, 5, 6, 7],
  axes_denied:             [] as number[],
  reason_cdros:            [] as string[],
  // issued_at: SIGNED field (Finding 4, iter-12). Part of the canonical content
  // core, so it is covered by the signature and changes the OID. The host uses
  // it to bound how long a cached allow may be served (issued_at + maxage).
  issued_at:               '2099-01-01T00:00:00.000Z',
  expires_at:              '2099-01-01T00:00:00.000Z',
  // revocation_epoch: SIGNED field (ADR_005 Section 5.7, iter-12). The gateway's
  // monotonic per-process revocation epoch at decision mint time. The host refuses
  // to serve a cached allow whose revocation_epoch < host's last-seen epoch.
  // Test fixture uses epoch 0 (no revocations have fired in the test context).
  revocation_epoch:        0,
}

// -- Case 1: accept -----------------------------------------------------------

const acceptPayload = canonicalize(baseContentCore)
const acceptAttestation = buildEnvelope(acceptPayload, edPriv, ml.secretKey)

// -- Case 2: transplant (tuple mismatch) --------------------------------------
//
// The attestation is valid (signed over panel_id="receipt-verify"), but the
// live_tuple presented at evaluation has panel_id changed to "OTHER-PANEL".
// Sigs verify; binding check fails.

const transplantLiveTuple = { ...baseLiveTuple, panel_id: 'OTHER-PANEL' }
// attestation is the SAME valid envelope as accept (content_core has "receipt-verify")
const transplantAttestation = buildEnvelope(acceptPayload, edPriv, ml.secretKey)

// -- Case 3: stripped_ml_dsa (missing ML-DSA signature) ----------------------

const strippedPayload = canonicalize(baseContentCore)
const strippedAttestation = buildEnvelope(strippedPayload, edPriv, ml.secretKey, { stripMlDsa: true })

// -- Case 4: expired ----------------------------------------------------------

const expiredCore = { ...baseContentCore, expires_at: '2000-01-01T00:00:00.000Z' }
const expiredPayload = canonicalize(expiredCore)
const expiredAttestation = buildEnvelope(expiredPayload, edPriv, ml.secretKey)

// -- Case 5: untrusted_signer (signed by ephemeral second keypair) ------------

const untrustedPayload = canonicalize(baseContentCore)
const untrustedAttestation = buildEnvelope(untrustedPayload, edPriv2, ml2.secretKey)

// -- Case 6: transplant_originating (5th-field tuple mismatch) ----------------
//
// The attestation is valid (content_core.originating_receipt_oid = null), but the
// live_tuple presents a concrete originating_receipt_oid. The ADR_005 Section 5.1
// bound tuple has FIVE fields; the 5th (originating_receipt_oid) MUST be compared.
// Sigs verify; binding check fails on the 5th field (Security + Adversary F2/A).
const transplantOrigLiveTuple = {
  ...baseLiveTuple,
  originating_receipt_oid: 'sha256:' + 'c'.repeat(64),
}
const transplantOrigAttestation = buildEnvelope(acceptPayload, edPriv, ml.secretKey)

// -- Case 7: transplant_principal (principal_oid tuple mismatch) --------------
//
// Valid attestation, but live_tuple.principal_oid differs. Pins that principal_oid
// is enforced in the rebind, not just panel_id.
const transplantPrincipalLiveTuple = {
  ...baseLiveTuple,
  principal_oid: 'sha256:' + 'd'.repeat(64),
}
const transplantPrincipalAttestation = buildEnvelope(acceptPayload, edPriv, ml.secretKey)

// -- Case 8: null_principal_injection (reproduce-first for coercion fix) ------
//
// Demonstrates the strict-parity fix (ADR_005 bound_tuple_matches Rust semantics).
//
// The signed payload carries principal_oid: null (a non-string mandatory field).
// The live_tuple also presents principal_oid: null (null injection at the JSON
// boundary -- bypasses the TypeScript string type at runtime).
//
// Under the OLD ?? null coercion the runner would WRONGLY ACCEPT this vector:
//   lt.principal_oid ?? null  = null   (null ?? null stays null)
//   payload.principal_oid ?? null = null   (null ?? null stays null)
//   null === null  ->  no mismatch  ->  ACCEPT  (wrong -- mandatory field is null)
//
// Under the NEW strict code the runner CORRECTLY REJECTS:
//   typeof null !== 'string'  ->  tuple-mismatch  ->  REJECT  (correct, fail-closed)
//
// The attestation is VALIDLY SIGNED over the null-principal payload so signature
// verification passes. The tuple-mismatch branch is the sole deciding factor --
// this is a pure reproduce-first for the coercion bug, backed by test-fixture keys.
const nullPrincipalCore = {
  ...baseContentCore,
  // Deliberately null: this is the malformed payload that the old ?? null code
  // would accept when the live tuple is also null.
  principal_oid: null as unknown as string,
}
const nullPrincipalPayload     = canonicalize(nullPrincipalCore)
const nullPrincipalAttestation = buildEnvelope(nullPrincipalPayload, edPriv, ml.secretKey)
// live_tuple also has null -- matching the signed null, so old code sees null==null
const nullPrincipalLiveTuple   = {
  ...baseLiveTuple,
  principal_oid: null as unknown as string,
}

// -- Compose output -----------------------------------------------------------

const output = {
  description: 'Gate-consult rebind conformance vector per ADR_005 Sec 5.1/5.2.',
  generated_at: new Date().toISOString(),
  gate_signer_ed25519_pub: hex(edPub),
  gate_signer_ml_dsa_pub:  hex(ml.publicKey),
  fixtures: {
    accept: {
      description: 'Valid attestation + matching live_tuple + future expires_at: must ACCEPT.',
      live_tuple:   baseLiveTuple,
      content_core: baseContentCore,
      attestation:  acceptAttestation,
      expected:     'ACCEPT',
    },
    transplant: {
      description: 'Attestation sigs are valid but live_tuple.panel_id differs from content_core.panel_id: tuple-mismatch REJECT.',
      live_tuple:   transplantLiveTuple,
      content_core: baseContentCore,
      attestation:  transplantAttestation,
      expected:         'REJECT',
      expected_reason:  'tuple-mismatch',
    },
    stripped_ml_dsa: {
      description: 'ML-DSA-65 signature removed from signatures array: missing-ml-dsa-65 REJECT.',
      live_tuple:   baseLiveTuple,
      content_core: baseContentCore,
      attestation:  strippedAttestation,
      expected:         'REJECT',
      expected_reason:  'missing-ml-dsa-65',
    },
    expired: {
      description: 'Both sigs valid, tuple matches, but expires_at is in the past: expired REJECT.',
      live_tuple:   baseLiveTuple,
      content_core: expiredCore,
      attestation:  expiredAttestation,
      expected:         'REJECT',
      expected_reason:  'expired',
    },
    untrusted_signer: {
      description: 'Attestation signed by a different keypair not in the trusted set: signer-not-trusted REJECT.',
      live_tuple:   baseLiveTuple,
      content_core: baseContentCore,
      attestation:  untrustedAttestation,
      expected:         'REJECT',
      expected_reason:  'signer-not-trusted',
    },
    transplant_originating: {
      description: 'Valid sigs, but live_tuple.originating_receipt_oid (5th bound-tuple field) differs from content_core (null): tuple-mismatch REJECT. Pins the 5th field is compared (Security + Adversary F2/A).',
      live_tuple:   transplantOrigLiveTuple,
      content_core: baseContentCore,
      attestation:  transplantOrigAttestation,
      expected:         'REJECT',
      expected_reason:  'tuple-mismatch',
    },
    transplant_principal: {
      description: 'Valid sigs, but live_tuple.principal_oid differs from content_core: tuple-mismatch REJECT. Pins principal_oid is enforced, not just panel_id.',
      live_tuple:   transplantPrincipalLiveTuple,
      content_core: baseContentCore,
      attestation:  transplantPrincipalAttestation,
      expected:         'REJECT',
      expected_reason:  'tuple-mismatch',
    },
    null_principal_injection: {
      description: 'REPRODUCE-FIRST for ?? null coercion bug: signed payload has principal_oid: null; live_tuple also null. Old ?? null coercion: both sides null == null -> wrongly ACCEPTED. New strict check: typeof null !== "string" -> correctly REJECTED. Attestation is validly signed over the null-principal payload (test-fixture keys); sig passes, tuple-mismatch is the sole deciding factor.',
      live_tuple:   nullPrincipalLiveTuple,
      content_core: nullPrincipalCore,
      attestation:  nullPrincipalAttestation,
      expected:         'REJECT',
      expected_reason:  'tuple-mismatch',
    },
  },
}

const outPath = join(outDir, 'gate-consult-rebind.json')
writeFileSync(outPath, JSON.stringify(output, null, 2) + '\n')

process.stdout.write('Wrote gate-consult-rebind vector:\n')
process.stdout.write(`  ${outPath}\n`)
process.stdout.write(`  gate_signer_ed25519_pub: ${hex(edPub).length} chars (${edPub.length} bytes)\n`)
process.stdout.write(`  gate_signer_ml_dsa_pub:  ${hex(ml.publicKey).length} chars (${ml.publicKey.length} bytes)\n`)
process.stdout.write(`  fixtures: accept, transplant, stripped_ml_dsa, expired, untrusted_signer, transplant_originating, transplant_principal, null_principal_injection\n`)
