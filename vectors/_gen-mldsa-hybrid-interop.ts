// vectors/_gen-mldsa-hybrid-interop.ts -- produce hybrid Ed25519 + ML-DSA-65
// DSSE interop vectors for the WASM/WASI gate (iteration 6). Run with
// `npm run gen:mldsa-interop`. Output: vectors/wasm-shell/mldsa-hybrid-interop.json.
//
// Covers a GateDecision CDRO body signed with both algorithms per ADR_005 5.1.
// Four fixtures: accept (valid), tampered-payload, stripped-ML-DSA, wrong-payloadType.
//
// Keys are RANDOM (not deterministic) -- this is an interop vector, not a
// canonical byte-stability vector. Regenerate freely; the Rust WASM verifier
// reads pubkeys from the file and must accept/reject accordingly.

import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize, pae } from '@synoi/sraid'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, 'wasm-shell')
mkdirSync(outDir, { recursive: true })

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')
const hex  = (b: Uint8Array): string => Buffer.from(b).toString('hex')

const PAYLOAD_TYPE = 'application/vnd.synoi.sraid+json'

// GateDecision CDRO body -- pinned per task spec.
const gateDecisionBody = {
  schema_version:          'gate-decision/1',
  bundle_oid:              'sha256:0000000000000000000000000000000000000000000000000000000000000001',
  principal_oid:           'sha256:0000000000000000000000000000000000000000000000000000000000000002',
  panel_id:                'receipt-verify',
  action_kind:             'render-panel',
  originating_receipt_oid: null,
  decision:                'allow',
  axes_consulted:          [1, 2, 3, 7],
  axes_denied:             [],
  expires_at:              '2026-12-31T00:00:00Z',
}

// 1. Canonicalize the body.
const canonicalPayload = canonicalize(gateDecisionBody)

// 2. Compute PAE bytes.
const paeBytes = pae(PAYLOAD_TYPE, canonicalPayload)

// 3. Generate fresh random keypairs.
const edPriv = ed25519.utils.randomPrivateKey()
const edPub  = ed25519.getPublicKey(edPriv)

const ml = ml_dsa65.keygen()

// 4. Sign with both algorithms.
//    noble API: ed25519.sign(message, privKey) and ml_dsa65.sign(message, secretKey).
const edSig = ed25519.sign(paeBytes, edPriv)
const mlSig = ml_dsa65.sign(paeBytes, ml.secretKey)

// 5. Build valid envelope.
const validEnvelope = {
  payloadType: PAYLOAD_TYPE,
  payload:     canonicalPayload,
  signatures: [
    { alg: 'ed25519',   sig: b64(edSig), keyid: 'interop-test' },
    { alg: 'ml-dsa-65', sig: b64(mlSig), keyid: 'interop-test' },
  ],
}

// 6. Tampered payload: append a space to the canonical string (ASCII, valid UTF-8).
const tamperedPayload = canonicalPayload + ' '
const tamperedEnvelope = {
  payloadType: PAYLOAD_TYPE,
  payload:     tamperedPayload,
  signatures:  validEnvelope.signatures,
}

// 7. ML-DSA stripped: only ed25519 signature present.
const mlStrippedEnvelope = {
  payloadType: PAYLOAD_TYPE,
  payload:     canonicalPayload,
  signatures:  validEnvelope.signatures.filter(s => s.alg !== 'ml-dsa-65'),
}

// 8. Wrong payloadType: PAE changes so both sigs must fail.
const wrongTypeEnvelope = {
  payloadType: PAYLOAD_TYPE + '/evil',
  payload:     canonicalPayload,
  signatures:  validEnvelope.signatures,
}

const output = {
  description:
    'Hybrid Ed25519 + ML-DSA-65 DSSE attestation over GateDecision CDRO with bound tuple per ADR_005 5.1. Four fixtures: accept, tampered-payload, stripped-ML-DSA, wrong-payloadType.',
  generator:              '_gen-mldsa-hybrid-interop.ts',
  generated_at:           new Date().toISOString(),
  noble_version_provenance: '@noble/post-quantum ml_dsa65 + @noble/curves ed25519',
  payload_type:           PAYLOAD_TYPE,
  payload:                canonicalPayload,
  pae_hex:                hex(paeBytes),
  ed25519_pub:            hex(edPub),
  ml_dsa_pub:             hex(ml.publicKey),
  ed25519_sig:            b64(edSig),
  ml_dsa_sig:             b64(mlSig),
  envelope:               validEnvelope,
  negative_fixtures: {
    tampered_payload: {
      description:
        'Payload body has one byte changed -- both sigs must fail',
      envelope: tamperedEnvelope,
    },
    ml_dsa_sig_stripped: {
      description:
        'ml-dsa-65 signature removed from signatures array -- must REJECT with missing-ml-dsa-65',
      envelope: mlStrippedEnvelope,
    },
    wrong_payload_type: {
      description:
        'payloadType changed -- PAE changes so both sigs must fail',
      envelope: wrongTypeEnvelope,
    },
  },
}

const outPath = join(outDir, 'mldsa-hybrid-interop.json')
writeFileSync(outPath, JSON.stringify(output, null, 2) + '\n')

process.stdout.write('Wrote WASM interop vectors:\n')
process.stdout.write(`  ${outPath}\n`)
process.stdout.write(`  ed25519_pub: ${hex(edPub).length} hex chars (${edPub.length} bytes)\n`)
process.stdout.write(`  ml_dsa_pub:  ${hex(ml.publicKey).length} hex chars (${ml.publicKey.length} bytes)\n`)
process.stdout.write(`  ed25519_sig: ${edSig.length} bytes\n`)
process.stdout.write(`  ml_dsa_sig:  ${mlSig.length} bytes\n`)
process.stdout.write(`  pae_hex (first 80): ${hex(paeBytes).substring(0, 80)}\n`)
