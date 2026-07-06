// vectors/_verify-governed-action-xlang.ts
//
// Cross-language governed-action receipt verify harness.
//
// Reads vectors/wasm-shell/governed-action-receipt-xlang.json (emitted by the
// Rust emit-governed-action-fixture bin in synoi-runtime-wt/runtime/b1-harness)
// and calls @synoi/verify verifyReceiptV2 on each fixture.
//
// Asserts:
//   POSITIVE (allow): Rust-emitted allowed receipt + [7,8] keys -> ACCEPT
//   POSITIVE (deny):  Rust-emitted denied receipt  + [7,8] keys -> ACCEPT
//   NEGATIVE-1 (tamper):    byte-flipped content -> REJECT (payload-core-mismatch)
//   NEGATIVE-2 (wrong key): [7,8]-signed receipt under [9,10] keys -> REJECT
//
// The verifyReceiptV2 call is the SHIPPED @synoi/verify public verifier path
// (not a re-implementation). Both Ed25519 and ML-DSA-65 are AND-enforced by
// the library.
//
// Run standalone: npx tsx vectors/_verify-governed-action-xlang.ts
// Or via:        node --import tsx/esm vectors/_verify-governed-action-xlang.ts
//
// TAG: PARTIAL-against-test-keys. TEST KEYS ONLY.
// No AI attribution. No em dashes.

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { verifyReceiptV2 } from '../../synoi-verify/src/verify.ts'

const here    = dirname(fileURLToPath(import.meta.url))
const fixture = JSON.parse(
  readFileSync(join(here, 'wasm-shell', 'governed-action-receipt-xlang.json'), 'utf8'),
) as {
  ed25519_pub_hex: string
  ml_dsa_pub_hex:  string
  allow_receipt:   Record<string, unknown>
  deny_receipt:    Record<string, unknown>
}

// ── Key reconstruction ──────────────────────────────────────────────────────
//
// The fixture carries the Rust-derived public key bytes as hex. We decode them
// here so the TS verifier uses the SAME public keys the Rust signer used.
// The hex strings were emitted by the Rust generator from:
//   SHELL_RECEIPT_ED_SEED = [7, 0, 0, ..., 0, 7]   (ed25519_dalek: from_bytes)
//   SHELL_RECEIPT_ML_SEED = [8, 0, 0, ..., 0, 8]   (ml_dsa::from_seed)
//
// Cross-language key consistency note: the noble and ml_dsa crate both implement
// FIPS 204 KeyGen (ML-DSA-65 from a 32-byte seed) deterministically. The Ed25519
// public key is the RFC 8032 scalar multiple of the seed, identical in both libs.
// The fixture's pub-key hex is the ground truth; the harness decodes it rather
// than rederiving from seeds to avoid an independent derivation that could mask
// a seed-format mismatch.

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`odd-length hex: ${hex.length}`)
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    out[i >> 1] = parseInt(hex.slice(i, i + 2), 16)
  }
  return out
}

const ed25519_pub = hexToBytes(fixture.ed25519_pub_hex)
const ml_dsa_pub  = hexToBytes(fixture.ml_dsa_pub_hex)

// Wrong-key set: ML-DSA-65 from seed [9,0,...,0,9] / [10,0,...,0,10].
// These are different keys from the signer keys; the verifier must reject.
// Ed25519 wrong key: seed [9,0,...,0,9] -> use noble ed25519 to derive.
import { ed25519 as nobleEd } from '@noble/curves/ed25519'
const wrongEdSeed = new Uint8Array(32); wrongEdSeed[0] = 9; wrongEdSeed[31] = 9
const wrongMlSeed = new Uint8Array(32); wrongMlSeed[0] = 10; wrongMlSeed[31] = 10
const wrong_ed25519_pub = nobleEd.getPublicKey(wrongEdSeed)
const wrong_ml_dsa_pub  = ml_dsa65.keygen(wrongMlSeed).publicKey

// ── Test runner ─────────────────────────────────────────────────────────────

let passed = 0
let failed = 0

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++
    process.stdout.write(`PASS  ${label}\n`)
  } else {
    failed++
    process.stdout.write(`FAIL  ${label}${detail ? '  -- ' + detail : ''}\n`)
  }
}

async function main(): Promise<void> {
  // ── POSITIVE 1: allowed receipt under [7,8] keys ──────────────────────────
  const allowResult = await verifyReceiptV2({
    receipt:     fixture.allow_receipt,
    ed25519_pub,
    ml_dsa_pub,
  })
  ok(
    'xlang-allow-receipt-accept',
    allowResult.valid,
    `valid=${allowResult.valid} reasons=${JSON.stringify(allowResult.reasons)}`,
  )
  ok(
    'xlang-allow-receipt-both-sigs',
    allowResult.valid && allowResult.reasons.length === 0,
    `reasons=${JSON.stringify(allowResult.reasons)}`,
  )

  // ── POSITIVE 2: denied receipt under [7,8] keys ───────────────────────────
  const denyResult = await verifyReceiptV2({
    receipt:     fixture.deny_receipt,
    ed25519_pub,
    ml_dsa_pub,
  })
  ok(
    'xlang-deny-receipt-accept',
    denyResult.valid,
    `valid=${denyResult.valid} reasons=${JSON.stringify(denyResult.reasons)}`,
  )

  // ── NEGATIVE 1: tampered content (byte flip in attestation payload) ────────
  // Flip the first character of the envelope payload to break the content-core
  // bind check. This causes the TS verifier to reject at the payload-core-mismatch
  // step, before even checking the signature.
  const tamperedReceipt = JSON.parse(JSON.stringify(fixture.allow_receipt)) as Record<string, unknown>
  const tamperedAttestation = tamperedReceipt['attestation'] as Record<string, unknown>
  const origPayload = String(tamperedAttestation['payload'])
  // Flip one byte: change the first char. The canonical payload always starts
  // with '{', so changing it to '}' breaks the JSON and the hash in one step.
  tamperedAttestation['payload'] = origPayload.slice(0, 1) === '{'
    ? '}' + origPayload.slice(1)
    : origPayload.slice(0, -1) + (origPayload.slice(-1) === '}' ? '{' : '}')

  const tamperResult = await verifyReceiptV2({
    receipt:     tamperedReceipt,
    ed25519_pub,
    ml_dsa_pub,
  })
  ok(
    'xlang-tamper-reject',
    !tamperResult.valid,
    `valid=${tamperResult.valid} reasons=${JSON.stringify(tamperResult.reasons)}`,
  )
  ok(
    'xlang-tamper-reject-reason',
    !tamperResult.valid && tamperResult.reasons.includes('payload-core-mismatch'),
    `reasons=${JSON.stringify(tamperResult.reasons)}`,
  )

  // ── NEGATIVE 2: wrong public key ([9,10] instead of [7,8]) ────────────────
  // The receipt was signed with [7,8] keys; presenting it under [9,10] keys
  // must cause signature verification to reject both Ed25519 and ML-DSA-65.
  const wrongKeyResult = await verifyReceiptV2({
    receipt:     fixture.allow_receipt,
    ed25519_pub: wrong_ed25519_pub,
    ml_dsa_pub:  wrong_ml_dsa_pub,
  })
  ok(
    'xlang-wrong-key-reject',
    !wrongKeyResult.valid,
    `valid=${wrongKeyResult.valid} reasons=${JSON.stringify(wrongKeyResult.reasons)}`,
  )

  // ── Summary ───────────────────────────────────────────────────────────────
  process.stdout.write(`\n--- ${passed} passed, ${failed} failed ---\n`)
  if (failed > 0) process.exit(1)
}

main().catch(err => {
  process.stderr.write(`ERROR: ${(err as Error).message}\n${(err as Error).stack ?? ''}\n`)
  process.exit(1)
})
