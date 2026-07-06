// test/governed-action-xlang-conformance.test.ts
//
// Cross-language governed-action receipt verify conformance test.
//
// Exercises the governed-action-receipt-xlang.json fixture (Rust-emitted
// receipt-v2 CDROs) against the SHIPPED @synoi/verify verifyReceiptV2 public
// verifier. This is the Rust-produces / TS-verifies direction, closing the
// cross-language gap documented in governed-action-receipt-cdro.json.
//
// Vectors:
//   POSITIVE allow  -- governed-action.allowed receipt + [7,8] keys -> ACCEPT
//   POSITIVE deny   -- governed-action.denied  receipt + [7,8] keys -> ACCEPT
//   NEGATIVE tamper -- byte-flipped payload -> REJECT (payload-core-mismatch)
//   NEGATIVE wrong-key -- [7,8]-signed receipt under [9,10] keys -> REJECT
//
// These four assertions make the positive result non-vacuous: tamper and
// wrong-key controls both produce REJECT, proving the verifier binds content
// AND key.
//
// TAG: PARTIAL-against-test-keys. TEST KEYS ONLY.
// No AI attribution. No em dashes.

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyReceiptV2 } from '@synoi/verify'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ed25519 as nobleEd } from '@noble/curves/ed25519'

const here      = dirname(fileURLToPath(import.meta.url))
const vectorDir = join(here, '..', 'vectors', 'wasm-shell')

// ── Helpers ────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`odd-length hex: ${hex.length}`)
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    out[i >> 1] = parseInt(hex.slice(i, i + 2), 16)
  }
  return out
}

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

// ── Load fixture ───────────────────────────────────────────────────────────

interface XlangFixture {
  schema:          string
  tag:             string
  ed25519_pub_hex: string
  ml_dsa_pub_hex:  string
  allow_receipt:   Record<string, unknown>
  deny_receipt:    Record<string, unknown>
}

const fixturePath = join(vectorDir, 'governed-action-receipt-xlang.json')
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as XlangFixture

ok('xlang-fixture-schema', fixture.schema === 'governed-action-receipt-xlang/1',
  `got schema=${fixture.schema}`)
ok('xlang-fixture-tag', fixture.tag === 'PARTIAL-against-test-keys',
  `got tag=${fixture.tag}`)

const ed25519_pub = hexToBytes(fixture.ed25519_pub_hex)
const ml_dsa_pub  = hexToBytes(fixture.ml_dsa_pub_hex)

ok('xlang-ed-pub-len',   ed25519_pub.length === 32,   `len=${ed25519_pub.length}`)
ok('xlang-ml-pub-len',   ml_dsa_pub.length === 1952,  `len=${ml_dsa_pub.length}`)

// Wrong-key set: seeds [9,0,...,0,9] for Ed25519 and ML-DSA-65.
const wrongEdSeed = new Uint8Array(32); wrongEdSeed[0] = 9; wrongEdSeed[31] = 9
const wrongMlSeed = new Uint8Array(32); wrongMlSeed[0] = 9; wrongMlSeed[31] = 9
const wrong_ed25519_pub = nobleEd.getPublicKey(wrongEdSeed)
const wrong_ml_dsa_pub  = ml_dsa65.keygen(wrongMlSeed).publicKey

async function main(): Promise<void> {
  // ── POSITIVE 1: governed-action.allowed receipt ──────────────────────────
  const allowResult = await verifyReceiptV2({
    receipt:     fixture.allow_receipt,
    ed25519_pub,
    ml_dsa_pub,
  })
  ok('xlang-allow-receipt-accept',
    allowResult.valid,
    `valid=${allowResult.valid} reasons=${JSON.stringify(allowResult.reasons)}`)
  ok('xlang-allow-receipt-subject',
    fixture.allow_receipt['subject'] === 'governed-action.allowed',
    `subject=${String(fixture.allow_receipt['subject'])}`)
  ok('xlang-allow-receipt-scheme',
    fixture.allow_receipt['receipt_scheme'] === 'synoi.receipt/v2',
    `scheme=${String(fixture.allow_receipt['receipt_scheme'])}`)

  // ── POSITIVE 2: governed-action.denied receipt ────────────────────────────
  const denyResult = await verifyReceiptV2({
    receipt:     fixture.deny_receipt,
    ed25519_pub,
    ml_dsa_pub,
  })
  ok('xlang-deny-receipt-accept',
    denyResult.valid,
    `valid=${denyResult.valid} reasons=${JSON.stringify(denyResult.reasons)}`)
  ok('xlang-deny-receipt-subject',
    fixture.deny_receipt['subject'] === 'governed-action.denied',
    `subject=${String(fixture.deny_receipt['subject'])}`)

  // ── NEGATIVE 1: tampered content (payload-core-mismatch control) ──────────
  const tampered = JSON.parse(JSON.stringify(fixture.allow_receipt)) as Record<string, unknown>
  const att = tampered['attestation'] as Record<string, unknown>
  const orig = String(att['payload'] ?? '')
  // Flip the first character. Canonical payload always starts with '{'.
  att['payload'] = orig.length > 0
    ? (orig[0] === '{' ? '}' + orig.slice(1) : '{' + orig.slice(1))
    : '_tampered_'

  const tamperResult = await verifyReceiptV2({
    receipt:     tampered,
    ed25519_pub,
    ml_dsa_pub,
  })
  ok('xlang-tamper-reject',
    !tamperResult.valid,
    `valid=${tamperResult.valid} reasons=${JSON.stringify(tamperResult.reasons)}`)
  ok('xlang-tamper-reject-reason',
    !tamperResult.valid && tamperResult.reasons.includes('payload-core-mismatch'),
    `reasons=${JSON.stringify(tamperResult.reasons)}`)

  // ── NEGATIVE 2: wrong public key (key-binding control) ────────────────────
  const wrongKeyResult = await verifyReceiptV2({
    receipt:     fixture.allow_receipt,
    ed25519_pub: wrong_ed25519_pub,
    ml_dsa_pub:  wrong_ml_dsa_pub,
  })
  ok('xlang-wrong-key-reject',
    !wrongKeyResult.valid,
    `valid=${wrongKeyResult.valid} reasons=${JSON.stringify(wrongKeyResult.reasons)}`)

  // ── Summary ───────────────────────────────────────────────────────────────
  process.stdout.write(`\ngoverned-action-xlang: ${passed} passed, ${failed} failed\n`)
  if (failed > 0) process.exit(1)
}

main().catch(err => {
  process.stderr.write(`ERROR: ${(err as Error).message}\n${(err as Error).stack ?? ''}\n`)
  process.exit(1)
})
