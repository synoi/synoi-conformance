// vectors/_gen-adr019-projection.ts - ADR_019 (L0 Normative Contract
// Unification) cross-language projection vectors, GENERATED from the
// @synoi/sraid reference implementation. Run with `npm run gen:adr019`.
//
// PROVENANCE: generated-from-sraid. Every OID / canonical-bytes value emitted
// here is computed by @synoi/sraid `cdroOid` / `cdroContentCore` /
// `canonicalize` - the SINGLE NORMATIVE SOURCE per ADR_019 decision 3 and
// synoi-sraid/PROJECTION_SPEC.md. A consuming implementation that produces a
// different value for the same input is NON-CONFORMANT. These are the
// cross-language ABI vectors the ADR_019 CI gate replays against every impl
// that must agree (@synoi/sraid, @synoi/verify, GAP TS/Python/Rust/Go, and the
// gateway signer projection).
//
// WHY THESE VECTORS EXIST (the bug they would have caught):
// The original divergence - four incompatible content-core strip-sets across
// seven surfaces - stayed invisible because NO shared vector ever carried
// {attestation, supersedes, gap_version} together. On a vector missing those
// fields, a 3-strip projection (sraid, KEEPS gap_version+supersedes) and a
// 5-strip projection (GAP-TS/Python/Rust, DROPS them) and a 6-strip Go
// projection produce a byte-identical content core, so every divergent copy
// tested green. In production the live v2 signer ALWAYS stamps gap_version
// and often supersedes, so a third party following IMPLEMENTING.md recomputed
// a DIFFERENT OID and wrongly declared a valid receipt tampered. This breaks
// "approved before it runs, provable after."
//
// FIX: every projection vector below CARRIES attestation AND supersedes AND
// gap_version, so any strip-set divergence turns a vector RED.
//
// Three vector files are written to vectors/adr019/ (their own directory,
// separate from vectors/sraid/):
//   - adr019/cdro-contentcore-mixed.json  - the keystone mixed vector
//   - adr019/receipt-v2-supersedes.json   - receipt-v2 carrying gap_version+supersedes
//   - adr019/float-reject.json            - float-bearing inputs are expected-reject
//
// Keys are DETERMINISTIC (fixed seeds) so the vectors are byte-stable across
// regeneration; the canonical bytes, OID, and signatures are load-bearing.

import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  canonicalize,
  cdroContentCore,
  cdroOid,
  CDRO_ENVELOPE_FIELDS,
  pae,
} from '@synoi/sraid'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

const here = dirname(fileURLToPath(import.meta.url))
// ADR_019 vectors live in their OWN directory, NOT vectors/sraid/. They carry
// bespoke kinds (cdro_content_core, float-reject with a JSON `input`) consumed
// by test/adr019-projection-conformance.test.ts and the cross-language gate;
// they are intentionally NOT swept by the generic sraid protocol runner (which
// only understands its own vector shapes).
const outDir = join(here, 'adr019')
mkdirSync(outDir, { recursive: true })

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')

// ── Constants (mirror @synoi/verify; conformance stays dependency-free of it) ─

const V2_PAYLOAD_TYPE = 'application/vnd.synoi.gap+json' // ADR_007 payloadType split

// ── Deterministic hybrid keys ────────────────────────────────────────────────

const ed_priv = new Uint8Array(32)
for (let i = 0; i < 32; i++) ed_priv[i] = (i * 11 + 5) & 0xff
const ed_pub = ed25519.getPublicKey(ed_priv)

const ml = ml_dsa65.keygen(new Uint8Array(32).fill(19))

const ed_pub_b64 = b64(ed_pub)
const ml_pub_b64 = b64(ml.publicKey)

// ─────────────────────────────────────────────────────────────────────────────
// The representative full CDRO. This is `baseCdro` from
// synoi-sraid/test/oid.test.ts, carrying the three fields whose absence hid the
// bug: gap_version, supersedes, AND (once signed) attestation. Its OID under
// the normative sraid projection is the published keystone value
// sha256:476e1c2a…52d1 (PROJECTION_SPEC.md §2.3).
// ─────────────────────────────────────────────────────────────────────────────

function baseCdro(): Record<string, unknown> {
  return {
    type: 'gap:decision_receipt',
    sraid_version: '2.0',
    gap_version: '1.0',
    tenant_id: 'tenant-x',
    created_at_ms: 1_720_000_000_000,
    created_by: 'sha256:' + 'c'.repeat(64),
    body: { decision: 'allow', amount_minor: 1299 },
    authority: { grant_oid: 'sha256:' + 'a'.repeat(64), decision: 'allow' },
    supersedes: 'sha256:' + 'b'.repeat(64),
  }
}

// Mint the full hybrid DSSE attestation over the content core.
function mintEnvelope(cdro: Record<string, unknown>) {
  const payload = canonicalize(cdroContentCore(cdro))
  const message = pae(V2_PAYLOAD_TYPE, payload)
  // ML-DSA-65 signing is HEDGED (randomized) by default in @noble/post-quantum,
  // which would make the emitted vectors non-deterministic across regeneration.
  // `extraEntropy: false` selects the DETERMINISTIC (non-hedged) FIPS 204 mode,
  // so the same (message, key) always yields byte-identical signatures - a hard
  // requirement for a committed golden vector. Verification is identical for
  // hedged and deterministic signatures, so a live signer using the hedged mode
  // still verifies against this vector; only the emitted bytes are pinned.
  return {
    payloadType: V2_PAYLOAD_TYPE,
    payload,
    signatures: [
      { alg: 'ed25519', sig: b64(ed25519.sign(message, ed_priv)) },
      { alg: 'ml-dsa-65', sig: b64(ml_dsa65.sign(message, ml.secretKey, { extraEntropy: false })) },
    ],
  }
}

// The signer-attached detached fields (the six ADR_019 envelope fields, minus
// `oid` which the signer stamps separately). A post-attestation object carries
// ALL of these; cdroContentCore must strip every one so the OID is invariant.
function attachAllDetachedFields(
  cdro: Record<string, unknown>,
): Record<string, unknown> {
  const env = mintEnvelope(cdro)
  return {
    ...cdro,
    // the OID the signer stamps as output (must not feed back into the hash)
    oid: cdroOid(cdro),
    // DSSE attestation envelope
    attestation: env,
    // legacy hybrid SignatureEnvelope (also detached)
    signature: {
      ed25519: env.signatures[0]!.sig,
      ml_dsa_65: env.signatures[1]!.sig,
      signer_kid: 'k-adr019',
    },
    // the remaining three detached signer-stamped fields
    ml_dsa_signature: env.signatures[1]!.sig,
    signature_key_id: 'k-adr019',
    signature_algorithm: 'ed25519+ml-dsa-65',
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// FILE 1 - adr019/cdro-contentcore-mixed.json
//
// The keystone. ONE object carrying ALL of {oid, gap_version, supersedes,
// attestation, hybrid-signature fields}. Its `expected_oid` is computed by
// sraid `cdroOid` and MUST equal the OID of the SAME object with the detached
// fields absent (pre-attestation). This is the pre/post-attestation identity
// invariant of PROJECTION_SPEC.md §2.3 - the single property the whole
// "independently verifiable receipt" thesis rests on.
//
// A 5-strip GAP projection (drops gap_version+supersedes) or a Go 6-strip
// projection (drops gap_version+supersedes, keeps ml_dsa_signature +
// signature_algorithm) computes a DIFFERENT content core here, so it fails
// `expected_content_core` and `expected_oid`. That is the divergence the
// original suite could not see.
// ═════════════════════════════════════════════════════════════════════════════

const pre = baseCdro()
const post = attachAllDetachedFields(pre)

// Sanity: sraid must agree pre === post, and both must equal the published
// keystone. If not, the reference moved - FAIL the gen deterministically rather
// than emit a stale vector.
// ADR_020 Wave 2: this OID changed by design (M1-M6 rename the hashed type/
// version bytes). The value below was recomputed from the reference
// @synoi/sraid after the sraid_version/gap:decision_receipt migration; the
// old value was sha256:476e1c2a514bf2afe315b9a8a08e574bb58c734e12ac1aa2f784315abeca52d1.
// synoi-sraid PROJECTION_SPEC.md §2.3 (line ~108) pins the SAME old value and
// must be updated to match in the synoi-sraid repo (out of this repo's scope).
const KEYSTONE_OID = 'sha256:d1d5d5c51d2d5f80470089ff10b8b642e19fc76db6be298f4f346616528a087a'
{
  const preOid = cdroOid(pre)
  const postOid = cdroOid(post)
  if (preOid !== postOid) {
    process.stderr.write(
      `FATAL: pre-attestation OID !== post-attestation OID\n  pre : ${preOid}\n  post: ${postOid}\n`,
    )
    process.exit(1)
  }
  if (preOid !== KEYSTONE_OID) {
    process.stderr.write(
      `FATAL: reference keystone OID drifted\n  got     : ${preOid}\n  expected: ${KEYSTONE_OID}\n` +
        `If PROJECTION_SPEC.md §2.3 changed intentionally, update KEYSTONE_OID here.\n`,
    )
    process.exit(1)
  }
  // Confirm the post object literally carries every detached field, so the
  // vector actually exercises the strip.
  for (const f of CDRO_ENVELOPE_FIELDS) {
    if (!(f in post)) {
      process.stderr.write(`FATAL: post object is missing detached field "${f}"\n`)
      process.exit(1)
    }
  }
}

const mixedVectors = [
  {
    name: 'adr019: content core keeps gap_version+supersedes (pre-attestation)',
    kind: 'cdro_content_core',
    // The bare pre-attestation object (no detached fields).
    input: pre,
    expected_content_core: canonicalize(cdroContentCore(pre)),
    expected_oid: cdroOid(pre),
  },
  {
    name: 'adr019: KEYSTONE - post-attestation object strips all six detached fields to the SAME OID',
    kind: 'cdro_content_core',
    // The SAME object, now carrying oid + attestation + signature +
    // ml_dsa_signature + signature_key_id + signature_algorithm.
    input: post,
    // MUST equal the pre-attestation values above (identity invariant).
    expected_content_core: canonicalize(cdroContentCore(post)),
    expected_oid: cdroOid(post),
    // The six fields a conformant cdroContentCore MUST remove. A projection
    // that removes a different set (e.g. also gap_version/supersedes) reddens.
    detached_fields: [...CDRO_ENVELOPE_FIELDS],
    // Fields that MUST survive into the content core (the ones the divergent
    // strip-sets wrongly dropped). Verifiers assert these are present.
    identity_fields_present: ['gap_version', 'supersedes', 'authority', 'body', 'type'],
    // Cross-link to the pre-attestation vector: these two OIDs are byte-identical.
    equals_oid_of: 'adr019: content core keeps gap_version+supersedes (pre-attestation)',
    keystone: true,
  },
  {
    name: 'adr019: changing supersedes changes the OID (supersedes IS in identity)',
    kind: 'cdro_content_core',
    input: (() => {
      const c = baseCdro()
      c.supersedes = 'sha256:' + 'e'.repeat(64)
      return c
    })(),
    expected_content_core: canonicalize(
      cdroContentCore((() => { const c = baseCdro(); c.supersedes = 'sha256:' + 'e'.repeat(64); return c })()),
    ),
    expected_oid: cdroOid((() => { const c = baseCdro(); c.supersedes = 'sha256:' + 'e'.repeat(64); return c })()),
    // Its OID MUST differ from the keystone (proves supersedes is hashed).
    must_differ_from_oid: cdroOid(pre),
  },
  {
    name: 'adr019: protocol downgrade of gap_version changes the OID',
    kind: 'cdro_content_core',
    input: (() => {
      const c = baseCdro()
      c.gap_version = '0.9'
      return c
    })(),
    expected_content_core: canonicalize(
      cdroContentCore((() => { const c = baseCdro(); c.gap_version = '0.9'; return c })()),
    ),
    expected_oid: cdroOid((() => { const c = baseCdro(); c.gap_version = '0.9'; return c })()),
    must_differ_from_oid: cdroOid(pre),
  },
]

writeFileSync(
  join(outDir, 'cdro-contentcore-mixed.json'),
  JSON.stringify(mixedVectors, null, 2) + '\n',
)

// ═════════════════════════════════════════════════════════════════════════════
// FILE 2 - adr019/receipt-v2-supersedes.json
//
// A receipt-v2 REISSUED to CARRY gap_version + supersedes (the existing
// receipt-v2.json carries neither, which is exactly why the projections
// coexisted green). A live gateway signGapReceiptV2 and an IMPLEMENTING.md
// follower must both bind canonicalize(cdroContentCore(receipt)) - which now
// INCLUDES gap_version+supersedes - to the envelope payload and hybrid-verify.
// A verifier on a divergent strip-set recomputes a different content core, so
// `payload` no longer equals its recomputed bytes → payload-core-mismatch.
// ═════════════════════════════════════════════════════════════════════════════

function receiptWithSupersedes(): Record<string, unknown> {
  return {
    type: 'gap:decision_receipt',
    sraid_version: '2.0',
    gap_version: '1.0',
    tenant_id: 'founder',
    created_at_ms: 1_747_584_000_000,
    created_by: 'sha256:' + 'a'.repeat(64),
    supersedes: 'sha256:' + 'd'.repeat(64),
    body: {
      decision: 'allow',
      action_class: 'B',
      risk_level: 'low',
      settlement: { cost: { amount_minor: 1200, currency: 'usd' } },
    },
  }
}

const receiptVectors: Array<Record<string, unknown>> = []

// 0. Canonical-bytes + OID binding: the content core INCLUDES gap_version +
//    supersedes. Emitted EXACTLY so a divergent strip-set reddens here first.
{
  const receipt = receiptWithSupersedes()
  receiptVectors.push({
    name: 'adr019 receipt-v2: content core INCLUDES gap_version+supersedes (canonical)',
    kind: 'receipt_v2',
    mode: 'canonical',
    receipt,
    expected_content_core: canonicalize(cdroContentCore(receipt)),
    expected_oid: cdroOid(receipt),
  })
}

// 1. Valid hybrid receipt (carrying gap_version+supersedes) → TRUE.
{
  const receipt = receiptWithSupersedes()
  receipt.attestation = mintEnvelope(receipt)
  receiptVectors.push({
    name: 'adr019 receipt-v2: valid hybrid receipt with gap_version+supersedes verifies TRUE',
    kind: 'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64: ml_pub_b64,
    expected_valid: true,
  })
}

// 2. supersedes tampered AFTER signing → content-core bind fails. A verifier
//    that (wrongly) strips supersedes from the core would MISS this tamper and
//    pass it - so this vector reddens any strip-supersedes projection two ways:
//    a conformant verifier REJECTS (mismatch), a strip-supersedes verifier
//    wrongly ACCEPTS.
{
  const receipt = receiptWithSupersedes()
  receipt.attestation = mintEnvelope(receipt)
  receipt.supersedes = 'sha256:' + '9'.repeat(64) // re-point the lineage edge
  receiptVectors.push({
    name: 'adr019 receipt-v2: supersedes re-pointed after signing → REJECT (payload-core-mismatch)',
    kind: 'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64: ml_pub_b64,
    expected_valid: false,
    expected_reason: 'payload-core-mismatch',
  })
}

// 3. gap_version downgraded AFTER signing → content-core bind fails (a verifier
//    that strips gap_version would miss a protocol downgrade).
{
  const receipt = receiptWithSupersedes()
  receipt.attestation = mintEnvelope(receipt)
  receipt.gap_version = '0.9'
  receiptVectors.push({
    name: 'adr019 receipt-v2: gap_version downgraded after signing → REJECT (payload-core-mismatch)',
    kind: 'receipt_v2',
    receipt,
    ed25519_pub_b64: ed_pub_b64,
    ml_dsa_pub_b64: ml_pub_b64,
    expected_valid: false,
    expected_reason: 'payload-core-mismatch',
  })
}

writeFileSync(
  join(outDir, 'receipt-v2-supersedes.json'),
  JSON.stringify(receiptVectors, null, 2) + '\n',
)

// ═════════════════════════════════════════════════════════════════════════════
// FILE 3 - adr019/float-reject.json
//
// ADR_019 decision 2: a number is legal iff it is a finite integer. A
// float-bearing input is EXPECTED-REJECT before hashing. The live signing path
// (sraid) and GAP-TS/Python already reject; these vectors pin the contract so a
// permissive canonicalizer that mints an OID over a float reddens.
// ═════════════════════════════════════════════════════════════════════════════

// Confirm sraid rejects each float input (the vectors are only meaningful if
// the reference truly throws).
function sraidRejects(input: unknown): boolean {
  try {
    cdroOid(input)
    return false
  } catch {
    return true
  }
}

const floatInputs: Array<{ name: string; input: unknown }> = [
  {
    name: 'top-level float',
    input: 3.14,
  },
  {
    name: 'float in receipt body (amount as major-unit float)',
    input: (() => { const c = baseCdro(); (c.body as Record<string, unknown>).amount = 12.99; return c })(),
  },
  {
    name: 'nested fractional rate',
    input: (() => { const c = baseCdro(); c.body = { rate: { pct: 0.5 } }; return c })(),
  },
  {
    name: 'float array element',
    input: (() => { const c = baseCdro(); c.body = { rates: [1, 2, 3.5] }; return c })(),
  },
  {
    name: 'negative float',
    input: (() => { const c = baseCdro(); (c.body as Record<string, unknown>).delta = -0.25; return c })(),
  },
  {
    name: 'exponent-form non-integer',
    input: (() => { const c = baseCdro(); (c.body as Record<string, unknown>).tiny = 2e-3; return c })(),
  },
]

// NOTE: NaN / Infinity are deliberately NOT file vectors. They are not
// JSON-representable (JSON.stringify(NaN) === 'null'), so a JSON conformance
// vector CANNOT carry them - a round-trip silently rewrites them to null, an
// integer-legal value, and the "reject" assertion becomes vacuous. Non-finite
// rejection is covered by @synoi/sraid's in-process unit tests
// (canonicalize.test.ts), not by a cross-language JSON vector. The finite
// non-integer vectors above fully exercise ADR_019 decision 2's
// "a number is legal iff it is a finite INTEGER" rule across languages.

const floatVectors = floatInputs.map(({ name, input }) => {
  // Guard 1: sraid must reject the in-memory input.
  if (!sraidRejects(input)) {
    process.stderr.write(`FATAL: sraid did NOT reject float vector "${name}"\n`)
    process.exit(1)
  }
  // Guard 2: the input must SURVIVE a JSON round-trip and STILL reject. This
  // catches any value (like NaN) that JSON rewrites into a legal one, so a
  // committed vector can never be a vacuous "reject" that actually parses clean.
  const roundTripped = JSON.parse(JSON.stringify(input))
  if (!sraidRejects(roundTripped)) {
    process.stderr.write(
      `FATAL: float vector "${name}" does NOT reject after a JSON round-trip ` +
        `(the float was rewritten by JSON.stringify; it cannot be a file vector)\n`,
    )
    process.exit(1)
  }
  return {
    name: `adr019 float-reject: ${name}`,
    kind: 'canonicalize_reject',
    input,
    expected: 'reject',
    // The number rule that must fire: finite integers only (ADR_019 decision 2).
    reason: 'non-integer-number-forbidden',
  }
})

writeFileSync(
  join(outDir, 'float-reject.json'),
  JSON.stringify(floatVectors, null, 2) + '\n',
)

// ── Summary ──────────────────────────────────────────────────────────────────

process.stdout.write('Wrote ADR_019 projection vectors (generated-from-sraid):\n')
process.stdout.write(
  `  adr019/cdro-contentcore-mixed.json  ${mixedVectors.length} vectors (keystone OID ${KEYSTONE_OID.slice(0, 15)}…)\n`,
)
process.stdout.write(
  `  adr019/receipt-v2-supersedes.json   ${receiptVectors.length} vectors (carries gap_version+supersedes)\n`,
)
process.stdout.write(
  `  adr019/float-reject.json            ${floatVectors.length} vectors (float = expected-reject)\n`,
)
process.stdout.write(
  `  mixed keystone proof: cdroOid(pre) === cdroOid(post) === ${cdroOid(pre)}\n`,
)
