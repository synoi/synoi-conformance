// vectors/_gen-receipt-v1-canonical.ts - cross-package golden vectors proving
// the v1 Decision Receipt canonical form is byte-identical across:
//   - the SIGNER canonicalizer (@synoi/sraid `canonicalize`, RFC 8785 JCS), and
//   - the flat scalar projection the gateway signer emits (JSON.stringify), and
//   - any reimplementation (e.g. @synoi/verify) run through the conformance test.
//
// A language-independent reimplementation must reproduce `expected_canonical`
// byte-for-byte from `receipt` (over the sorted scalar canonical-field
// projection) to agree with the SynOI signer. Run with `npm run gen:receipt-v1`.
//
// Output: vectors/receipt-v1/canonical.json
//
// NOTE: this lives in its own vectors/receipt-v1/ dir (NOT vectors/sraid/) so
// the SRAID protocol runner - which sweeps every .json in vectors/sraid/ and
// dispatches by `kind` - does not see this `receipt_v1_canonical` kind. This
// is a cross-package canonicalization proof consumed by
// test/receipt-v1-canonical-conformance.test.ts, not a SRAID-protocol vector.

import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize } from '@synoi/sraid'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, 'receipt-v1')
mkdirSync(outDir, { recursive: true })

// The v1 canonical-field allow-list the signer projects the receipt onto
// (verify-router.ts / @synoi/verify canonicalPayload). All scalar.
const CANONICAL_FIELDS = [
  'action_class', 'decision', 'oid_hex', 'receipt_id',
  'recorded_at', 'risk_level', 'tenant_id',
]
const OPTIONAL = ['gateway_manifest_sha256']

// The SIGNER's flat projection: JSON.stringify over the sorted scalar
// projection, omitting undefined/null. This is the exact byte string the
// gateway signs (verify-router.ts:canonicalPayload).
function signerFlat(receipt: Record<string, unknown>): string {
  const obj: Record<string, unknown> = {}
  for (const k of [...CANONICAL_FIELDS, ...OPTIONAL].sort()) {
    const v = receipt[k]
    if (v !== undefined && v !== null) obj[k] = v
  }
  return JSON.stringify(obj)
}
// The JCS projection through the reference signer canonicalizer.
function jcsFlat(receipt: Record<string, unknown>): string {
  const obj: Record<string, unknown> = {}
  for (const k of [...CANONICAL_FIELDS, ...OPTIONAL].sort()) {
    const v = receipt[k]
    if (v !== undefined && v !== null) obj[k] = v
  }
  return canonicalize(obj)
}

const receipts: Array<{ name: string; receipt: Record<string, unknown> }> = [
  {
    name: 'ascii',
    receipt: {
      receipt_id: 'rcpt_ascii_01', tenant_id: 'founder', decision: 'allow',
      action_class: 'B', risk_level: 'low',
      oid_hex: 'sha256:' + '01'.repeat(32), recorded_at: 1747584000000,
    },
  },
  {
    name: 'unicode_tenant_and_action_class',
    receipt: {
      receipt_id: 'rcpt_uni_01', tenant_id: 'tенант-Ünïcøde', decision: 'deny',
      action_class: 'nét-wörk', risk_level: 'high',
      oid_hex: 'sha256:' + 'ab'.repeat(32), recorded_at: 1747584000001,
    },
  },
  {
    name: 'emoji_action_class',
    receipt: {
      receipt_id: 'rcpt_emoji_01', tenant_id: 't1', decision: 'allow',
      action_class: 'deploy-\u{1F680}', risk_level: 'medium',
      oid_hex: 'sha256:' + 'cd'.repeat(32), recorded_at: 1747584000002,
    },
  },
  {
    name: 'large_int_recorded_at_max_safe',
    receipt: {
      receipt_id: 'rcpt_bigint_01', tenant_id: 't1', decision: 'allow',
      action_class: 'B', risk_level: 'low',
      oid_hex: 'sha256:' + 'ef'.repeat(32), recorded_at: 9007199254740991,
    },
  },
  {
    name: 'with_gateway_manifest_sha256',
    receipt: {
      receipt_id: 'rcpt_manifest_01', tenant_id: 'founder', decision: 'allow',
      action_class: 'B', risk_level: 'low',
      oid_hex: 'sha256:' + '01'.repeat(32), recorded_at: 1747584000003,
      gateway_manifest_sha256: 'sha256:' + 'be'.repeat(32),
    },
  },
  {
    name: 'null_authority_field_omitted',
    receipt: {
      receipt_id: 'rcpt_null_01', tenant_id: 't1', decision: 'allow',
      action_class: 'B', risk_level: 'low',
      oid_hex: 'sha256:' + '02'.repeat(32), recorded_at: 1747584000004,
      gateway_manifest_sha256: null,
    },
  },
]

const vectors = receipts.map(({ name, receipt }) => {
  const signer = signerFlat(receipt)
  const jcs = jcsFlat(receipt)
  if (signer !== jcs) {
    process.stderr.write(
      `FATAL: signer flat vs JCS diverge for "${name}"\n  signer: ${signer}\n  jcs   : ${jcs}\n`,
    )
    process.exit(1)
  }
  return {
    name,
    kind: 'receipt_v1_canonical',
    canonical_fields: CANONICAL_FIELDS,
    optional_canonical_fields: OPTIONAL,
    receipt,
    // expected_canonical is byte-identical from BOTH the JCS reference signer
    // canonicalizer and the gateway's flat JSON.stringify projection.
    expected_canonical: signer,
  }
})

writeFileSync(
  join(outDir, 'canonical.json'),
  JSON.stringify(vectors, null, 2) + '\n',
)
process.stdout.write(`Wrote receipt-v1/canonical.json  ${vectors.length} vectors\n`)
