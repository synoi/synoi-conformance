// vectors/_gen-vault-roundtrip.ts
//
// Regenerates vectors/vault.canonical.roundtrip/roundtrip.json from the vault's
// binary field-region canonicalizer (synoi-vault/src/core/canonicalize.ts).
//
// Run: npm run gen:vault-roundtrip
//
// DEPENDENCY NOTE: @synoi/sraid exports only the JSON/JCS canonicalizer (RFC 8785).
// It does NOT export the binary field-region canonicalizer used by the vault
// (field_id LE uint16 || type_tag uint8 || varint length || encoded value).
// This means the conformance suite cannot currently attest the vault hash regime
// through its @synoi/sraid dependency alone. This is a conformance coverage gap.
//
// Consequence: the generator imports from the vault source directly via a relative
// path. This is intentional: the vault binary canonicalizer is the spec for this
// vector set, and the generator must stay byte-identical to it. If the vault
// canonicalizer is ever extracted into @synoi/sraid or a separate package, update
// this import and flag as a dependency change.
//
// A non-zero diff between the committed roundtrip.json and the freshly generated
// output means the committed expected_hash_match values have drifted from reality.

import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

// Import the vault's binary canonicalizer directly (not via @synoi/sraid).
// Adjust the relative path if this generator is moved.
import {
  canonicalizeAndHash,
  filterCanonicalFields,
} from '../../synoi-vault/src/core/canonicalize.js'
import { FieldType, FieldPolicyType, BioLevel } from '../../synoi-vault/src/types/index.js'
import type { CanonicalField, FieldPolicy } from '../../synoi-vault/src/types/index.js'

const here   = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, 'vault.canonical.roundtrip')

mkdirSync(outDir, { recursive: true })

// ── Helper: canonical hash hex for a single field ─────────────────────────────

function hashOf(field: CanonicalField): string | null {
  const policy: FieldPolicy = {
    field_id:          field.field_id,
    policy:            FieldPolicyType.REQUIRED_CANONICAL,
    importance_weight: 100,
    bio_level:         BioLevel.ATOM,
  }
  try {
    const filtered = filterCanonicalFields([field], [policy])
    const { canonical_hash } = canonicalizeAndHash(filtered)
    return Array.from(canonical_hash).map(b => b.toString(16).padStart(2, '0')).join('')
  } catch {
    return null
  }
}

// ── Simulate what JSON.stringify + JSON.parse does to each value type ──────────

function jsonRoundTrip(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value))
}

// ── Test cases (mirrors the Jest suite in synoi-vault/tests/canonical-roundtrip.test.ts) ─

interface VectorCase {
  name:                string
  field:               CanonicalField
  value_repr:          string
  original_value_note: string
  json_roundtrip_lossy: boolean
  expected_wrote_ok:   boolean   // whether JSON.stringify throws
  expected_hash_match: boolean
  loss_reason:         string
}

// For value_repr types that cannot be carried in JSON (bigint, -0, NaN, Uint8Array,
// ArrayBuffer), we reconstruct the live value and run both sides.

const CASES: VectorCase[] = [
  {
    name:                'int64_le_2p53_number',
    field:               { field_id: 1, type_tag: FieldType.INT64,   value: 9007199254740991 },
    value_repr:          'number',
    original_value_note: '9007199254740991 (Number.MAX_SAFE_INTEGER)',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'small int64 as JS number: JSON-safe; BigInt(x) stable on both write and read sides',
  },
  {
    name:                'int64_bigint',
    field:               { field_id: 1, type_tag: FieldType.INT64,   value: 9007199254740993n },
    value_repr:          'bigint',
    original_value_note: '9007199254740993n (exceeds Number.MAX_SAFE_INTEGER)',
    json_roundtrip_lossy: true,
    expected_wrote_ok:   false,
    expected_hash_match: false,
    loss_reason:         'bigint: JSON.stringify(BigInt) throws TypeError at edge-store.ts:257; write path crashes',
  },
  {
    name:                'uint64_bigint',
    field:               { field_id: 1, type_tag: FieldType.UINT64,  value: 18446744073709551615n },
    value_repr:          'bigint',
    original_value_note: '18446744073709551615n (UINT64_MAX)',
    json_roundtrip_lossy: true,
    expected_wrote_ok:   false,
    expected_hash_match: false,
    loss_reason:         'bigint: JSON.stringify(BigInt) throws TypeError at edge-store.ts:257; write path crashes',
  },
  {
    name:                'float64_positive',
    field:               { field_id: 1, type_tag: FieldType.FLOAT64, value: 3.14159 },
    value_repr:          'number',
    original_value_note: '3.14159',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'normal float: JSON round-trips exactly; IEEE-754 LE encoding stable',
  },
  {
    name:                'float64_one_point_zero',
    field:               { field_id: 1, type_tag: FieldType.FLOAT64, value: 1.0 },
    value_repr:          'number',
    original_value_note: '1.0',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         '1.0 survives as 1 in JSON; encodeFloat64(1) is stable',
  },
  {
    name:                'float64_neg_zero',
    field:               { field_id: 1, type_tag: FieldType.FLOAT64, value: -0 },
    value_repr:          'neg_zero',
    original_value_note: '-0 (negative zero)',
    json_roundtrip_lossy: true,
    expected_wrote_ok:   true,
    expected_hash_match: false,
    loss_reason: "JSON.stringify(-0) -> '0'; setFloat64(-0) sign bit differs from setFloat64(0); canonical hash diverges",
  },
  {
    name:                'float64_nan',
    field:               { field_id: 1, type_tag: FieldType.FLOAT64, value: NaN },
    value_repr:          'nan',
    original_value_note: 'NaN',
    json_roundtrip_lossy: true,
    expected_wrote_ok:   true,
    expected_hash_match: false,
    loss_reason:         "JSON.stringify(NaN) -> 'null'; JSON.parse -> null; encodeFloat64(null) throws TypeError on read-side recompute",
  },
  {
    name:                'string_ascii',
    field:               { field_id: 1, type_tag: FieldType.STRING,  value: 'hello world' },
    value_repr:          'string',
    original_value_note: '"hello world"',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'ASCII string: JSON-safe; NFC normalization stable on both sides',
  },
  {
    name:                'string_non_nfc',
    field:               { field_id: 1, type_tag: FieldType.STRING,  value: 'é' },  // e + combining acute
    value_repr:          'non_nfc',
    original_value_note: '"e\\u0301" (e + combining acute accent, NFD form of é)',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'non-NFC input: encodeString NFC-normalizes on BOTH write and read sides; hash is normalization-invariant by construction',
  },
  {
    name:                'bytes_uint8array',
    field:               { field_id: 1, type_tag: FieldType.BYTES,   value: new Uint8Array([12, 255, 0, 1]) },
    value_repr:          'uint8array',
    original_value_note: 'Uint8Array([12, 255, 0, 1])',
    json_roundtrip_lossy: true,
    expected_wrote_ok:   true,
    expected_hash_match: false,
    loss_reason:         'Uint8Array: JSON.stringify -> index-keyed object {"0":12,...}; write does not throw; read-side encodeBytes rejects plain object; hash cannot be recomputed',
  },
  {
    name:                'bytes_arraybuffer',
    field:               { field_id: 1, type_tag: FieldType.BYTES,   value: new Uint8Array([7, 8, 9]).buffer },
    value_repr:          'arraybuffer',
    original_value_note: 'ArrayBuffer (bytes [7, 8, 9])',
    json_roundtrip_lossy: true,
    expected_wrote_ok:   true,
    expected_hash_match: false,
    loss_reason:         "ArrayBuffer: JSON.stringify -> '{}'; write does not throw; read-side encodeBytes rejects empty object; all data lost",
  },
  {
    name:                'bytes_number_array',
    field:               { field_id: 1, type_tag: FieldType.BYTES,   value: [200, 100, 50] },
    value_repr:          'number_array',
    original_value_note: '[200, 100, 50] (JS number[])',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'number[] survives JSON round-trip; encodeBytes accepts number[]; binary encoding identical on both sides; hash stable',
  },
  {
    name:                'bool_true',
    field:               { field_id: 1, type_tag: FieldType.BOOL,    value: true },
    value_repr:          'boolean',
    original_value_note: 'true',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'boolean: JSON-safe; encodeBool stable',
  },
  {
    name:                'null_field',
    field:               { field_id: 1, type_tag: FieldType.NULL,    value: null },
    value_repr:          'null',
    original_value_note: 'null',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'null: JSON-safe; encodeNull stable',
  },
  {
    name:                'list_json_safe_scalars',
    field:               { field_id: 1, type_tag: FieldType.LIST,    value: [[FieldType.INT64, 42], [FieldType.STRING, 'x']] },
    value_repr:          'list',
    original_value_note: '[[1, 42], [3, "x"]] (TypedValue tuples)',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'TypedValue tuples are arrays; JSON-safe scalar elements; hash stable',
  },
  {
    name:                'map_json_safe_values',
    field:               { field_id: 1, type_tag: FieldType.MAP,     value: { z: [FieldType.INT64, 1], a: [FieldType.STRING, 'v'] } },
    value_repr:          'map',
    original_value_note: '{ z: [1,1], a: [3,"v"] } (TypedValue map)',
    json_roundtrip_lossy: false,
    expected_wrote_ok:   true,
    expected_hash_match: true,
    loss_reason:         'plain object with JSON-safe TypedValues; encodeMap sorts keys; hash stable',
  },
]

// ── Compute ground-truth expected_hash_match for each case ────────────────────

const policy = (field_id: number): FieldPolicy => ({
  field_id,
  policy:            FieldPolicyType.REQUIRED_CANONICAL,
  importance_weight: 100,
  bio_level:         BioLevel.ATOM,
})

type VectorEntry = {
  name:                string
  kind:                string
  field:               { field_id: number; type_tag: number; value_repr: string; value: unknown }
  json_roundtrip_lossy: boolean
  expected_wrote_ok:   boolean
  expected_hash_match: boolean
  loss_reason:         string
}

const vectors: VectorEntry[] = CASES.map(tc => {
  const { field } = tc

  // Write-side hash (binary canonicalizer over the original value).
  const writeHash = hashOf(field)

  // Simulate JSON.stringify throw (for bigint).
  let wroteOk = true
  let jsonRoundTripped: unknown
  try {
    jsonRoundTripped = jsonRoundTrip(field.value)
  } catch {
    wroteOk = false
    jsonRoundTripped = undefined
  }

  // Read-side recompute (binary canonicalizer over the JSON-round-tripped value).
  let hashMatch = false
  if (wroteOk && writeHash !== null) {
    const readField: CanonicalField = { field_id: field.field_id, type_tag: field.type_tag, value: jsonRoundTripped }
    const readHash = hashOf(readField)
    hashMatch = readHash !== null && writeHash === readHash
  }

  // Validate that the computed verdict matches the committed expected value.
  if (wroteOk !== tc.expected_wrote_ok) {
    throw new Error(
      `[gen:vault-roundtrip] REGRESSION: ${tc.name}: expected_wrote_ok=${tc.expected_wrote_ok} but computed=${wroteOk}. ` +
      'Update the test case or fix the seam.'
    )
  }
  if (hashMatch !== tc.expected_hash_match) {
    throw new Error(
      `[gen:vault-roundtrip] REGRESSION: ${tc.name}: expected_hash_match=${tc.expected_hash_match} but computed=${hashMatch}. ` +
      'Update the vector or fix the seam.'
    )
  }

  // Serialize the value for the vector file.
  // For value_reprs that cannot round-trip through JSON (bigint, -0, NaN, Uint8Array, ArrayBuffer),
  // store the reconstructable form under the original type.
  let serializedValue: unknown
  switch (tc.value_repr) {
    case 'bigint':
      serializedValue = String(field.value as bigint)
      break
    case 'neg_zero':
    case 'nan':
      serializedValue = null
      break
    case 'uint8array':
      serializedValue = Array.from(field.value as Uint8Array)
      break
    case 'arraybuffer':
      serializedValue = Array.from(new Uint8Array(field.value as ArrayBuffer))
      break
    default:
      serializedValue = field.value
  }

  return {
    name:                tc.name,
    kind:                'vault.canonical.roundtrip',
    field:               { field_id: field.field_id, type_tag: field.type_tag, value_repr: tc.value_repr, value: serializedValue },
    json_roundtrip_lossy: tc.json_roundtrip_lossy,
    expected_wrote_ok:   wroteOk,
    expected_hash_match: hashMatch,
    loss_reason:         tc.loss_reason,
  }
})

writeFileSync(
  join(outDir, 'roundtrip.json'),
  JSON.stringify(vectors, null, 2) + '\n',
)

// eslint-disable-next-line no-console
console.log(`[gen:vault-roundtrip] wrote ${vectors.length} vectors to vectors/vault.canonical.roundtrip/roundtrip.json`)
// eslint-disable-next-line no-console
console.log('[gen:vault-roundtrip] DEPENDENCY NOTE: this generator imports the vault binary')
// eslint-disable-next-line no-console
console.log('  canonicalizer directly from ../../synoi-vault/src/core/canonicalize.ts.')
// eslint-disable-next-line no-console
console.log('  @synoi/sraid does NOT export the binary field-region canonicalizer -- this')
// eslint-disable-next-line no-console
console.log('  is a conformance coverage gap. Escalate to MIGRATION_V5.')
