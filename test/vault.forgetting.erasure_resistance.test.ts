// test/vault.forgetting.erasure_resistance.test.ts
//
// Conformance vector: vault.forgetting.erasure_resistance
//
// claim_id:   vault.forgetting.erasure_resistance
// source_doc: VAULT_COMPOUNDING_SUBSTRATE_SPEC.md section 6.7 (F10)
// target_status: SHIPPED
//
// Assertions:
//   1. recordHit calls beyond HIT_RATE_CAP_PER_WINDOW (20) per (oid, scope,
//      window) are rejected: hit_count does NOT increase past the cap.
//   2. The DB-backed cap (checkHitRateCapDB) rejects hits beyond cap even
//      across two separate EdgeStore instances over the same DB file
//      (cross-process / serverless correctness, BLOCKER 5 / MF-4).
//   3. governance types (decision_receipt, gateway_manifest, license) are
//      unconditionally non-prunable: prunable() returns false regardless of
//      stability value.
//
// Methodology: import real openDatabase, checkHitRateCapDB, prunable,
// __resetHitRateBuckets from synoi-vault (line/forget @ 4ce5c70). Use a
// temp SQLite DB. N=1 per scenario (deterministic SQLite atomic ops).
// The cross-instance test opens the same DB file with two EdgeStore
// instances to exercise the persistent hit_rate_cap table path.

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { openDatabase } from '../../synoi-vault/src/storage/edge-store.js'
import {
  checkHitRateCapDB,
  prunable,
  __resetHitRateBuckets,
} from '../../synoi-vault/src/storage/forgetting.js'
import { FieldType, FieldPolicyType, BioLevel } from '../../synoi-vault/src/types/index.js'
import { buildCDRO } from '../../synoi-vault/src/core/cdro.js'
import { deriveOID, toOIDHex } from '../../synoi-vault/src/core/oid.js'
import { canonicalize, filterCanonicalFields } from '../../synoi-vault/src/core/canonicalize.js'
import { serializeCanonicalValues } from '../../synoi-vault/src/storage/canonical-values.js'

// ─── Test harness ─────────────────────────────────────────────────────────────

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

// The per-(oid,scope,window) cap exported from forgetting.ts
const HIT_RATE_CAP_PER_WINDOW = 20
// Use a fixed window start in the distant past so none of our test calls
// land in the same window as each other (we control windowStart explicitly
// in the checkHitRateCapDB path via the `now` parameter).
const TEST_WINDOW_BASE = 1_000_000  // deterministic, far from real time

// ─── Helper: insert a minimal test CDRO ───────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function insertTestCdro(
  db: any,
  objectId: string,
  objectType: string,
  scope: string,
  opts: { stability?: number; trustLevel?: string } = {},
): { oid_hex: string } {
  const stability  = opts.stability  ?? 1.5
  const trustLevel = opts.trustLevel ?? 'unverified'

  const cdro = buildCDRO({
    object_id:      objectId,
    object_type:    objectType,
    schema_version: '1.0.0',
    canonical_fields: [
      { field_id: 1, type_tag: FieldType.STRING, value: objectId },
    ],
    field_policies: [
      { field_id: 1, policy: FieldPolicyType.REQUIRED_CANONICAL, importance_weight: 255, bio_level: BioLevel.ATOM },
    ],
    provenance: {
      source:           'conformance-test',
      ingest_path:      `scope:${scope}`,
      ingest_timestamp: Date.now(),
    },
    truth_quality: {
      birth_level:            'full',
      extraction_depth:       'deep',
      plaintext_availability: 'available',
      provenance_confidence:  1.0,
      trust_level:            trustLevel as 'authoritative' | 'inferred' | 'unverified',
    },
  })

  const tlv = Buffer.from(canonicalize(filterCanonicalFields(cdro.canonical_fields, cdro.field_policies)))
  const oid = deriveOID(cdro, scope)
  const oid_hex = toOIDHex(oid)
  const canonical_hash = Array.from(cdro.canonical_hash as Uint8Array)
    .map((b: number) => b.toString(16).padStart(2, '0'))
    .join('')
  const canonical_values_json = serializeCanonicalValues(cdro.canonical_fields)

  db.prepare(`
    INSERT INTO cdros (
      object_id, object_type, schema_version, canonical_hash, oid_hex, scope,
      version, birth_level, provenance_json, truth_quality_json,
      canonical_tlv, canonical_values_json, base_canonical_hash, attestation_json,
      field_policies_json, created_at, supersedes,
      ttl_expires_at, encrypted, payload_enc, export_policy_ref,
      stability, hit_count
    ) VALUES (
      @object_id, @object_type, @schema_version, @canonical_hash, @oid_hex, @scope,
      @version, @birth_level, @provenance_json, @truth_quality_json,
      @canonical_tlv, @canonical_values_json, NULL, NULL,
      @field_policies_json, @created_at, NULL,
      NULL, 0, NULL, NULL,
      @stability, 0
    )
    ON CONFLICT(object_id, version, scope) DO NOTHING
  `).run({
    object_id:           cdro.object_id,
    object_type:         objectType,
    schema_version:      cdro.schema_version,
    canonical_hash,
    oid_hex,
    scope,
    version:             cdro.version,
    birth_level:         cdro.truth_quality.birth_level,
    provenance_json:     JSON.stringify(cdro.provenance),
    truth_quality_json:  JSON.stringify({ ...cdro.truth_quality, trust_level: trustLevel }),
    canonical_tlv:       tlv,
    canonical_values_json,
    field_policies_json: JSON.stringify(cdro.field_policies),
    created_at:          cdro.created_at,
    stability,
  })

  return { oid_hex }
}

// ─── Scenario 1: hit_count does not exceed cap via recordHit ─────────────────

async function scenarioRateCapRecordHit(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-erase-cap-'))
  try {
    // Reset the in-process bucket cache before the test so prior test runs
    // in the same process do not consume cap slots for our oid.
    __resetHitRateBuckets()

    const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
    const db = store.rawDb
    const scope = 'test-scope'
    const objectId = 'rate-cap-test-obj'

    const { oid_hex } = insertTestCdro(db, objectId, 'test_object', scope)

    // Fire exactly HIT_RATE_CAP_PER_WINDOW hits (all should be accepted)
    for (let i = 0; i < HIT_RATE_CAP_PER_WINDOW; i++) {
      store.recordHit(oid_hex, scope)
    }

    const afterCap = db.prepare(
      `SELECT hit_count FROM cdros WHERE oid_hex = ? AND scope = ? LIMIT 1`,
    ).get(oid_hex, scope) as { hit_count: number } | undefined
    ok('[rate-cap] hit_count equals cap after exactly cap hits',
      afterCap?.hit_count === HIT_RATE_CAP_PER_WINDOW,
      `hit_count = ${afterCap?.hit_count}, expected ${HIT_RATE_CAP_PER_WINDOW}`)

    // Fire one more hit beyond the cap: MUST be rejected
    store.recordHit(oid_hex, scope)
    const afterExcess = db.prepare(
      `SELECT hit_count FROM cdros WHERE oid_hex = ? AND scope = ? LIMIT 1`,
    ).get(oid_hex, scope) as { hit_count: number } | undefined
    ok('[rate-cap] hit_count does NOT increase beyond cap on excess hit',
      afterExcess?.hit_count === HIT_RATE_CAP_PER_WINDOW,
      `hit_count = ${afterExcess?.hit_count}, expected ${HIT_RATE_CAP_PER_WINDOW} (cap)`)

    // Fire 80 more excess hits to confirm the cap holds under a flood
    for (let i = 0; i < 80; i++) {
      store.recordHit(oid_hex, scope)
    }
    const afterFlood = db.prepare(
      `SELECT hit_count FROM cdros WHERE oid_hex = ? AND scope = ? LIMIT 1`,
    ).get(oid_hex, scope) as { hit_count: number } | undefined
    ok('[rate-cap] hit_count remains at cap after flood of 80 excess hits',
      afterFlood?.hit_count === HIT_RATE_CAP_PER_WINDOW,
      `hit_count = ${afterFlood?.hit_count}, expected ${HIT_RATE_CAP_PER_WINDOW}`)

    store.close()
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 2: DB-backed cap holds across two EdgeStore instances ───────────
//
// Opens the same DB file with two separate EdgeStore instances to prove the
// hit_rate_cap table enforces the cap cross-instance (BLOCKER 5 / MF-4).
// Uses the checkHitRateCapDB function directly to isolate the persistent
// table from the in-process cache.

async function scenarioCrossInstanceCap(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-erase-xi-'))
  try {
    const scope  = 'test-scope'
    const oidHex = 'a'.repeat(64)  // synthetic deterministic oid_hex

    // Use a synthetic window start guaranteed not to collide with any other
    // test (far from real time, unique per run).
    const windowNow = TEST_WINDOW_BASE

    // Instance A: drive cap to exactly HIT_RATE_CAP_PER_WINDOW
    const storeA = openDatabase({ path: tmpDir, scope })
    const dbA = storeA.rawDb

    let acceptedA = 0
    for (let i = 0; i < HIT_RATE_CAP_PER_WINDOW; i++) {
      const ok_ = checkHitRateCapDB(dbA, oidHex, scope, windowNow)
      if (ok_) acceptedA++
    }
    ok('[cross-inst] instance A: all cap hits accepted',
      acceptedA === HIT_RATE_CAP_PER_WINDOW,
      `accepted = ${acceptedA}, expected ${HIT_RATE_CAP_PER_WINDOW}`)

    // One more on instance A must be rejected
    const excessA = checkHitRateCapDB(dbA, oidHex, scope, windowNow)
    ok('[cross-inst] instance A: hit beyond cap is rejected', excessA === false,
      `excess result = ${excessA}`)

    // Instance B: same DB file, fresh in-process connection
    // The hit_rate_cap row already has count=cap in the DB.
    // Instance B must see the cap and reject immediately.
    const storeB = openDatabase({ path: tmpDir, scope })
    const dbB = storeB.rawDb

    const excessB = checkHitRateCapDB(dbB, oidHex, scope, windowNow)
    ok('[cross-inst] instance B: first hit rejected (cap already reached by instance A)',
      excessB === false,
      `excess result from B = ${excessB}`)

    // 10 more hits from instance B: all must be rejected
    let rejectedB = 0
    for (let i = 0; i < 10; i++) {
      if (!checkHitRateCapDB(dbB, oidHex, scope, windowNow)) rejectedB++
    }
    ok('[cross-inst] instance B: all 10 excess hits rejected',
      rejectedB === 10,
      `rejected = ${rejectedB}`)

    storeA.close()
    storeB.close()
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 3: governance types are never prunable ─────────────────────────
//
// prunable() must return false for decision_receipt, gateway_manifest, license
// regardless of stability value (including stability values well above the
// survival floor that would make a non-governance object prunable).

async function scenarioGovernanceNeverPrunable(): Promise<void> {
  const govTypes = [
    'decision_receipt',
    'gateway_manifest',
    'license',
  ] as const

  // Test at multiple stability values including very high (2.0) which would
  // make a non-governance object prunable if stability > floor.
  const stabilityValues = [1.0, 1.3, 1.6, 1.7, 2.0]

  for (const objectType of govTypes) {
    for (const stability of stabilityValues) {
      const row = {
        object_id:           `gov-prune-test-${objectType}`,
        object_type:         objectType,
        scope:               'test-scope',
        stability,
        truth_quality_json:  JSON.stringify({ trust_level: 'authoritative' }),
      }
      const result = prunable(row)
      ok(
        `[gov-prunable] prunable() is false for ${objectType} at stability ${stability}`,
        result === false,
        `prunable returned ${result}`,
      )
    }
  }

  // Sanity check: a non-governance object at high stability IS prunable
  const nonGovRow = {
    object_id:          'non-gov-test',
    object_type:        'test_object',
    scope:              'test-scope',
    stability:          2.0,
    truth_quality_json: JSON.stringify({ trust_level: 'unverified' }),
  }
  // At stability 2.0 and trust_level 'unverified' (floor=1.0), 2.0 > 1.0 => prunable
  const nonGovResult = prunable(nonGovRow)
  ok('[gov-prunable] non-governance test_object at stability 2.0 IS prunable (sanity check)',
    nonGovResult === true,
    `prunable returned ${nonGovResult}`)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  process.stdout.write('vault.forgetting.erasure_resistance conformance vector\n')
  process.stdout.write('claim_id: vault.forgetting.erasure_resistance\n')
  process.stdout.write('target_status: SHIPPED\n')
  process.stdout.write('vault branch: line/forget @ 4ce5c70\n\n')

  await scenarioRateCapRecordHit()
  await scenarioCrossInstanceCap()
  await scenarioGovernanceNeverPrunable()

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
