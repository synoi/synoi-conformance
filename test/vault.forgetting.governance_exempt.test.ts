// test/vault.forgetting.governance_exempt.test.ts
//
// Conformance vector: vault.forgetting.governance_exempt
//
// claim_id:   vault.forgetting.governance_exempt
// source_doc: VAULT_COMPOUNDING_SUBSTRATE_SPEC.md section 6.7
// target_status: SHIPPED
//
// Assertions:
//   1. A direct safePrune call on a decision_receipt CDRO returns
//      pruned:false, skip_reason:'governance_exempt', writes no tombstone,
//      and deletes nothing.
//   2. A direct safePrune call on a gateway_manifest CDRO returns
//      pruned:false, skip_reason:'governance_exempt', writes no tombstone,
//      and deletes nothing.
//   3. A direct safePrune call on a license CDRO returns
//      pruned:false, skip_reason:'governance_exempt', writes no tombstone,
//      and deletes nothing.
//   4. runTTLCleanup does NOT delete a governance CDRO whose ttl_expires_at
//      is in the past (TTL_CLEANUP_CDRO_SQL excludes governance types).
//
// Methodology: import real safePrune, openDatabase, runTTLCleanup from
// synoi-vault source (line/forget @ 4ce5c70). Use temp SQLite DBs.
// N=1 per scenario (deterministic SQLite).

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { openDatabase }  from '../../synoi-vault/src/storage/edge-store.js'
import {
  safePrune,
  TEST_TOMBSTONE_REASONS,
} from '../../synoi-vault/src/storage/forgetting.js'
import { InMemoryJournal } from '../../synoi-vault/src/governance/journal.js'
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

// ─── Helper: insert a CDRO with a specific object_type directly via SQL ───────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function insertCdroWithType(
  db: any,
  objectId: string,
  objectType: string,
  scope: string,
  ttlExpiresAt?: number,
): { oid_hex: string; canonical_hash: string } {
  const cdro = buildCDRO({
    object_id:      objectId,
    object_type:    objectType,
    schema_version: '1.0.0',
    canonical_fields: [
      { field_id: 1, type_tag: FieldType.STRING, value: objectId },
      { field_id: 2, type_tag: FieldType.STRING, value: objectType },
    ],
    field_policies: [
      { field_id: 1, policy: FieldPolicyType.REQUIRED_CANONICAL, importance_weight: 255, bio_level: BioLevel.ATOM },
      { field_id: 2, policy: FieldPolicyType.REQUIRED_CANONICAL, importance_weight: 200, bio_level: BioLevel.ATOM },
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
      trust_level:            'authoritative',
    },
  })

  const tlv = Buffer.from(canonicalize(filterCanonicalFields(cdro.canonical_fields, cdro.field_policies)))
  const canonical_values_json = serializeCanonicalValues(cdro.canonical_fields)
  const oid = deriveOID(cdro, scope)
  const oid_hex = toOIDHex(oid)
  const canonical_hash = Array.from(cdro.canonical_hash as Uint8Array)
    .map((b: number) => b.toString(16).padStart(2, '0'))
    .join('')

  db.prepare(`
    INSERT INTO cdros (
      object_id, object_type, schema_version, canonical_hash, oid_hex, scope,
      version, birth_level, provenance_json, truth_quality_json,
      canonical_tlv, canonical_values_json, base_canonical_hash, attestation_json,
      field_policies_json, created_at, supersedes,
      ttl_expires_at, encrypted, payload_enc, export_policy_ref
    ) VALUES (
      @object_id, @object_type, @schema_version, @canonical_hash, @oid_hex, @scope,
      @version, @birth_level, @provenance_json, @truth_quality_json,
      @canonical_tlv, @canonical_values_json, NULL, NULL,
      @field_policies_json, @created_at, NULL,
      @ttl_expires_at, 0, NULL, NULL
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
    truth_quality_json:  JSON.stringify(cdro.truth_quality),
    canonical_tlv:       tlv,
    canonical_values_json,
    field_policies_json: JSON.stringify(cdro.field_policies),
    created_at:          cdro.created_at,
    ttl_expires_at:      ttlExpiresAt ?? null,
  })

  return { oid_hex, canonical_hash }
}

// ─── Scenario: safePrune on each governance type returns governance_exempt ────

async function scenarioGovernanceExemptPrune(
  objectType: 'decision_receipt' | 'gateway_manifest' | 'license',
): Promise<void> {
  const label = `[gov-exempt:${objectType}]`
  const tmpDir = mkdtempSync(join(tmpdir(), `synoi-conf-govex-`))
  try {
    const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
    const db = store.rawDb
    const objectId = `gov-test-${objectType}`
    const scope = 'test-scope'

    const { oid_hex, canonical_hash } = insertCdroWithType(db, objectId, objectType, scope)

    // Verify the object was inserted as the intended type
    const inserted = db.prepare(
      `SELECT object_type FROM cdros WHERE object_id = ? AND scope = ? LIMIT 1`,
    ).get(objectId, scope) as { object_type: string } | undefined
    ok(`${label} inserted as ${objectType}`, inserted?.object_type === objectType,
      `actual = ${inserted?.object_type}`)

    const journal = new InMemoryJournal()
    const result = await safePrune(
      db,
      {
        pruned_object_id: objectId,
        oid_hex,
        canonical_hash,
        scope,
        reason: 'test-prune',
        recorded_at: Date.now(),
      },
      journal,
      undefined,
      TEST_TOMBSTONE_REASONS,
    )

    ok(`${label} pruned is false`, result.pruned === false,
      `pruned = ${result.pruned}`)
    ok(`${label} skip_reason is governance_exempt`,
      result.skip_reason === 'governance_exempt',
      `skip_reason = ${result.skip_reason}`)

    // Body MUST still exist
    const bodyAfter = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = ? AND scope = ? LIMIT 1`,
    ).get(objectId, scope)
    ok(`${label} body still exists after exempted prune attempt`, bodyAfter !== undefined,
      `body = ${JSON.stringify(bodyAfter)}`)

    // NO tombstone was written
    const tombstone = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = ? AND scope = ? LIMIT 1`,
    ).get(`tombstone:${objectId}`, scope)
    ok(`${label} no tombstone written`, tombstone === undefined,
      `tombstone = ${JSON.stringify(tombstone)}`)

    // vault_journal MUST be empty (no entry written for a skip)
    const journalCount = (db.prepare(
      `SELECT COUNT(*) AS n FROM vault_journal WHERE tenant_id = ?`,
    ).get(scope) as { n: number }).n
    ok(`${label} vault_journal empty (no entry written on exempt skip)`,
      journalCount === 0,
      `journal rows = ${journalCount}`)

    store.close()
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario: runTTLCleanup does NOT delete a governance CDRO with past TTL ──

async function scenarioTTLCleanupExemptsGovernance(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-govttl-'))
  try {
    const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
    const db = store.rawDb
    const scope = 'test-scope'

    // Insert one of each governance type with a past ttl_expires_at
    const pastTTL = Date.now() - 1000  // 1 second in the past
    insertCdroWithType(db, 'gov-dr-ttl',  'decision_receipt', scope, pastTTL)
    insertCdroWithType(db, 'gov-gm-ttl',  'gateway_manifest', scope, pastTTL)
    insertCdroWithType(db, 'gov-lic-ttl', 'license',          scope, pastTTL)

    // Insert a non-governance object with a past TTL (should be deleted)
    insertCdroWithType(db, 'non-gov-ttl', 'test_object', scope, pastTTL)

    // Verify all four exist before cleanup
    const beforeCount = (db.prepare(
      `SELECT COUNT(*) AS n FROM cdros WHERE scope = ? AND object_id IN ('gov-dr-ttl','gov-gm-ttl','gov-lic-ttl','non-gov-ttl')`,
    ).get(scope) as { n: number }).n
    ok('[gov-ttl] all 4 objects inserted before cleanup', beforeCount === 4,
      `count before = ${beforeCount}`)

    // Run TTL cleanup
    store.runTTLCleanup()

    // The three governance CDROs MUST still exist
    const drAfter = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'gov-dr-ttl' AND scope = ? LIMIT 1`,
    ).get(scope)
    ok('[gov-ttl] decision_receipt survives TTL cleanup despite past ttl_expires_at',
      drAfter !== undefined, `decision_receipt row = ${JSON.stringify(drAfter)}`)

    const gmAfter = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'gov-gm-ttl' AND scope = ? LIMIT 1`,
    ).get(scope)
    ok('[gov-ttl] gateway_manifest survives TTL cleanup despite past ttl_expires_at',
      gmAfter !== undefined, `gateway_manifest row = ${JSON.stringify(gmAfter)}`)

    const licAfter = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'gov-lic-ttl' AND scope = ? LIMIT 1`,
    ).get(scope)
    ok('[gov-ttl] license survives TTL cleanup despite past ttl_expires_at',
      licAfter !== undefined, `license row = ${JSON.stringify(licAfter)}`)

    // The non-governance object MUST be deleted
    const nonGovAfter = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'non-gov-ttl' AND scope = ? LIMIT 1`,
    ).get(scope)
    ok('[gov-ttl] non-governance CDRO deleted by TTL cleanup',
      nonGovAfter === undefined,
      `non-gov row = ${JSON.stringify(nonGovAfter)}`)

    store.close()
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  process.stdout.write('vault.forgetting.governance_exempt conformance vector\n')
  process.stdout.write('claim_id: vault.forgetting.governance_exempt\n')
  process.stdout.write('target_status: SHIPPED\n')
  process.stdout.write('vault branch: line/forget @ 4ce5c70\n\n')

  await scenarioGovernanceExemptPrune('decision_receipt')
  await scenarioGovernanceExemptPrune('gateway_manifest')
  await scenarioGovernanceExemptPrune('license')
  await scenarioTTLCleanupExemptsGovernance()

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
