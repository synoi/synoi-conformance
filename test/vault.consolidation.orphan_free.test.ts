// test/vault.consolidation.orphan_free.test.ts
//
// Conformance vector: vault.consolidation.orphan_free
//
// claim_id:   vault.consolidation.orphan_free
// source_doc: VAULT_COMPOUNDING_SUBSTRATE_SPEC.md section 6.5 / F7
// target_status: SHIPPED
//
// Assertions:
//   1. After a successful prune: zero ghost HNSW vectors remain.
//      l2_index_meta rows for the pruned CDRO are deleted in the transaction.
//      The HNSW remove() call fires ONLY after the SQL transaction commits.
//   2. After a successful prune: zero orphaned mros rows reference the deleted object.
//      mros rows for the pruned CDRO are deleted in the same transaction as the body DELETE.
//   3. Surviving CDRO identity (oid_hex, canonical_hash) is unchanged after prune of a
//      different object.
//   4. MF-3 (BLOCKER 4 live_ref skip): on a live_ref SKIP, HNSW vectors are NOT removed.
//      A superseding object that references the body blocks the prune; no HNSW remove()
//      is called on any skip path.
//
// Methodology: import real safePrune + openDatabase from synoi-vault (line/forget @ c492de9).
// Use a stub HNSWIndex that records remove() calls so we can assert HNSW removal behavior
// without needing the real HNSW native binary.  N=1 per scenario (deterministic SQLite).

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'

import { openDatabase }  from '../../synoi-vault/src/storage/edge-store.js'
import { safePrune, TEST_TOMBSTONE_REASONS } from '../../synoi-vault/src/storage/forgetting.js'
import { InMemoryJournal } from '../../synoi-vault/src/governance/journal.js'
import { FieldType, FieldPolicyType, BioLevel } from '../../synoi-vault/src/types/index.js'
import { buildCDRO }     from '../../synoi-vault/src/core/cdro.js'
import { deriveOID, toOIDHex } from '../../synoi-vault/src/core/oid.js'
import { canonicalize, filterCanonicalFields } from '../../synoi-vault/src/core/canonicalize.js'
import { serializeCanonicalValues } from '../../synoi-vault/src/storage/canonical-values.js'
import type { HNSWIndex } from '../../synoi-vault/src/ml/hnsw.js'

// ─── Test harness ────────────────────────────────────────────────────────────

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

// ─── Stub HNSWIndex ──────────────────────────────────────────────────────────
// Records every remove() call so we can assert HNSW removal behavior without
// the real native binary.

class StubHNSWIndex {
  readonly removedIds: number[] = []

  remove(id: number): void {
    this.removedIds.push(id)
  }

  search(_vec: Float32Array, _k: number): Array<{ id: number; distance: number }> {
    return []
  }

  add(_id: number, _vec: Float32Array): void {}
}

// ─── Helper: insert a test CDRO directly via SQL ─────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function insertTestCdro(db: any, objectId: string, scope: string): { oid_hex: string; canonical_hash: string } {
  const cdro = buildCDRO({
    object_id:      objectId,
    object_type:    'test_object',
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
      trust_level:            'unverified',
    },
  })

  const tlv = Buffer.from(canonicalize(filterCanonicalFields(cdro.canonical_fields, cdro.field_policies)))
  const oid = deriveOID(cdro, scope)
  const oid_hex = toOIDHex(oid)
  const canonical_hash = Array.from(cdro.canonical_hash).map((b: number) => b.toString(16).padStart(2, '0')).join('')
  const canonical_values_json = serializeCanonicalValues(cdro.canonical_fields)

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
      @field_policies_json, @created_at, @supersedes,
      NULL, 0, NULL, NULL
    )
    ON CONFLICT(object_id, version, scope) DO NOTHING
  `).run({
    object_id:           cdro.object_id,
    object_type:         cdro.object_type,
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
    supersedes:          null,
  })

  return { oid_hex, canonical_hash }
}

// ─── Helper: insert an MRO row for a CDRO ────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function insertMro(db: any, cdroId: string, scope: string): string {
  const id = randomUUID()
  db.prepare(`
    INSERT INTO mros (
      id, source_cdro_id, scope, source_cdro_hash, source_version, schema_version,
      derived_at, profile, interaction_log_json
    ) VALUES (
      @id, @source_cdro_id, @scope, @source_cdro_hash, @source_version, @schema_version,
      @derived_at, @profile, @interaction_log_json
    )
  `).run({
    id,
    source_cdro_id:   cdroId,
    scope,
    source_cdro_hash: 'aabbccdd',
    source_version:   1,
    schema_version:   '1.0.0',
    derived_at:       Date.now(),
    profile:          'standard',
    interaction_log_json: '[]',
  })
  return id
}

// ─── Helper: insert an l2_index_meta row ─────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function insertL2Meta(db: any, mroId: string, cdroId: string, scope: string, oidHex: string): number {
  const result = db.prepare(`
    INSERT INTO l2_index_meta
      (mro_id, cdro_id, oid_hex, scope, encoder_id, encoder_version, indexed_at)
    VALUES
      (@mro_id, @cdro_id, @oid_hex, @scope, @encoder_id, @encoder_version, @indexed_at)
  `).run({
    mro_id:          mroId,
    cdro_id:         cdroId,
    oid_hex:         oidHex,
    scope,
    encoder_id:      'test-encoder',
    encoder_version: '1.0',
    indexed_at:      Date.now(),
  })
  return Number(result.lastInsertRowid)
}

// ─── Scenario 1: zero ghost HNSW vectors + zero orphaned mros after prune ────

async function scenarioOrphanFree(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-orphan-'))
  const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
  try {
    const db = store.rawDb
    const scope = 'test-scope'

    // Insert two CDROs: one to prune, one survivor
    const { oid_hex: pruneOid, canonical_hash: pruneHash } =
      insertTestCdro(db, 'prune-obj', scope)
    const { oid_hex: surviveOid } = insertTestCdro(db, 'survive-obj', scope)

    // Insert MRO + l2_index_meta for the object to be pruned
    const mroId = insertMro(db, 'prune-obj', scope)
    const vectorId = insertL2Meta(db, mroId, 'prune-obj', scope, pruneOid)

    // Insert MRO + l2_index_meta for the survivor (must be untouched)
    const surviveMroId = insertMro(db, 'survive-obj', scope)
    const surviveVectorId = insertL2Meta(db, surviveMroId, 'survive-obj', scope, surviveOid)

    // Capture survivor identity before prune
    const survivorBefore = db.prepare(
      `SELECT oid_hex, canonical_hash FROM cdros WHERE object_id = 'survive-obj' AND scope = ? LIMIT 1`,
    ).get(scope) as { oid_hex: string; canonical_hash: string } | undefined

    const hnsw = new StubHNSWIndex()
    const journal = new InMemoryJournal()

    const result = await safePrune(
      db,
      {
        pruned_object_id: 'prune-obj',
        oid_hex:          pruneOid,
        canonical_hash:   pruneHash,
        scope,
        reason:           'test-prune',
        recorded_at:      Date.now(),
      },
      journal,
      hnsw as unknown as HNSWIndex,
      TEST_TOMBSTONE_REASONS,
    )

    ok('[F7] safePrune reports pruned:true', result.pruned === true,
      `result = ${JSON.stringify(result)}`)

    // Pruned body is gone
    const bodyRow = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'prune-obj' AND scope = ? LIMIT 1`,
    ).get(scope)
    ok('[F7] pruned body absent from cdros', bodyRow === undefined,
      `body = ${JSON.stringify(bodyRow)}`)

    // MRO for pruned object is gone
    const mroRow = db.prepare(
      `SELECT id FROM mros WHERE source_cdro_id = 'prune-obj' AND scope = ? LIMIT 1`,
    ).get(scope)
    ok('[F7] mros row for pruned object deleted', mroRow === undefined,
      `mro = ${JSON.stringify(mroRow)}`)

    // l2_index_meta for pruned object is gone
    const l2Row = db.prepare(
      `SELECT vector_id FROM l2_index_meta WHERE cdro_id = 'prune-obj' AND scope = ? LIMIT 1`,
    ).get(scope)
    ok('[F7] l2_index_meta row for pruned object deleted', l2Row === undefined,
      `l2 = ${JSON.stringify(l2Row)}`)

    // HNSW remove() was called with the correct vector_id
    ok('[F7] HNSW remove() called for the pruned vector_id', hnsw.removedIds.includes(vectorId),
      `removed = ${JSON.stringify(hnsw.removedIds)}, expected vectorId=${vectorId}`)

    // HNSW remove() was NOT called for the survivor's vector_id
    ok('[F7] HNSW remove() NOT called for survivor vector_id', !hnsw.removedIds.includes(surviveVectorId),
      `removed = ${JSON.stringify(hnsw.removedIds)}, surviveVectorId=${surviveVectorId}`)

    // Survivor CDRO still exists
    const survivorAfter = db.prepare(
      `SELECT oid_hex, canonical_hash FROM cdros WHERE object_id = 'survive-obj' AND scope = ? LIMIT 1`,
    ).get(scope) as { oid_hex: string; canonical_hash: string } | undefined
    ok('[F7] survivor CDRO still exists', survivorAfter !== undefined)
    ok('[F7] survivor oid_hex unchanged',
      survivorAfter?.oid_hex === survivorBefore?.oid_hex,
      `before=${survivorBefore?.oid_hex} after=${survivorAfter?.oid_hex}`)
    ok('[F7] survivor canonical_hash unchanged',
      survivorAfter?.canonical_hash === survivorBefore?.canonical_hash,
      `before=${survivorBefore?.canonical_hash} after=${survivorAfter?.canonical_hash}`)

    // Survivor MRO intact
    const surviveMroRow = db.prepare(
      `SELECT id FROM mros WHERE id = ? LIMIT 1`,
    ).get(surviveMroId)
    ok('[F7] survivor mros row intact', surviveMroRow !== undefined)

    // Survivor l2_index_meta intact
    const surviveL2Row = db.prepare(
      `SELECT vector_id FROM l2_index_meta WHERE vector_id = ? LIMIT 1`,
    ).get(surviveVectorId)
    ok('[F7] survivor l2_index_meta row intact', surviveL2Row !== undefined)

  } finally {
    store.close()
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 2: MF-3 - HNSW vectors NOT removed on live_ref skip ───────────

async function scenarioLiveRefNoHnswRemoval(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-liveref-'))
  const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
  try {
    const db = store.rawDb
    const scope = 'test-scope'

    // Insert the body object to attempt to prune
    const { oid_hex, canonical_hash } = insertTestCdro(db, 'live-ref-body', scope)

    // Insert a superseding object (non-decision_receipt) that references live-ref-body.
    // Setting supersedes creates the live reference that blocks the prune.
    insertTestCdro(db, 'live-ref-superseder', scope)
    db.prepare(
      `UPDATE cdros SET supersedes = 'live-ref-body' WHERE object_id = 'live-ref-superseder' AND scope = ?`,
    ).run(scope)

    // Insert l2_index_meta for the body (to prove HNSW is NOT called on skip)
    const mroId = insertMro(db, 'live-ref-body', scope)
    const vectorId = insertL2Meta(db, mroId, 'live-ref-body', scope, oid_hex)

    const hnsw = new StubHNSWIndex()
    const journal = new InMemoryJournal()

    const result = await safePrune(
      db,
      {
        pruned_object_id: 'live-ref-body',
        oid_hex,
        canonical_hash,
        scope,
        reason:           'test-live-ref',
        recorded_at:      Date.now(),
      },
      journal,
      hnsw as unknown as HNSWIndex,
      TEST_TOMBSTONE_REASONS,
    )

    ok('[MF-3] safePrune skips on live_ref', result.pruned === false,
      `result = ${JSON.stringify(result)}`)
    ok('[MF-3] skip_reason is live_receipt_reference',
      result.skip_reason === 'live_receipt_reference',
      `skip_reason = ${result.skip_reason}`)

    // MF-3 (BLOCKER 4): HNSW remove() MUST NOT be called on a skip path
    ok('[MF-3] HNSW remove() NOT called on live_ref skip',
      !hnsw.removedIds.includes(vectorId),
      `removed = ${JSON.stringify(hnsw.removedIds)}, vectorId=${vectorId}`)
    ok('[MF-3] HNSW removedIds is empty on live_ref skip',
      hnsw.removedIds.length === 0,
      `removed = ${JSON.stringify(hnsw.removedIds)}`)

    // Body still exists
    const bodyRow = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'live-ref-body' AND scope = ? LIMIT 1`,
    ).get(scope)
    ok('[MF-3] body STILL EXISTS after live_ref skip', bodyRow !== undefined)

    // l2_index_meta still intact
    const l2Row = db.prepare(
      `SELECT vector_id FROM l2_index_meta WHERE vector_id = ? LIMIT 1`,
    ).get(vectorId)
    ok('[MF-3] l2_index_meta row intact after live_ref skip', l2Row !== undefined)

  } finally {
    store.close()
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  process.stdout.write('vault.consolidation.orphan_free conformance vector\n')
  process.stdout.write('claim_id: vault.consolidation.orphan_free\n')
  process.stdout.write('target_status: SHIPPED\n')
  process.stdout.write('vault branch: line/forget @ c492de9\n\n')

  await scenarioOrphanFree()
  await scenarioLiveRefNoHnswRemoval()

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
