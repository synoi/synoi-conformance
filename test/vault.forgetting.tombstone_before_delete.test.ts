// test/vault.forgetting.tombstone_before_delete.test.ts
//
// Conformance vector: vault.forgetting.tombstone_before_delete
//
// claim_id:   vault.forgetting.tombstone_before_delete
// source_doc: VAULT_COMPOUNDING_SUBSTRATE_SPEC.md section 6.4 / F6
// target_status: SHIPPED
//
// Assertions:
//   1. FAILURE PATH (atomic rollback): when the vault_journal INSERT is forced to
//      fail inside safePrune's BEGIN EXCLUSIVE transaction, the entire transaction
//      rolls back.  On rollback:
//        - the body CDRO STILL EXISTS (was not deleted)
//        - NO tombstone decision_receipt CDRO was written
//        - NO vault_journal entry was written
//      This is the corrected assertion for the F6 atomic behavior at c492de9.
//      The OLD prose-vector said "body survives, tombstone CDRO is the durable record"
//      implying a partial commit; the code now does full all-or-nothing rollback.
//
//   2. SUCCESS PATH: a normal safePrune atomically writes the tombstone decision_receipt
//      CDRO AND the journal entry AND deletes the body.  All three happen together or
//      not at all (verified by success = pruned:true + all three present + body absent).
//
//   3. IDEMPOTENCY: a second safePrune call on an already-tombstoned object returns
//      skip_reason='tombstone_exists' and is a no-op.
//
// Methodology: import the real safePrune + openDatabase from synoi-vault source
// (line/forget @ c492de9).  Set up a temp SQLite vault, run scenarios, assert
// programmatically via SQL inspection.  N=1 per scenario (deterministic SQLite).

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { openDatabase }       from '../../../synoi-systems/synoi-vault/src/storage/edge-store.js'
import {
  safePrune,
  ensureEdgeJournalTable,
  ensureConsolidationStateV6,
  verifyTombstoneReceiptSignature,
  TEST_TOMBSTONE_REASONS,
} from '../../../synoi-systems/synoi-vault/src/storage/forgetting.js'
import { InMemoryJournal }    from '../../../synoi-systems/synoi-vault/src/governance/journal.js'
import { FieldType, FieldPolicyType, BioLevel } from '../../../synoi-systems/synoi-vault/src/types/index.js'
import { buildCDRO }          from '../../../synoi-systems/synoi-vault/src/core/cdro.js'
import { deriveOID, toOIDHex } from '../../../synoi-systems/synoi-vault/src/core/oid.js'
import {
  canonicalize,
  filterCanonicalFields,
} from '../../../synoi-systems/synoi-vault/src/core/canonicalize.js'
import { serializeCanonicalValues } from '../../../synoi-systems/synoi-vault/src/storage/canonical-values.js'

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

// ─── Helper: build and insert a minimal CDRO directly into the DB ────────────

function insertTestCdro(db: InstanceType<typeof Database>, objectId: string, scope: string): {
  oid_hex: string
  canonical_hash: string
} {
  const cdro = buildCDRO({
    object_id:      objectId,
    object_type:    'test_object',
    schema_version: '1.0.0',
    canonical_fields: [
      { field_id: 1, type_tag: FieldType.STRING, value: objectId },
      { field_id: 2, type_tag: FieldType.STRING, value: 'test-body-content' },
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
      trust_level:            'unverified',
    },
  })

  const tlv = Buffer.from(canonicalize(filterCanonicalFields(cdro.canonical_fields, cdro.field_policies)))
  const canonical_values_json = serializeCanonicalValues(cdro.canonical_fields)
  const oid = deriveOID(cdro, scope)
  const oid_hex = toOIDHex(oid)
  const canonical_hash = Array.from(cdro.canonical_hash).map(b => b.toString(16).padStart(2, '0')).join('')

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
  })

  return { oid_hex, canonical_hash }
}

// ─── Scenario 1: FAILURE PATH - forced journal failure rolls back everything ──

async function scenarioFailurePath(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-tomb-fail-'))
  try {
    const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
    const db = store.rawDb

    const objectId = 'test-obj-fail-journal'
    const scope = 'test-scope'

    const { oid_hex, canonical_hash } = insertTestCdro(db, objectId, scope)

    // Verify the body exists before the test
    const bodyBefore = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = ? AND scope = ? LIMIT 1`,
    ).get(objectId, scope)
    ok('[F6-fail] body exists before forced-failure prune', bodyBefore !== undefined)

    // Force the journal INSERT to fail by replacing vault_journal with a version
    // that has a NOT NULL CHECK constraint on a non-existent column.
    //
    // Strategy: after openDatabase creates vault_journal normally, we drop it and
    // recreate it with a STRICT schema that includes a column 'blocker' with
    // NOT NULL and no DEFAULT.  writeJournalEntryInTxn does not INSERT 'blocker',
    // so the INSERT inside the transaction gets a NOT NULL constraint violation.
    // SQLite propagates this as an exception, better-sqlite3's exclusive() call
    // re-throws it, and the surrounding transaction rolls back ALL of:
    //   - tombstone CDRO write
    //   - journal INSERT
    //   - body DELETE
    //
    // We ensure the table exists first (calling ensureEdgeJournalTable so
    // ensureEdgeJournalTable won't recreate it to the old schema inside safePrune)
    // then immediately replace it with the poisoned schema.

    // Step 1: let safePrune's pre-check see a well-formed table (so it won't bail
    // before the transaction on a missing-table error)
    ensureEdgeJournalTable(db)

    // Step 2: replace with a schema that will reject the INSERT
    db.exec(`DROP TABLE IF EXISTS vault_journal`)
    db.exec(`
      CREATE TABLE vault_journal (
        tenant_id     TEXT    NOT NULL,
        seq           INTEGER NOT NULL,
        head          TEXT    NOT NULL,
        prior_head    TEXT,
        payload       BLOB    NOT NULL,
        created_at_ms INTEGER NOT NULL,
        blocker       TEXT    NOT NULL,
        PRIMARY KEY (tenant_id, seq)
      )
    `)

    const journal = new InMemoryJournal()
    let pruneResult: Awaited<ReturnType<typeof safePrune>> | undefined
    let threw = false
    try {
      pruneResult = await safePrune(
        db,
        {
          pruned_object_id: objectId,
          oid_hex,
          canonical_hash,
          scope,
          reason: 'test-prune-fail-journal',
          recorded_at: Date.now(),
        },
        journal,
        undefined,
        TEST_TOMBSTONE_REASONS,
      )
    } catch {
      // better-sqlite3 propagates the constraint exception out of the exclusive()
      // call.  The throw means the transaction did NOT commit.
      threw = true
    }

    // Core assertion: body STILL EXISTS after the forced failure
    const bodyAfter = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = ? AND scope = ? LIMIT 1`,
    ).get(objectId, scope)
    ok('[F6-fail] body STILL EXISTS after forced journal failure (full rollback)', bodyAfter !== undefined,
      `body row = ${JSON.stringify(bodyAfter)}`)

    // NO tombstone was written
    const tombstone = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = ? AND scope = ? LIMIT 1`,
    ).get(`tombstone:${objectId}`, scope)
    ok('[F6-fail] NO tombstone CDRO written on journal failure', tombstone === undefined,
      `tombstone row = ${JSON.stringify(tombstone)}`)

    // NO journal entry was written by safePrune.
    // The vault_journal was poisoned with a NOT NULL 'blocker' column so any INSERT
    // by writeJournalEntryInTxn fails.  The table remains empty (0 rows).
    let journalCount = 0
    try {
      journalCount = (db.prepare(
        `SELECT COUNT(*) AS n FROM vault_journal WHERE tenant_id = ?`,
      ).get(scope) as { n: number }).n
    } catch {
      // If the table schema was replaced in a way that SELECT still works, fallback
      journalCount = 0
    }
    ok('[F6-fail] vault_journal is EMPTY (no entry written by safePrune on journal failure)',
      journalCount === 0,
      `journal entries for scope = ${journalCount} (expected 0)`)

    // The result (threw OR pruned:false) must indicate that NO prune occurred.
    // better-sqlite3's exclusive() throws when the transaction body throws,
    // so the constraint violation propagates as a throw from safePrune.
    if (threw) {
      ok('[F6-fail] safePrune threw on journal conflict (transaction rolled back, body protected)', true)
    } else {
      ok('[F6-fail] pruneResult.pruned is false (transaction rolled back, body protected)',
        pruneResult?.pruned === false,
        `pruneResult = ${JSON.stringify(pruneResult)}`)
    }

    store.close()
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 2: SUCCESS PATH - normal safePrune is fully atomic ─────────────

async function scenarioSuccessPath(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-tomb-ok-'))
  try {
    const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
    const db = store.rawDb

    const objectId = 'test-obj-success'
    const scope = 'test-scope'

    const { oid_hex, canonical_hash } = insertTestCdro(db, objectId, scope)

    const journal = new InMemoryJournal()
    const pruneResult = await safePrune(
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

    ok('[F6-ok] safePrune returns pruned:true', pruneResult.pruned === true,
      `result = ${JSON.stringify(pruneResult)}`)
    ok('[F6-ok] no skip_reason on success', pruneResult.skip_reason === undefined,
      `skip_reason = ${pruneResult.skip_reason}`)

    // Body MUST be absent after successful prune
    const bodyAfter = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = ? AND scope = ? LIMIT 1`,
    ).get(objectId, scope)
    ok('[F6-ok] body DELETED after successful prune', bodyAfter === undefined,
      `body row = ${JSON.stringify(bodyAfter)}`)

    // Tombstone decision_receipt CDRO MUST be written
    const tombstone = db.prepare(
      `SELECT object_id, object_type FROM cdros WHERE object_id = ? AND scope = ? LIMIT 1`,
    ).get(`tombstone:${objectId}`, scope) as { object_id: string; object_type: string } | undefined
    ok('[F6-ok] tombstone decision_receipt CDRO written', tombstone !== undefined,
      `tombstone = ${JSON.stringify(tombstone)}`)
    ok('[F6-ok] tombstone has object_type decision_receipt',
      tombstone?.object_type === 'decision_receipt',
      `object_type = ${tombstone?.object_type}`)

    // vault_journal entry MUST be written
    const journalRow = db.prepare(
      `SELECT seq, tenant_id FROM vault_journal WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1`,
    ).get(scope) as { seq: number; tenant_id: string } | undefined
    ok('[F6-ok] vault_journal entry written after successful prune', journalRow !== undefined,
      `journal row = ${JSON.stringify(journalRow)}`)

    store.close()
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 3: IDEMPOTENCY - second prune on already-tombstoned object ─────

async function scenarioIdempotency(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-tomb-idem-'))
  try {
    const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
    const db = store.rawDb

    const objectId = 'test-obj-idempotent'
    const scope = 'test-scope'

    const { oid_hex, canonical_hash } = insertTestCdro(db, objectId, scope)

    const journal = new InMemoryJournal()

    // First prune - should succeed
    const first = await safePrune(
      db,
      { pruned_object_id: objectId, oid_hex, canonical_hash, scope, reason: 'test-idempotent', recorded_at: Date.now() },
      journal,
      undefined,
      TEST_TOMBSTONE_REASONS,
    )
    ok('[F6-idem] first prune succeeds', first.pruned === true, `first = ${JSON.stringify(first)}`)

    // Second prune on same object - tombstone already exists, must skip
    const second = await safePrune(
      db,
      { pruned_object_id: objectId, oid_hex, canonical_hash, scope, reason: 'test-idempotent', recorded_at: Date.now() },
      journal,
      undefined,
      TEST_TOMBSTONE_REASONS,
    )
    ok('[F6-idem] second prune returns pruned:false', second.pruned === false,
      `second = ${JSON.stringify(second)}`)
    ok('[F6-idem] second prune skip_reason is tombstone_exists',
      second.skip_reason === 'tombstone_exists',
      `skip_reason = ${second.skip_reason}`)

    // Confirm there is still exactly ONE tombstone row (no double-write)
    const tombstoneCount = (db.prepare(
      `SELECT COUNT(*) AS n FROM cdros WHERE object_id = ? AND scope = ?`,
    ).get(`tombstone:${objectId}`, scope) as { n: number }).n
    ok('[F6-idem] exactly one tombstone row (no double-write)', tombstoneCount === 1,
      `tombstone count = ${tombstoneCount}`)

    store.close()
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 4: SIGNATURE VERIFIABILITY (4ce5c70) ─────────────────────────
//
// Asserts the tombstone receipt produced by safePrune is independently
// signature-verifiable via verifyTombstoneReceiptSignature (Ed25519 + ML-DSA-65
// hybrid). Also asserts that tampering any field causes verification to return
// false (tamper-detection).
//
// claim_id:   vault.forgetting.tombstone_before_delete (extended at 4ce5c70)
// source_doc: VAULT_COMPOUNDING_SUBSTRATE_SPEC.md section 6.4 Rule B
// target_status: SHIPPED
// vault commit: 4ce5c70

async function scenarioSignatureVerifiable(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-tomb-sig-'))
  try {
    const store = openDatabase({ path: tmpDir, scope: 'test-scope' })
    const db = store.rawDb

    const objectId = 'test-obj-sig-verify'
    const scope = 'test-scope'

    const { oid_hex, canonical_hash } = insertTestCdro(db, objectId, scope)

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

    ok('[sig] safePrune returned pruned:true', result.pruned === true,
      `result = ${JSON.stringify(result)}`)

    const receipt = result.tombstone_receipt
    ok('[sig] tombstone_receipt is present in result', receipt !== undefined)

    if (!receipt) {
      // Cannot proceed without the receipt; remaining assertions are auto-failed
      ok('[sig] receipt.signature is a non-empty string', false, 'receipt absent')
      ok('[sig] verifyTombstoneReceiptSignature returns true for genuine receipt', false, 'receipt absent')
      ok('[sig] verifyTombstoneReceiptSignature returns false after reason tamper', false, 'receipt absent')
      ok('[sig] verifyTombstoneReceiptSignature returns false after decision tamper', false, 'receipt absent')
      store.close()
      return
    }

    ok('[sig] receipt.signature is a non-empty string',
      typeof receipt.signature === 'string' && receipt.signature.length > 0,
      `signature = ${receipt.signature?.slice(0, 60)}...`)

    // Positive: genuine receipt must verify
    const genuineOk = await verifyTombstoneReceiptSignature(receipt)
    ok('[sig] verifyTombstoneReceiptSignature returns true for genuine receipt', genuineOk,
      `genuineOk = ${genuineOk}`)

    // Negative: tamper reason field - verification MUST return false
    const tamperedReason = { ...receipt, reason: 'TAMPERED_REASON_' + receipt.reason }
    const reasonTamperedOk = await verifyTombstoneReceiptSignature(tamperedReason)
    ok('[sig] verifyTombstoneReceiptSignature returns false after reason tamper',
      reasonTamperedOk === false,
      `reasonTamperedOk = ${reasonTamperedOk}`)

    // Negative: tamper decision field
    const tamperedDecision = { ...receipt, decision: 'deny' as const }
    const decisionTamperedOk = await verifyTombstoneReceiptSignature(tamperedDecision)
    ok('[sig] verifyTombstoneReceiptSignature returns false after decision tamper',
      decisionTamperedOk === false,
      `decisionTamperedOk = ${decisionTamperedOk}`)

    // Negative: tamper scope field
    const tamperedScope = { ...receipt, scope: 'attacker-scope' }
    const scopeTamperedOk = await verifyTombstoneReceiptSignature(tamperedScope)
    ok('[sig] verifyTombstoneReceiptSignature returns false after scope tamper',
      scopeTamperedOk === false,
      `scopeTamperedOk = ${scopeTamperedOk}`)

    // Negative: corrupt the raw signature bytes
    const corruptSig = { ...receipt, signature: receipt.signature.slice(0, -8) + 'XXXXXXXX' }
    const corruptSigOk = await verifyTombstoneReceiptSignature(corruptSig)
    ok('[sig] verifyTombstoneReceiptSignature returns false for corrupt signature bytes',
      corruptSigOk === false,
      `corruptSigOk = ${corruptSigOk}`)

    store.close()
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  process.stdout.write('vault.forgetting.tombstone_before_delete conformance vector\n')
  process.stdout.write('claim_id: vault.forgetting.tombstone_before_delete\n')
  process.stdout.write('target_status: SHIPPED\n')
  process.stdout.write('vault branch: line/forget @ 4ce5c70\n\n')

  await scenarioFailurePath()
  await scenarioSuccessPath()
  await scenarioIdempotency()
  await scenarioSignatureVerifiable()

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
