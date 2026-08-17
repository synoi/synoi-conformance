// test/vault.consolidation.scope_isolated.test.ts
//
// Conformance vector: vault.consolidation.scope_isolated
//
// claim_id:   vault.consolidation.scope_isolated
// source_doc: VAULT_COMPOUNDING_SUBSTRATE_SPEC.md section 6.4 Rule C, section 6.10 / F9
// target_status: SHIPPED
//
// Assertions:
//   1. A supersedes pointer in scope-A that points to an object existing ONLY in scope-B
//      causes walkChainInScope to throw ChainScopeViolation.  Fail closed.
//
//   2. runConsolidationSweep on scope-A does NOT touch CDROs in scope-B.
//      Scope-B CDROs are present-and-unchanged after a scope-A sweep.
//
//   3. walkChainInScope returns the full in-scope chain without throwing when all
//      supersedes pointers resolve within the caller's scope.
//
//   4. ChainScopeViolation carries the violating pointer and the caller's scope.
//
//   5. Cross-scope pointer during a prune-enabled sweep is recorded in errors[],
//      the object is NOT tombstoned, and the sweep continues without crashing.
//
// Methodology: import real walkChainInScope + runConsolidationSweep + openDatabase from
// synoi-vault (line/forget @ c492de9).  Set up a temp SQLite vault with two scopes.
// N=1 per scenario (deterministic SQLite).

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { openDatabase }          from '../../../synoi-systems/synoi-vault/src/storage/edge-store.js'
import {
  walkChainInScope,
  runConsolidationSweep,
  ChainScopeViolation,
} from '../../../synoi-systems/synoi-vault/src/storage/forgetting.js'
import { InMemoryJournal }       from '../../../synoi-systems/synoi-vault/src/governance/journal.js'
import { FieldType, FieldPolicyType, BioLevel } from '../../../synoi-systems/synoi-vault/src/types/index.js'
import { buildCDRO }             from '../../../synoi-systems/synoi-vault/src/core/cdro.js'
import { deriveOID, toOIDHex }   from '../../../synoi-systems/synoi-vault/src/core/oid.js'
import { canonicalize, filterCanonicalFields } from '../../../synoi-systems/synoi-vault/src/core/canonicalize.js'
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

// ─── Helper: insert a test CDRO ──────────────────────────────────────────────

function insertTestCdro(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  db: any,
  objectId: string,
  scope: string,
  supersedes: string | null = null,
): { oid_hex: string; canonical_hash: string } {
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
    supersedes,
  })

  return { oid_hex, canonical_hash }
}

// ─── Scenario 1: cross-scope supersedes pointer throws ChainScopeViolation ───

async function scenarioCrossScopeThrows(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-scope-iso-'))
  const store = openDatabase({ path: tmpDir, scope: 'scope-a' })
  try {
    const db = store.rawDb

    // Insert a CDRO in scope-b (the foreign scope)
    insertTestCdro(db, 'foreign-obj', 'scope-b')

    // Insert a CDRO in scope-a that claims to supersede a foreign-scope object.
    // 'foreign-obj' exists only in scope-b, not in scope-a.
    insertTestCdro(db, 'local-obj', 'scope-a', 'foreign-obj')

    // walkChainInScope from scope-a: local-obj.supersedes = foreign-obj,
    // but foreign-obj is not in scope-a, so this MUST throw ChainScopeViolation.
    let threw = false
    let caughtError: unknown

    try {
      walkChainInScope(db, 'local-obj', 'scope-a')
    } catch (err) {
      threw = true
      caughtError = err
    }

    ok('[F9] walkChainInScope throws on cross-scope supersedes pointer', threw,
      `error = ${caughtError instanceof Error ? caughtError.message : String(caughtError)}`)

    ok('[F9] thrown error is ChainScopeViolation instance',
      caughtError instanceof ChainScopeViolation,
      `error type = ${Object.prototype.toString.call(caughtError)}`)

    if (caughtError instanceof ChainScopeViolation) {
      ok('[F9] ChainScopeViolation.supersedes_pointer is the foreign pointer',
        caughtError.supersedes_pointer === 'foreign-obj',
        `supersedes_pointer = ${caughtError.supersedes_pointer}`)
      ok('[F9] ChainScopeViolation.caller_scope is scope-a',
        caughtError.caller_scope === 'scope-a',
        `caller_scope = ${caughtError.caller_scope}`)
      ok('[F9] ChainScopeViolation.name is ChainScopeViolation',
        caughtError.name === 'ChainScopeViolation',
        `name = ${caughtError.name}`)
    }

  } finally {
    store.close()
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 2: in-scope chain resolves correctly without throwing ───────────

async function scenarioInScopeChain(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-scope-chain-'))
  const store = openDatabase({ path: tmpDir, scope: 'scope-a' })
  try {
    const db = store.rawDb

    // Build a chain entirely within scope-a: c -> b -> a (supersedes)
    insertTestCdro(db, 'chain-a', 'scope-a')
    insertTestCdro(db, 'chain-b', 'scope-a', 'chain-a')
    insertTestCdro(db, 'chain-c', 'scope-a', 'chain-b')

    let chain: Array<{ object_id: string; supersedes: string | null }> = []
    let threw = false
    try {
      chain = walkChainInScope(db, 'chain-c', 'scope-a')
    } catch {
      threw = true
    }

    ok('[F9] in-scope chain walk does NOT throw', !threw)
    ok('[F9] in-scope chain has 3 elements', chain.length === 3,
      `chain = ${JSON.stringify(chain)}`)
    ok('[F9] chain head is chain-c', chain[0]?.object_id === 'chain-c',
      `chain[0] = ${JSON.stringify(chain[0])}`)
    ok('[F9] chain tail is chain-a', chain[2]?.object_id === 'chain-a',
      `chain[2] = ${JSON.stringify(chain[2])}`)
    ok('[F9] chain tail supersedes is null', chain[2]?.supersedes === null,
      `chain[2].supersedes = ${chain[2]?.supersedes}`)

  } finally {
    store.close()
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 3: runConsolidationSweep on scope-A does NOT touch scope-B ─────

async function scenarioSweepScopeIsolated(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-sweep-iso-'))
  const store = openDatabase({ path: tmpDir, scope: 'scope-a' })
  try {
    const db = store.rawDb

    // Insert CDROs in both scopes
    insertTestCdro(db, 'scope-a-obj', 'scope-a')
    insertTestCdro(db, 'scope-b-obj', 'scope-b')

    // Capture scope-b identity before sweep of scope-a
    const bBefore = db.prepare(
      `SELECT oid_hex, canonical_hash FROM cdros WHERE object_id = 'scope-b-obj' AND scope = 'scope-b' LIMIT 1`,
    ).get() as { oid_hex: string; canonical_hash: string } | undefined

    const journal = new InMemoryJournal()

    // Phase 1: prune_enabled defaults to false; sweep visits but does not prune
    const sweepResult = await runConsolidationSweep(db, {
      scope:         'scope-a',
      journal,
      prune_enabled: false,
      batch_size:    100,
    })

    ok('[F9-sweep] sweep scope field is scope-a', sweepResult.scope === 'scope-a',
      `scope = ${sweepResult.scope}`)

    // scope-b CDRO must be untouched
    const bAfter = db.prepare(
      `SELECT oid_hex, canonical_hash FROM cdros WHERE object_id = 'scope-b-obj' AND scope = 'scope-b' LIMIT 1`,
    ).get() as { oid_hex: string; canonical_hash: string } | undefined

    ok('[F9-sweep] scope-b CDRO still exists after scope-a sweep', bAfter !== undefined)
    ok('[F9-sweep] scope-b oid_hex unchanged',
      bAfter?.oid_hex === bBefore?.oid_hex,
      `before=${bBefore?.oid_hex} after=${bAfter?.oid_hex}`)
    ok('[F9-sweep] scope-b canonical_hash unchanged',
      bAfter?.canonical_hash === bBefore?.canonical_hash,
      `before=${bBefore?.canonical_hash} after=${bAfter?.canonical_hash}`)

    // No tombstone was written for scope-b objects
    const bTombstone = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'tombstone:scope-b-obj' LIMIT 1`,
    ).get()
    ok('[F9-sweep] no tombstone written for scope-b object by scope-a sweep',
      bTombstone === undefined,
      `tombstone = ${JSON.stringify(bTombstone)}`)

    // scope-a object was visited (visited >= 1)
    ok('[F9-sweep] scope-a sweep visited >= 1 object', sweepResult.visited >= 1,
      `visited = ${sweepResult.visited}`)

    // No errors during sweep
    ok('[F9-sweep] no errors during scope-a sweep', sweepResult.errors.length === 0,
      `errors = ${JSON.stringify(sweepResult.errors)}`)

  } finally {
    store.close()
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Scenario 4: cross-scope pointer during prune-enabled sweep lands in errors[] ──
//
// When a prune-enabled sweep encounters a cross-scope supersedes pointer,
// walkChainInScope throws ChainScopeViolation.  The sweep catches it, records the
// error in result.errors[], and continues without crashing.  The object is NOT tombstoned.

async function scenarioCrossScopeInSweepErrors(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'synoi-conf-sweep-crossscope-'))
  const store = openDatabase({ path: tmpDir, scope: 'scope-a' })
  try {
    const db = store.rawDb

    // Insert a scope-b root object (the foreign target)
    insertTestCdro(db, 'cross-root', 'scope-b')

    // Insert a scope-a object that supersedes a scope-b object.
    // The supersedes pointer is a cross-scope reference.
    insertTestCdro(db, 'cross-head', 'scope-a', 'cross-root')

    // Set stability=1.3 so cross-head is prune-eligible:
    // For unverified trust_level, provenanceSurvivalFloor=1.0.
    // prunable() returns true only when stability > floor (1.0).
    // 1.3 > 1.0 => prunable=true.  With prune_threshold=2.0, 1.3 < 2.0 => gate passes.
    // The sweep then calls walkChainInScope, which throws ChainScopeViolation.
    db.prepare(
      `UPDATE cdros SET stability = 1.3, ` +
      `truth_quality_json = '{"trust_level":"unverified","birth_level":"full","extraction_depth":"deep","plaintext_availability":"available","provenance_confidence":1.0}' ` +
      `WHERE object_id = 'cross-head' AND scope = 'scope-a'`,
    ).run()

    const journal = new InMemoryJournal()

    // Enable prune with threshold=2.0; cross-head (stability=1.3) is prune-eligible,
    // triggering the F9 walkChainInScope path which throws ChainScopeViolation.
    const sweepResult = await runConsolidationSweep(db, {
      scope:           'scope-a',
      journal,
      prune_enabled:   true,
      prune_threshold: 2.0,
      batch_size:      100,
    })

    ok('[F9-cross-sweep] sweep completes without throwing', true)
    ok('[F9-cross-sweep] sweep scope is scope-a', sweepResult.scope === 'scope-a',
      `scope = ${sweepResult.scope}`)

    // The cross-scope pointer must have produced an error entry
    ok('[F9-cross-sweep] cross-scope pointer produces an errors[] entry',
      sweepResult.errors.length >= 1,
      `errors = ${JSON.stringify(sweepResult.errors)}`)

    // The error message identifies the scope walk failure
    const hasViolationMsg = sweepResult.errors.some(e =>
      e.includes('scope walk failed') || e.includes('scope violation') ||
      e.includes('cross-root') || e.includes('fail closed'),
    )
    ok('[F9-cross-sweep] errors[] contains scope-violation message', hasViolationMsg,
      `errors = ${JSON.stringify(sweepResult.errors)}`)

    // cross-head body was NOT tombstoned (sweep skipped it due to scope error)
    const tombstone = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'tombstone:cross-head' AND scope = 'scope-a' LIMIT 1`,
    ).get()
    ok('[F9-cross-sweep] cross-scope object NOT tombstoned (sweep skipped it)', tombstone === undefined,
      `tombstone = ${JSON.stringify(tombstone)}`)

    // scope-b root remains untouched
    const bRoot = db.prepare(
      `SELECT object_id FROM cdros WHERE object_id = 'cross-root' AND scope = 'scope-b' LIMIT 1`,
    ).get()
    ok('[F9-cross-sweep] scope-b root still exists', bRoot !== undefined)

  } finally {
    store.close()
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  process.stdout.write('vault.consolidation.scope_isolated conformance vector\n')
  process.stdout.write('claim_id: vault.consolidation.scope_isolated\n')
  process.stdout.write('target_status: SHIPPED\n')
  process.stdout.write('vault branch: line/forget @ c492de9\n\n')

  await scenarioCrossScopeThrows()
  await scenarioInScopeChain()
  await scenarioSweepScopeIsolated()
  await scenarioCrossScopeInSweepErrors()

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
