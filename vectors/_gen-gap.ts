// vectors/_gen-gap.ts -- generate GAP conformance vectors against the
// @synoi/gap-types reference. Run with `npm run gen:gap`.
//
// ADR_007: type prefix changed from agp: to gap:; agp_version -> gap_version.
//
// Output:
//   vectors/gap/validate.json    -- well-formed + malformed per top-level type
//   vectors/gap/oid.json         -- computeGapOid fixed inputs + outputs

import { writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  computeGapOid,
  validateCapabilityDeclaration,
  validateCapabilityGrant,
  validateCapabilityInvocation,
  validateWorkflowDefinition,
  validateGapDecisionReceipt,
  validateRevocationEvent,
} from '@synoi/gap'

const here = dirname(fileURLToPath(import.meta.url))
const gapDir = join(here, 'gap')

// ── Validate vectors ──────────────────────────────────────────────────────

const goodDeclaration = {
  oid:           'sha256:0000000000000000000000000000000000000000000000000000000000000001',
  type:          'gap:capability_declaration',
  gap_version:   '1.0',
  tenant_id:     't-1',
  created_at_ms: 1700000000000,
  created_by:    'test-actor',
  body: {
    actor_type: 'service',
    actor_id:   'service-A',
    actor_name: 'Service A',
    actor_version: '1.0.0',
    capabilities: [{ capability: 'cap.x', safety_class: 'A' }],
  },
}

const goodGrant = {
  oid:           'sha256:0000000000000000000000000000000000000000000000000000000000000002',
  type:          'gap:capability_grant',
  gap_version:   '1.0',
  tenant_id:     't-1',
  created_at_ms: 1700000000000,
  created_by:    'op',
  body: {
    grantee:           { actor_type: 'agent', actor_oid: 'agent:test' },
    capability_scopes: [{ capability: 'cap.x', capability_declaration_oid: goodDeclaration.oid }],
    granted_at_ms:     1700000000000,
    expires_at_ms:     null,
    granted_by:        'op',
  },
}

const goodInvocation = {
  oid:           'sha256:0000000000000000000000000000000000000000000000000000000000000003',
  type:          'gap:capability_invocation',
  gap_version:   '1.0',
  tenant_id:     't-1',
  created_at_ms: 1700000000000,
  created_by:    'agent:test',
  body: {
    caller: {
      actor_type: 'agent',
      actor_oid:  'agent:test',
      grant_oid:  goodGrant.oid,
    },
    capability:                 'cap.x',
    capability_declaration_oid: goodDeclaration.oid,
    args:                       { foo: 'bar' },
    idempotency_key:            'op-001',
    invoked_at_ms:              1700000000000,
  },
}

const goodWorkflowDef = {
  oid:           'sha256:0000000000000000000000000000000000000000000000000000000000000004',
  type:          'gap:workflow_definition',
  gap_version:   '1.0',
  tenant_id:     't-1',
  created_at_ms: 1700000000000,
  created_by:    'op',
  body: {
    workflow_id:      'wf-1',
    workflow_name:    'Test workflow',
    workflow_version: '1.0.0',
    trigger:          { kind: 'explicit' },
    initial_stage_id: 'stage:start',
    required_channels: [],
    max_total_duration_seconds: 3600,
    stages: [{
      stage_id: 'stage:start',
      terminal: true,
      terminal_outcome: 'approved',
    }],
  },
}

const goodReceipt = {
  oid:           'sha256:0000000000000000000000000000000000000000000000000000000000000005',
  type:          'gap:decision_receipt',
  gap_version:   '1.0',
  tenant_id:     't-1',
  created_at_ms: 1700000000000,
  created_by:    'agent:test',
  body: {
    subject_kind:    'capability_invocation',
    subject_oid:     goodInvocation.oid,
    initiator:       { actor_type: 'agent', actor_oid: 'agent:test' },
    status:          'ok',
    initiated_at_ms: 1700000000000,
    resolved_at_ms:  1700000000005,
  },
}

const goodRevocation = {
  oid:           'sha256:0000000000000000000000000000000000000000000000000000000000000006',
  type:          'gap:revocation_event',
  gap_version:   '1.0',
  tenant_id:     't-1',
  created_at_ms: 1700000000000,
  created_by:    'op',
  body: {
    target_kind:    'capability_grant',
    target_oid:     goodGrant.oid,
    reason:         'rotation',
    required_level: 1,
    provisional:    false,
    approvers:      [{ actor_oid: 'op', approved_at_ms: 1700000000000, cooling_off_satisfied: true }],
    effective_at_ms: 1700000000000,
  },
}

interface ValidateVector {
  name:                     string
  kind:                     'validate'
  target:                   string
  input:                    unknown
  expected_ok:              boolean
  expected_errors_include?: string[]
}

const validateVectors: ValidateVector[] = [
  // CapabilityDeclaration
  { name: 'cap_decl: well-formed',                       kind: 'validate', target: 'capability_declaration', input: goodDeclaration,                                           expected_ok: true },
  { name: 'cap_decl: missing body',                      kind: 'validate', target: 'capability_declaration', input: { ...goodDeclaration, body: undefined },                  expected_ok: false },
  { name: 'cap_decl: wrong type field',                  kind: 'validate', target: 'capability_declaration', input: { ...goodDeclaration, type: 'gap:wrong_type' },           expected_ok: false },
  { name: 'cap_decl: tolerates extra unknown key',       kind: 'validate', target: 'capability_declaration', input: { ...goodDeclaration, unknown_future_field: 'x' },        expected_ok: true },

  // CapabilityGrant
  { name: 'cap_grant: well-formed',                      kind: 'validate', target: 'capability_grant',       input: goodGrant,                                                  expected_ok: true },
  { name: 'cap_grant: missing grantee',                  kind: 'validate', target: 'capability_grant',       input: { ...goodGrant, body: { ...goodGrant.body, grantee: undefined } }, expected_ok: false },
  { name: 'cap_grant: wrong tenant_id type',             kind: 'validate', target: 'capability_grant',       input: { ...goodGrant, tenant_id: 123 },                          expected_ok: false },
  { name: 'cap_grant: tolerates extra key in body',      kind: 'validate', target: 'capability_grant',       input: { ...goodGrant, body: { ...goodGrant.body, label: 'x' } }, expected_ok: true },

  // CapabilityInvocation
  { name: 'cap_inv: well-formed',                        kind: 'validate', target: 'capability_invocation',  input: goodInvocation,                                             expected_ok: true },
  { name: 'cap_inv: missing capability',                 kind: 'validate', target: 'capability_invocation',  input: { ...goodInvocation, body: { ...goodInvocation.body, capability: undefined } }, expected_ok: false },
  { name: 'cap_inv: wrong-type invoked_at_ms',           kind: 'validate', target: 'capability_invocation',  input: { ...goodInvocation, body: { ...goodInvocation.body, invoked_at_ms: 'now' } }, expected_ok: false },
  { name: 'cap_inv: tolerates extra unknown key',        kind: 'validate', target: 'capability_invocation',  input: { ...goodInvocation, body: { ...goodInvocation.body, sla_hint: { max_latency_ms: 500 } } }, expected_ok: true },

  // WorkflowDefinition
  { name: 'wf_def: well-formed',                          kind: 'validate', target: 'workflow_definition',     input: goodWorkflowDef,                                            expected_ok: true },
  { name: 'wf_def: stages is not an array',              kind: 'validate', target: 'workflow_definition',     input: { ...goodWorkflowDef, body: { ...goodWorkflowDef.body, stages: 'oops' } }, expected_ok: false },
  { name: 'wf_def: missing workflow_version',            kind: 'validate', target: 'workflow_definition',     input: { ...goodWorkflowDef, body: { ...goodWorkflowDef.body, workflow_version: undefined } }, expected_ok: false },
  { name: 'wf_def: tolerates extra unknown body key',    kind: 'validate', target: 'workflow_definition',     input: { ...goodWorkflowDef, body: { ...goodWorkflowDef.body, description: 'desc' } }, expected_ok: true },

  // DecisionReceipt
  { name: 'receipt: well-formed',                        kind: 'validate', target: 'decision_receipt',         input: goodReceipt,                                                expected_ok: true },
  { name: 'receipt: missing subject_oid',                kind: 'validate', target: 'decision_receipt',         input: { ...goodReceipt, body: { ...goodReceipt.body, subject_oid: undefined } }, expected_ok: false },
  { name: 'receipt: wrong status value',                 kind: 'validate', target: 'decision_receipt',         input: { ...goodReceipt, body: { ...goodReceipt.body, status: 'maybe' } }, expected_ok: false },
  { name: 'receipt: tolerates extra key',                kind: 'validate', target: 'decision_receipt',         input: { ...goodReceipt, body: { ...goodReceipt.body, note: 'audit' } }, expected_ok: true },

  // RevocationEvent
  { name: 'revocation: well-formed',                     kind: 'validate', target: 'revocation_event',         input: goodRevocation,                                            expected_ok: true },
  { name: 'revocation: bad target_kind',                 kind: 'validate', target: 'revocation_event',         input: { ...goodRevocation, body: { ...goodRevocation.body, target_kind: 'nonsense' } }, expected_ok: false },
  { name: 'revocation: missing reason',                  kind: 'validate', target: 'revocation_event',         input: { ...goodRevocation, body: { ...goodRevocation.body, reason: undefined } }, expected_ok: false },
  { name: 'revocation: tolerates extra key',             kind: 'validate', target: 'revocation_event',         input: { ...goodRevocation, body: { ...goodRevocation.body, attestation_url: 'https://x' } }, expected_ok: true },
]

writeFileSync(join(gapDir, 'validate.json'), JSON.stringify(validateVectors, null, 2) + '\n')

// Sanity -- fail loudly if a vector marked expected_ok=true doesn't validate
const validatorMap: Record<string, (x: unknown) => { ok: boolean; errors: string[] }> = {
  capability_declaration: validateCapabilityDeclaration,
  capability_grant:       validateCapabilityGrant,
  capability_invocation:  validateCapabilityInvocation,
  workflow_definition:    validateWorkflowDefinition,
  decision_receipt:       validateGapDecisionReceipt,
  revocation_event:       validateRevocationEvent,
}
for (const v of validateVectors) {
  const fn = validatorMap[v.target]
  if (!fn) { console.error(`unknown target: ${v.target}`); process.exit(1) }
  const r = fn(v.input)
  if (r.ok !== v.expected_ok) {
    console.error(`vector "${v.name}" failed self-check: expected ok=${v.expected_ok}, got ok=${r.ok}\n  errors: ${r.errors.join(',')}`)
    process.exit(1)
  }
}

// ── computeGapOid vectors -- fix tenant + body + created_at_ms; capture output ──

interface OidVector {
  name:          string
  kind:          'oid'
  input:         unknown
  expected_oid:  string
}

const oidInputs: Array<{ name: string; payload: { type: string; tenant_id: string; created_at_ms: number; body: unknown } }> = [
  { name: 'capability_declaration small',  payload: { type: 'gap:capability_declaration', tenant_id: 't1', created_at_ms: 1700000000000, body: goodDeclaration.body } },
  { name: 'capability_grant small',        payload: { type: 'gap:capability_grant',       tenant_id: 't1', created_at_ms: 1700000000000, body: goodGrant.body } },
  { name: 'capability_invocation small',   payload: { type: 'gap:capability_invocation',  tenant_id: 't1', created_at_ms: 1700000000000, body: goodInvocation.body } },
  { name: 'workflow_definition small',     payload: { type: 'gap:workflow_definition',    tenant_id: 't1', created_at_ms: 1700000000000, body: goodWorkflowDef.body } },
  { name: 'decision_receipt small',        payload: { type: 'gap:decision_receipt',       tenant_id: 't1', created_at_ms: 1700000000000, body: goodReceipt.body } },
  { name: 'revocation_event small',        payload: { type: 'gap:revocation_event',       tenant_id: 't1', created_at_ms: 1700000000000, body: goodRevocation.body } },
]

const oidVectors: OidVector[] = oidInputs.map(v => ({
  name:          v.name,
  kind:          'oid',
  input:         v.payload,
  expected_oid:  computeGapOid(v.payload),
}))

writeFileSync(join(gapDir, 'oid.json'), JSON.stringify(oidVectors, null, 2) + '\n')

process.stdout.write('Wrote GAP vectors:\n')
process.stdout.write(`  validate.json  ${validateVectors.length} vectors\n`)
process.stdout.write(`  oid.json       ${oidVectors.length} vectors\n`)
