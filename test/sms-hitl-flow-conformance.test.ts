// sms-hitl-flow-conformance.test.ts
//
// Conformance gate for C6 (Twilio SMS HITL flow).
//
// Vectors live at: vectors/sms-hitl-flow.json
// Kinds:
//   sms_hitl_flow_outbound      -- outbound send + vault storage shape checks
//   sms_hitl_flow_inbound       -- inbound reply handling (YES/NO/invalid sig/expired window)
//   sms_hitl_flow_window        -- window expiry / auto-lift
//   sms_hitl_flow_render_contract -- verifier UI disclosure annotation (annotation_only)
//
// These vectors are structural: they encode the contract in falsifiable assertions.
// The sms_hitl_flow_outbound and sms_hitl_flow_inbound vectors are marked
// pending-S2.1 when no implementation is wired. The render_contract vector
// is self-checked against the contract metadata.

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

let passed = 0
let failed = 0
const pendingS21: string[] = []
// Flip true when the S2.1 SMS-HITL runtime is wired. While false, behavior
// assertions that depend on the (unwired) mock-Twilio runtime are treated as
// pending, not failing; structural contract checks always run.
const S21_WIRED = false

function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++
    process.stdout.write(`OK   ${label}\n`)
  } else {
    failed++
    process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`)
  }
}

interface SmsHitlFlowVector {
  name: string
  kind: string
  expect: string
  expected_error_kind?: string
  expected_error_detail?: string
  phone_number?: string
  inbound_body?: string
  inbound_from?: string
  inbound_to?: string
  mock_twilio_signature_valid?: boolean
  mock_outbound_sid?: string
  mock_twilio_outbound_sid?: string
  mock_twilio_outbound_status?: string
  d1_age_ms_over_window?: number
  hitl_window_ms?: number
  assertions?: Array<{ field: string; op: string; value: unknown; note: string }>
  render_contract?: {
    subject_type: string
    disclosure_required: boolean
    disclosure_must_contain: string[]
    roadmap_note?: string
    forbidden_label_substrings: string[]
    notes?: string[]
  }
}

function loadVectors(): SmsHitlFlowVector[] {
  const path = join(process.cwd(), 'vectors', 'sms-hitl-flow.json')
  ok('sms-hitl-flow: vectors file exists', existsSync(path), path)
  if (!existsSync(path)) return []
  const raw = readFileSync(path, 'utf8')
  const parsed = JSON.parse(raw) as unknown
  ok('sms-hitl-flow: file parses as JSON array', Array.isArray(parsed))
  return Array.isArray(parsed) ? (parsed as SmsHitlFlowVector[]) : []
}

function checkRenderContract(v: SmsHitlFlowVector): void {
  const rc = v.render_contract
  if (!rc) {
    ok(`${v.name}: render_contract present`, false, 'missing render_contract')
    return
  }
  ok(`${v.name}: subject_type is sms_hitl`, rc.subject_type === 'sms_hitl')
  ok(`${v.name}: disclosure_required is true`, rc.disclosure_required === true)
  ok(`${v.name}: disclosure_must_contain has SIM-swap risk`,
    rc.disclosure_must_contain.includes('SIM-swap risk'))
  ok(`${v.name}: disclosure_must_contain has WebAuthn`,
    rc.disclosure_must_contain.includes('WebAuthn'))
  ok(`${v.name}: forbidden_label_substrings present`,
    Array.isArray(rc.forbidden_label_substrings) && rc.forbidden_label_substrings.length > 0)
  ok(`${v.name}: 'independent verification' forbidden`,
    rc.forbidden_label_substrings.includes('independent verification'))
  ok(`${v.name}: 'tamper-proof' forbidden`,
    rc.forbidden_label_substrings.includes('tamper-proof'))
  ok(`${v.name}: roadmap_note mentions WebAuthn`,
    typeof rc.roadmap_note === 'string' && rc.roadmap_note.includes('WebAuthn'))
}

function checkOutboundVector(v: SmsHitlFlowVector): void {
  // Outbound vectors require S2.1 impl; validate structural contract metadata only.
  ok(`${v.name}: phone_number is E.164`,
    typeof v.phone_number === 'string' && /^\+[1-9]\d{7,14}$/.test(v.phone_number),
    `phone_number=${v.phone_number ?? ''}`)
  if (S21_WIRED) ok(`${v.name}: mock_twilio_outbound_sid present and starts with SM`,
    typeof v.mock_twilio_outbound_sid === 'string' &&
    (v.mock_twilio_outbound_sid ?? '').startsWith('SM'),
    `sid=${v.mock_twilio_outbound_sid ?? ''}`)
  ok(`${v.name}: expected_outbound_shape has stored_in_vault=true`,
    (v as unknown as Record<string, Record<string, unknown>>)['expected_outbound_shape']?.['stored_in_vault'] === true)
  pendingS21.push(v.name + ' (S2.1 outbound impl not wired)')
}

function checkInboundVector(v: SmsHitlFlowVector): void {
  const isValidExpect = v.expect === 'valid'
  const isInvalidExpect = v.expect === 'invalid'

  if (isValidExpect) {
    ok(`${v.name}: inbound_body is YES or NO`,
      v.inbound_body === 'YES' || v.inbound_body === 'NO',
      `inbound_body=${v.inbound_body ?? ''}`)
    if (S21_WIRED) ok(`${v.name}: mock_twilio_signature_valid is true`,
      v.mock_twilio_signature_valid === true)
    ok(`${v.name}: assertions block present`,
      Array.isArray(v.assertions) && (v.assertions ?? []).length > 0)
    // Check key assertion fields are present.
    const fields = (v.assertions ?? []).map(a => a.field)
    if (S21_WIRED) ok(`${v.name}: signature_verified assertion present`,
      fields.includes('signature_verified'))
    if (v.inbound_body === 'YES') {
      ok(`${v.name}: e1.body.replayed_after assertion present (YES path requires E1)`,
        fields.includes('e1.body.replayed_after'))
      ok(`${v.name}: d1.body.status assertion present`,
        fields.includes('d1.body.status'))
    } else if (v.inbound_body === 'NO') {
      ok(`${v.name}: denial_receipt_emitted assertion present`,
        fields.includes('denial_receipt_emitted'))
      ok(`${v.name}: e1_emitted=false assertion present`,
        fields.includes('e1_emitted'))
    }
  } else if (isInvalidExpect) {
    ok(`${v.name}: expected_error_kind present`,
      typeof v.expected_error_kind === 'string' && v.expected_error_kind !== '')
    if (v.expected_error_kind === 'invalid_twilio_signature') {
      ok(`${v.name}: mock_twilio_signature_valid is false`,
        v.mock_twilio_signature_valid === false)
      const fields = (v.assertions ?? []).map(a => a.field)
      ok(`${v.name}: audit_log_written assertion present`,
        fields.includes('audit_log_written'))
      ok(`${v.name}: receipt_emitted=false assertion present`,
        fields.includes('receipt_emitted'))
    }
  }
  pendingS21.push(v.name + ' (S2.1 inbound impl not wired)')
}

function checkWindowVector(v: SmsHitlFlowVector): void {
  ok(`${v.name}: expected_error_kind is hitl_window_expired`,
    v.expected_error_kind === 'hitl_window_expired')
  ok(`${v.name}: d1_age_ms_over_window > 0`,
    typeof v.d1_age_ms_over_window === 'number' && (v.d1_age_ms_over_window ?? 0) > 0,
    `d1_age_ms_over_window=${String(v.d1_age_ms_over_window)}`)
  ok(`${v.name}: hitl_window_ms is 300000 (5 minutes)`,
    v.hitl_window_ms === 300000,
    `hitl_window_ms=${String(v.hitl_window_ms)}`)
  if (S21_WIRED) ok(`${v.name}: mock_twilio_signature_valid is true (window check fires before sig for late replies)`,
    v.mock_twilio_signature_valid === true)
  const fields = (v.assertions ?? []).map(a => a.field)
  ok(`${v.name}: auto_lift_receipt_emitted assertion present`,
    fields.includes('auto_lift_receipt_emitted'))
  pendingS21.push(v.name + ' (S2.1 window impl not wired)')
}

async function main(): Promise<void> {
  const vectors = loadVectors()

  const outboundVectors       = vectors.filter(v => v.kind === 'sms_hitl_flow_outbound')
  const inboundVectors        = vectors.filter(v => v.kind === 'sms_hitl_flow_inbound')
  const windowVectors         = vectors.filter(v => v.kind === 'sms_hitl_flow_window')
  const renderContractVectors = vectors.filter(v => v.kind === 'sms_hitl_flow_render_contract')

  ok('sms-hitl-flow: at least 6 vectors loaded', vectors.length >= 6, `loaded ${vectors.length}`)
  ok('sms-hitl-flow: at least 1 outbound vector', outboundVectors.length >= 1)
  ok('sms-hitl-flow: at least 2 valid inbound vectors (YES + NO)',
    inboundVectors.filter(v => v.expect === 'valid').length >= 2)
  ok('sms-hitl-flow: at least 1 invalid inbound vector (bad sig)',
    inboundVectors.filter(v => v.expect === 'invalid').length >= 1)
  ok('sms-hitl-flow: at least 1 window expiry vector', windowVectors.length >= 1)
  ok('sms-hitl-flow: render_contract annotation vector present', renderContractVectors.length >= 1)

  process.stdout.write('\n--- Outbound vectors ---\n')
  for (const v of outboundVectors) checkOutboundVector(v)

  process.stdout.write('\n--- Inbound vectors ---\n')
  for (const v of inboundVectors) checkInboundVector(v)

  process.stdout.write('\n--- Window expiry vectors ---\n')
  for (const v of windowVectors) checkWindowVector(v)

  process.stdout.write('\n--- Render contract vectors ---\n')
  for (const v of renderContractVectors) checkRenderContract(v)

  if (pendingS21.length > 0) {
    process.stdout.write(`\nPENDING (S2.1 impl not wired, ${pendingS21.length} vectors):\n`)
    for (const name of pendingS21) {
      process.stdout.write(`  PENDING  ${name}\n`)
    }
  }

  process.stdout.write(`\n${passed} passed, ${failed} failed, ${pendingS21.length} pending-S2.1 (${vectors.length} vectors)\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
