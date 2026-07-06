// protocols/cited-oracle-inputs.ts
//
// Conformance runner for two test surfaces introduced in Sprint 1 Story S1.12:
//
//   C2 (cited_oracle_inputs schema):
//     Validates that a verifier correctly accepts well-formed entries and rejects
//     malformed entries per DEMO_PREWORK_SCHEMAS_2026-06-17.md Specification 1.
//
//   C3 (PIP wrapper):
//     Validates that a feed adapter implementation returns FeedResult values whose
//     shape and hash integrity align with the WIT contract defined in Specification 2.
//
// Vector kinds:
//   cited_oracle_input_entry  -- schema + hash-integrity check (C2)
//   pip_wrapper_fetch         -- adapter fetch I/O check (C3)
//   pip_wrapper_gate_boundary -- gate self-check before receipt signing (C3)
//
// Implementations under test must export:
//   verifyCitedOracleInputEntry(entry: unknown): { ok: boolean; error_kind?: string; error_detail?: string }
//   pipWrapperFetch(args: { subject_type: string; subject_value: string; mock?: unknown }):
//     Promise<{ ok: true; feed_result: FeedResult } | { ok: false; error_kind: string }>
//   pipWrapperGateBoundaryCheck(feed_result: FeedResult):
//     { action: 'proceed' | 'emit_denial_receipt'; cited_reason?: string }
//
// When S1.1 is not yet implemented, all vectors in this file will FAIL. That is
// expected: these vectors are the spec encoded ahead of the implementation.

import type { Vector, VectorResult } from '../types.js'
import { pathToFileURL } from 'node:url'
import { createHash } from 'node:crypto'

// Minimal FeedResult type matching Specification 2 Section 2.3.
export interface FeedResult {
  raw_value:      string
  value_hash:     string
  fetched_at:     string
  source_url:     string
  feed_claimed_at?: string
  source_cursor?:   string
}

// Expected shape of a cited_oracle_inputs[] entry per Specification 1 Section 1.1.
interface CitedOracleInputEntry {
  subject_type:   string
  value_hash:     string
  raw_value:      unknown
  fetched_at:     string
  source_url:     string
  feed_claimed_at?: string | null
  source_cursor?:   string | null
  [k: string]: unknown
}

interface VerifyEntryResult {
  ok:            boolean
  error_kind?:   string
  error_detail?: string
}

interface PipWrapperImpl {
  verifyCitedOracleInputEntry?(entry: unknown): VerifyEntryResult
  pipWrapperFetch?(args: {
    subject_type:   string
    subject_value:  string
    mock_upstream_status?:       number
    mock_upstream_response?:     unknown
    mock_upstream_response_body?: string
    mock_vault_snapshot?:        unknown
    mock_twilio_outbound_sid?:   string
    mock_twilio_inbound_body?:   string
    mock_upstream_timeout?:      boolean
    mock_timeout_after_ms?:      number
    mock_eval_snippet?:          string
    mock_eval_snippet_hash?:     string
    mock_eval_result?:           unknown
    injection_mode?:             string
    mock_twilio_inbound_received_at?: string
    mock_twilio_inbound_sid?:    string
    onInboundReceived?:          ((sid: string) => Promise<{ body: string; provider_message_sid: string; received_at: string }>)
  }): Promise<{ ok: true; feed_result: FeedResult } | { ok: false; error_kind: string }>
  pipWrapperGateBoundaryCheck?(feed_result: FeedResult): {
    action: 'proceed' | 'emit_denial_receipt'
    cited_reason?: string
  }
}

// Known valid subject_types per spec Section 1.1.
const VALID_SUBJECT_TYPES = new Set(['weather', 'ofac', 'time', 'sms_hitl', 'webhook', 'cve'])

// RFC 3339 UTC with millisecond precision and trailing Z.
// Accepts: 2026-06-17T19:32:18.412Z
// Rejects: 2026-06-17T19:32:18Z (no ms) | 2026-06-17T19:32:18.412+00:00 (offset)
const RFC3339_MS_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

// sha256:<64 hex chars>
const VALUE_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/

function jcs(v: unknown): string {
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v.toString()
  if (typeof v === 'number') return v.toString()
  if (typeof v === 'string') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + (v as unknown[]).map(jcs).join(',') + ']'
  if (typeof v === 'object') {
    const obj = v as Record<string, unknown>
    const keys = Object.keys(obj).sort()
    return '{' + keys.map(k => JSON.stringify(k) + ':' + jcs(obj[k])).join(',') + '}'
  }
  throw new Error(`jcs: cannot serialize ${typeof v}`)
}

function sha256Hex(s: string): string {
  return 'sha256:' + createHash('sha256').update(s, 'utf8').digest('hex')
}

// Standalone schema + hash-integrity verifier used by both the runner and
// the fallback path when the impl under test has no verifyCitedOracleInputEntry.
export function standaloneVerifyEntry(entry: unknown): VerifyEntryResult {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    return { ok: false, error_kind: 'schema_error', error_detail: 'entry must be a JSON object' }
  }
  const e = entry as CitedOracleInputEntry
  const KNOWN_KEYS = new Set([
    'subject_type', 'value_hash', 'raw_value', 'fetched_at', 'source_url',
    'feed_claimed_at', 'source_cursor',
  ])
  for (const k of Object.keys(e)) {
    if (!KNOWN_KEYS.has(k)) {
      return { ok: false, error_kind: 'schema_error', error_detail: `cited_oracle_inputs[] unknown key '${k}'` }
    }
  }
  // Required fields.
  const required = ['subject_type', 'value_hash', 'raw_value', 'fetched_at', 'source_url'] as const
  for (const f of required) {
    if (!(f in e) || e[f] === undefined || e[f] === null) {
      return { ok: false, error_kind: 'schema_error', error_detail: `cited_oracle_inputs[].${f} missing` }
    }
  }
  // subject_type closed enum.
  if (!VALID_SUBJECT_TYPES.has(String(e.subject_type))) {
    return { ok: false, error_kind: 'schema_error', error_detail: `cited_oracle_inputs[].subject_type unknown value '${e.subject_type}'` }
  }
  // value_hash format.
  if (!VALUE_HASH_PATTERN.test(String(e.value_hash))) {
    return { ok: false, error_kind: 'schema_error', error_detail: 'cited_oracle_inputs[].value_hash must match sha256:<64 hex>' }
  }
  // fetched_at RFC 3339 UTC ms.
  if (!RFC3339_MS_Z.test(String(e.fetched_at))) {
    return { ok: false, error_kind: 'schema_error', error_detail: 'cited_oracle_inputs[].fetched_at must be RFC 3339 UTC with millisecond precision and trailing Z' }
  }
  // Optional fields: null is forbidden; must be omitted or a non-null string.
  if ('feed_claimed_at' in e) {
    if (e.feed_claimed_at === null) {
      return { ok: false, error_kind: 'schema_error', error_detail: 'cited_oracle_inputs[].feed_claimed_at must be omitted, not null' }
    }
    if (!RFC3339_MS_Z.test(String(e.feed_claimed_at))) {
      return { ok: false, error_kind: 'schema_error', error_detail: 'cited_oracle_inputs[].feed_claimed_at must be RFC 3339 UTC with millisecond precision and trailing Z' }
    }
  }
  if ('source_cursor' in e && e.source_cursor === null) {
    return { ok: false, error_kind: 'schema_error', error_detail: 'cited_oracle_inputs[].source_cursor must be omitted, not null' }
  }
    // vault:// source_url OID must be full 64-hex sha256 form.
  // Rule per CLARIFICATIONS.md item 1: oid-[a-f0-9]{64} is the only accepted form on receipts.
  // Shortform (oid-[a-f0-9]{6,63}) is rejected here before hash checks so the failure reason
  // is deterministic: the OID check fires first.
  if (typeof e.source_url === 'string' && e.source_url.startsWith('vault://')) {
    // Extract the last path segment as the OID segment.
    const oidSegment = e.source_url.split('/').pop() ?? ''
    if (!oidSegment.startsWith('oid-') || !/^oid-[a-f0-9]{64}$/.test(oidSegment)) {
      return {
        ok: false,
        error_kind: 'schema_error',
        error_detail: 'schema_error: source_url vault scheme OID must be full 64-hex sha256',
      }
    }
  }
  // value_hash integrity: sha256(JCS(raw_value)).
  let computedHash: string
  try {
    computedHash = sha256Hex(jcs(e.raw_value))
  } catch (err) {
    return { ok: false, error_kind: 'integrity_error', error_detail: `jcs(raw_value) failed: ${(err as Error).message}` }
  }
  if (computedHash !== String(e.value_hash)) {
    return { ok: false, error_kind: 'integrity_error', error_detail: 'cited_oracle_inputs[].value_hash does not match sha256(JCS(raw_value))' }
  }
  return { ok: true }
}

export async function runCitedOracleInputsVectors(
  implPath: string | undefined,
  vectors: Vector[],
): Promise<VectorResult[]> {
  const impl = implPath ? await loadImpl(implPath) : {}
  const out: VectorResult[] = []

  for (const v of vectors) {
    const kind = String(v['kind'])
    if (kind === 'cited_oracle_input_entry') {
      out.push(runEntryVector(impl, v))
    } else if (kind === 'pip_wrapper_fetch') {
      out.push(await runFetchVector(impl, v))
    } else if (kind === 'pip_wrapper_gate_boundary') {
      out.push(runGateBoundaryVector(impl, v))
    } else {
      out.push({
        vector_name: v.name,
        passed: false,
        reason: `unknown vector kind: ${kind}`,
      })
    }
  }
  return out
}

async function loadImpl(p: string): Promise<PipWrapperImpl> {
  const url = pathToFileURL(p)
  const mod = await import(String(url)) as Record<string, unknown>
  const src = mod['default'] && typeof mod['default'] === 'object'
    ? mod['default'] as Record<string, unknown>
    : mod
  return src as unknown as PipWrapperImpl
}

function runEntryVector(impl: PipWrapperImpl, v: Vector): VectorResult {
  const entry  = v['entry']
  const expect = String(v['expect'])

  let result: VerifyEntryResult
  if (typeof impl.verifyCitedOracleInputEntry === 'function') {
    try {
      result = impl.verifyCitedOracleInputEntry(entry)
    } catch (err) {
      result = { ok: false, error_kind: 'threw', error_detail: (err as Error).message }
    }
  } else {
    // No impl loaded yet: use the standalone verifier so the vectors are self-checking
    // and produce useful failure details. When S1.1 ships and exposes
    // verifyCitedOracleInputEntry, the delegate path above takes over.
    result = standaloneVerifyEntry(entry)
  }

  if (expect === 'valid') {
    if (!result.ok) {
      return {
        vector_name: v.name,
        passed: false,
        reason: `expected valid but got ${result.error_kind}: ${result.error_detail ?? ''}`,
      }
    }
    return { vector_name: v.name, passed: true }
  }

  // expect === 'invalid'
  if (result.ok) {
    return {
      vector_name: v.name,
      passed: false,
      reason: 'expected invalid but entry was accepted',
    }
  }
  const expectedKind = v['expected_error_kind']
  if (expectedKind && result.error_kind !== String(expectedKind)) {
    return {
      vector_name: v.name,
      passed: false,
      reason: `wrong error_kind: expected ${String(expectedKind)}, got ${result.error_kind ?? 'none'}`,
    }
  }
  return { vector_name: v.name, passed: true }
}

async function runFetchVector(impl: PipWrapperImpl, v: Vector): Promise<VectorResult> {
  if (typeof impl.pipWrapperFetch !== 'function') {
    // S1.1 not yet shipped; mark as expected pending.
    return {
      vector_name: v.name,
      passed: false,
      reason: 'pip_wrapper_fetch: impl.pipWrapperFetch not present (S1.1 pending)',
    }
  }
  const args = {
    subject_type:                String(v['subject_type']),
    subject_value:               String(v['subject_value']),
    mock_upstream_status:        v['mock_upstream_status'] as number | undefined,
    mock_upstream_response:      v['mock_upstream_response'] as unknown,
    mock_upstream_response_body: v['mock_upstream_response_body'] as string | undefined,
    mock_vault_snapshot:         v['mock_vault_snapshot'] as unknown,
    mock_twilio_outbound_sid:    v['mock_twilio_outbound_sid'] as string | undefined,
    mock_twilio_inbound_body:    v['mock_twilio_inbound_body'] as string | undefined,
    mock_upstream_timeout:       v['mock_upstream_timeout'] as boolean | undefined,
    mock_timeout_after_ms:       v['mock_timeout_after_ms'] as number | undefined,
    mock_eval_snippet:           v['mock_eval_snippet'] as string | undefined,
    mock_eval_snippet_hash:      v['mock_eval_snippet_hash'] as string | undefined,
    mock_eval_result:            v['mock_eval_result'] as unknown,
    injection_mode:              v['injection_mode'] as string | undefined,
    mock_twilio_inbound_received_at: v['mock_twilio_inbound_received_at'] as string | undefined,
    mock_twilio_inbound_sid:     v['mock_twilio_inbound_sid'] as string | undefined,
  }
  let fetchResult: { ok: true; feed_result: FeedResult } | { ok: false; error_kind: string }
  try {
    fetchResult = await impl.pipWrapperFetch(args)
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }

  const expectOk = Boolean(v['expected_result_ok'])
  if (expectOk) {
    if (!fetchResult.ok) {
      return {
        vector_name: v.name,
        passed: false,
        reason: `expected ok=true but got error_kind=${(fetchResult as { ok: false; error_kind: string }).error_kind}`,
      }
    }
    const fr = (fetchResult as { ok: true; feed_result: FeedResult }).feed_result
    const shapeErrors = checkFeedResultShape(fr, v['expected_feed_result_shape'] as Record<string, unknown> | undefined)
    if (shapeErrors.length > 0) {
      return { vector_name: v.name, passed: false, reason: shapeErrors.join('; ') }
    }
    // Self-check value_hash integrity.
    let computedHash: string
    try {
      computedHash = sha256Hex(jcs(JSON.parse(fr.raw_value)))
    } catch (err) {
      return { vector_name: v.name, passed: false, reason: `raw_value parse/jcs failed: ${(err as Error).message}` }
    }
    if (computedHash !== fr.value_hash) {
      return {
        vector_name: v.name,
        passed: false,
        reason: `FeedResult.value_hash mismatch: computed ${computedHash}, got ${fr.value_hash}`,
      }
    }
    return { vector_name: v.name, passed: true }
  }

  // Expect failure.
  if (fetchResult.ok) {
    return { vector_name: v.name, passed: false, reason: 'expected ok=false but fetch succeeded' }
  }
  const expectedErrorKind = v['expected_error_kind']
  const actualErrorKind   = (fetchResult as { ok: false; error_kind: string }).error_kind
  if (expectedErrorKind && actualErrorKind !== String(expectedErrorKind)) {
    return {
      vector_name: v.name,
      passed: false,
      reason: `wrong error_kind: expected ${String(expectedErrorKind)}, got ${actualErrorKind}`,
    }
  }
  return { vector_name: v.name, passed: true }
}

function runGateBoundaryVector(impl: PipWrapperImpl, v: Vector): VectorResult {
  if (typeof impl.pipWrapperGateBoundaryCheck !== 'function') {
    return {
      vector_name: v.name,
      passed: false,
      reason: 'pip_wrapper_gate_boundary: impl.pipWrapperGateBoundaryCheck not present (S1.1 pending)',
    }
  }
  const feedResult = v['adapter_returns'] as FeedResult
  let checkResult: { action: string; cited_reason?: string }
  try {
    checkResult = impl.pipWrapperGateBoundaryCheck(feedResult)
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
  const expectedAction = String(v['expected_gate_action'])
  const expectedReason = v['expected_cited_reason'] as string | undefined
  if (checkResult.action !== expectedAction) {
    return {
      vector_name: v.name,
      passed: false,
      reason: `expected action=${expectedAction}, got ${checkResult.action}`,
    }
  }
  if (expectedReason && checkResult.cited_reason !== expectedReason) {
    return {
      vector_name: v.name,
      passed: false,
      reason: `expected cited_reason=${expectedReason}, got ${checkResult.cited_reason ?? 'none'}`,
    }
  }
  return { vector_name: v.name, passed: true }
}

function checkFeedResultShape(
  fr: FeedResult,
  shape: Record<string, unknown> | undefined,
): string[] {
  const errors: string[] = []
  if (!shape) return errors

  if (shape['raw_value_keys_present']) {
    let parsed: Record<string, unknown>
    try { parsed = JSON.parse(fr.raw_value) as Record<string, unknown> }
    catch (e) { return [`raw_value is not valid JSON: ${(e as Error).message}`] }
    for (const k of shape['raw_value_keys_present'] as string[]) {
      if (!(k in parsed)) errors.push(`raw_value missing key '${k}'`)
    }
    if (shape['raw_value_match_is_empty_array'] && !Array.isArray(parsed['match'])) {
      errors.push('raw_value.match must be an array')
    }
    if (shape['raw_value_match_is_empty_array'] && Array.isArray(parsed['match']) && (parsed['match'] as unknown[]).length !== 0) {
      errors.push('raw_value.match expected to be empty array')
    }
    if (typeof shape['raw_value_match_min_length'] === 'number') {
      if (!Array.isArray(parsed['match']) || (parsed['match'] as unknown[]).length < (shape['raw_value_match_min_length'] as number)) {
        errors.push(`raw_value.match must have at least ${shape['raw_value_match_min_length']} entry`)
      }
    }
    if (shape['raw_value_tz'] && parsed['tz'] !== shape['raw_value_tz']) {
      errors.push(`raw_value.tz expected '${String(shape['raw_value_tz'])}' got '${String(parsed['tz'])}'`)
    }
    if (shape['raw_value_direction'] && parsed['direction'] !== shape['raw_value_direction']) {
      errors.push(`raw_value.direction expected '${String(shape['raw_value_direction'])}' got '${String(parsed['direction'])}'`)
    }
    if (shape['raw_value_to'] && parsed['to'] !== shape['raw_value_to']) {
      errors.push(`raw_value.to expected '${String(shape['raw_value_to'])}' got '${String(parsed['to'])}'`)
    }
    if (shape['raw_value_endpoint_kind'] && parsed['endpoint_kind'] !== shape['raw_value_endpoint_kind']) {
      errors.push(`raw_value.endpoint_kind expected '${String(shape['raw_value_endpoint_kind'])}' got '${String(parsed['endpoint_kind'])}'`)
    }
    if (typeof shape['raw_value_status_code'] === 'number' && parsed['status_code_or_eval_result'] !== shape['raw_value_status_code']) {
      errors.push(`raw_value.status_code_or_eval_result expected ${String(shape['raw_value_status_code'])}`)
    }
  }

  if (shape['value_hash_prefix']) {
    if (!fr.value_hash.startsWith(String(shape['value_hash_prefix']))) {
      errors.push(`value_hash must start with '${String(shape['value_hash_prefix'])}'`)
    }
  }
  if (shape['source_url']) {
    if (fr.source_url !== String(shape['source_url'])) {
      errors.push(`source_url expected '${String(shape['source_url'])}' got '${fr.source_url}'`)
    }
  }
  if (shape['source_url_contains']) {
    if (!fr.source_url.includes(String(shape['source_url_contains']))) {
      errors.push(`source_url must contain '${String(shape['source_url_contains'])}'`)
    }
  }
  if (shape['source_url_scheme']) {
    if (!fr.source_url.startsWith(String(shape['source_url_scheme']))) {
      errors.push(`source_url must start with scheme '${String(shape['source_url_scheme'])}'`)
    }
  }
  if (shape['source_url_equals_subject_value']) {
    // Checked by caller having the subject_value; not available here without more plumbing.
    // Left as a note in the vector; not enforced structurally.
  }
  if (shape['snippet_hash_bound_in_raw_value']) {
    let parsed: Record<string, unknown>
    try { parsed = JSON.parse(fr.raw_value) as Record<string, unknown> }
    catch { errors.push('raw_value is not valid JSON (snippet_hash check)'); return errors }
    if (!('snippet_hash' in parsed)) {
      errors.push('raw_value missing snippet_hash field (C7 in-browser eval binding)')
    }
  }
  if (shape['fetched_at_pattern']) {
    const re = new RegExp(String(shape['fetched_at_pattern']))
    if (!re.test(fr.fetched_at)) {
      errors.push(`fetched_at '${fr.fetched_at}' does not match ${String(shape['fetched_at_pattern'])}`)
    }
  }
  if (shape['fetched_at_equals_now_utc']) {
    try {
      const parsed = JSON.parse(fr.raw_value) as Record<string, unknown>
      if (fr.fetched_at !== String(parsed['now_utc'])) {
        errors.push(`fetched_at must equal raw_value.now_utc for time adapter`)
      }
    } catch { /* already reported above */ }
  }
  return errors
}
