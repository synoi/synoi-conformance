// protocols/gap.ts -- GAP conformance vectors -> candidate impl.
// ADR_007: renamed from protocols/agp.ts; protocol ID is now 'gap'.

import type { Vector, VectorResult } from '../types.js'

type ValidatorFn = (x: unknown) => { ok: boolean; errors: string[] }
type OidFn = (body: unknown) => string
type GapImpl = Record<string, ValidatorFn | OidFn | undefined>

// decision_receipt is a valid GAP object type (validated here like any other kind) but is
// intentionally excluded from the OID Resolver's revocation scope: @synoi/oid-resolver's
// GET /v1/revocations ALLOWED_KINDS (src/routes/revocations.ts) does not include
// decision_receipt, so `target_kind=decision_receipt` 400s there. A decision receipt is an
// immutable audit record of a decision that already happened; it cannot be revoked, only the
// grant/declaration/workflow that authorized it can be. GAP validation (this file) and
// resolver revocability (separate repo, separate allowlist) are deliberately different axes.
const VALIDATOR_MAP: Record<string, string> = {
  capability_declaration: 'validateCapabilityDeclaration',
  capability_grant:       'validateCapabilityGrant',
  capability_invocation:  'validateCapabilityInvocation',
  workflow_definition:    'validateWorkflowDefinition',
  workflow_instance:      'validateWorkflowInstance',
  decision_receipt:       'validateGapDecisionReceipt',
  revocation_event:       'validateRevocationEvent',
  perimeter_declaration:  'validatePerimeterDeclaration',
}

export async function runGapVectors(implPath: string, vectors: Vector[]): Promise<VectorResult[]> {
  const impl = await loadImpl(implPath)
  const out: VectorResult[] = []

  for (const v of vectors) {
    if (v['kind'] === 'validate') out.push(runValidateVector(impl, v))
    else if (v['kind'] === 'oid') out.push(runOidVector(impl, v))
    else {
      out.push({
        vector_name: v.name, passed: false,
        reason: `unknown vector kind: ${String(v['kind'])}`,
      })
    }
  }
  return out
}

async function loadImpl(p: string): Promise<GapImpl> {
  const mod = await import(pathToFileUrl(p)) as Record<string, unknown>
  const src = mod['default'] && typeof mod['default'] === 'object'
    ? mod['default'] as Record<string, unknown>
    : mod
  return src as GapImpl
}

function runValidateVector(impl: GapImpl, v: Vector): VectorResult {
  const targetKind = String(v['target'])
  const validatorName = VALIDATOR_MAP[targetKind]
  if (!validatorName) {
    return { vector_name: v.name, passed: false, reason: `unknown target: ${targetKind}` }
  }
  const fn = impl[validatorName] as ValidatorFn | undefined
  if (typeof fn !== 'function') {
    return { vector_name: v.name, passed: false, reason: `impl missing ${validatorName}` }
  }
  let result: { ok: boolean; errors: string[] }
  try { result = fn(v['input']) }
  catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
  const expectedOk = v['expected_ok'] === true
  if (result.ok !== expectedOk) {
    return {
      vector_name: v.name, passed: false,
      reason: `expected ok=${expectedOk}, got ${result.ok} (${result.errors.join(',')})`,
    }
  }
  // When the vector specifies expected_errors_include, every entry must appear
  // as a substring of the actual errors.
  const expectInclude = v['expected_errors_include']
  if (Array.isArray(expectInclude)) {
    const joined = result.errors.join('|')
    for (const want of expectInclude) {
      if (!joined.includes(String(want))) {
        return {
          vector_name: v.name, passed: false,
          reason: `expected errors to include "${String(want)}"`,
          expected: expectInclude, actual: result.errors,
        }
      }
    }
  }
  return { vector_name: v.name, passed: true }
}

function runOidVector(impl: GapImpl, v: Vector): VectorResult {
  const oidFn = impl['computeGapOid'] as OidFn | undefined
  if (typeof oidFn !== 'function') {
    return { vector_name: v.name, passed: false, reason: 'impl missing computeGapOid' }
  }
  const expected = String(v['expected_oid'])
  let actual: string
  try { actual = oidFn(v['input']) }
  catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
  if (actual !== expected) {
    return { vector_name: v.name, passed: false, reason: 'oid mismatch', expected, actual }
  }
  return { vector_name: v.name, passed: true }
}

function pathToFileUrl(p: string): string {
  if (p.startsWith('file://')) return p
  if (!p.includes('/') && !p.includes('\\')) return p
  const abs = p.replace(/\\/g, '/')
  return abs.startsWith('/') ? `file://${abs}` : `file:///${abs}`
}
