// protocols/oid-resolver.ts - black-box HTTP conformance against a Resolver.

import type { Vector, VectorResult } from '../types.js'

interface ResolverInput {
  url:     string
  auth?:   string  // raw header value, e.g. "Bearer foo"
  vectors: Vector[]
}

interface Step {
  op:                   'GET' | 'POST'
  path:                 string
  body?:                Record<string, unknown>
  /** When set, send this Authorization header value. */
  auth?:                'default' | 'none' | string
  expected_status:      number
  /** Each key must appear in the response with the same value, OR the value
   *  may be the sentinel `<any>` meaning "field is present, any value". */
  expected_response?:   Record<string, unknown>
  /** When set, the response field at this dotted path must be truthy / equal. */
  assert?:              Array<{ path: string; equals?: unknown; truthy?: boolean }>
}

export async function runResolverVectors(input: ResolverInput): Promise<VectorResult[]> {
  const out: VectorResult[] = []
  const base = input.url.replace(/\/+$/, '')
  for (const v of input.vectors) {
    const steps = v['steps']
    if (!Array.isArray(steps)) {
      out.push({ vector_name: v.name, passed: false, reason: 'vector missing steps[]' })
      continue
    }
    let failure: { step: number; reason: string; expected?: unknown; actual?: unknown } | null = null
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i] as Step
      const r = await runStep(base, input.auth, step)
      if (!r.ok) { failure = { step: i, reason: r.reason, expected: r.expected, actual: r.actual }; break }
    }
    if (failure) {
      out.push({
        vector_name: v.name, passed: false,
        reason: `step ${failure.step}: ${failure.reason}`,
        ...(failure.expected !== undefined ? { expected: failure.expected } : {}),
        ...(failure.actual   !== undefined ? { actual:   failure.actual   } : {}),
      })
    } else {
      out.push({ vector_name: v.name, passed: true })
    }
  }
  return out
}

async function runStep(
  base: string, defaultAuth: string | undefined, step: Step,
): Promise<{ ok: true } | { ok: false; reason: string; expected?: unknown; actual?: unknown }> {
  const url = `${base}${step.path}`
  const headers: Record<string, string> = {}
  if (step.body !== undefined) headers['content-type'] = 'application/json'

  const authMode = step.auth ?? 'default'
  if (authMode === 'default' && defaultAuth) headers['authorization'] = defaultAuth
  else if (authMode === 'none')              { /* explicitly omit */ }
  else if (authMode !== 'default')           headers['authorization'] = String(authMode)

  let res: Response
  try {
    res = await fetch(url, {
      method: step.op,
      headers,
      body: step.body !== undefined ? JSON.stringify(step.body) : undefined,
    })
  } catch (err) {
    return { ok: false, reason: `fetch threw: ${(err as Error).message}` }
  }
  if (res.status !== step.expected_status) {
    const body = await res.text().catch(() => '')
    return {
      ok: false,
      reason: `expected status ${step.expected_status}, got ${res.status}`,
      actual: { status: res.status, body: body.slice(0, 200) },
    }
  }
  if (step.expected_response || step.assert) {
    const text = await res.text()
    let parsed: unknown
    try { parsed = text.length > 0 ? JSON.parse(text) : null } catch {
      return { ok: false, reason: 'response is not JSON', actual: text.slice(0, 200) }
    }
    if (step.expected_response) {
      for (const [k, want] of Object.entries(step.expected_response)) {
        const have = (parsed as Record<string, unknown> | null)?.[k]
        if (want === '<any>') {
          if (have === undefined) {
            return { ok: false, reason: `expected field "${k}" present`, actual: parsed }
          }
        } else if (!deepEqual(have, want)) {
          return { ok: false, reason: `field "${k}" mismatch`, expected: want, actual: have }
        }
      }
    }
    if (step.assert) {
      for (const a of step.assert) {
        const got = getDottedPath(parsed, a.path)
        if (a.equals !== undefined && !deepEqual(got, a.equals)) {
          return { ok: false, reason: `assert ${a.path} != expected`, expected: a.equals, actual: got }
        }
        if (a.truthy === true && !got) {
          return { ok: false, reason: `assert ${a.path} not truthy`, actual: got }
        }
      }
    }
  }
  return { ok: true }
}

function getDottedPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj
  for (const p of path.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[p]
  }
  return cur
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (a === null || b === null) return false
  if (typeof a !== typeof b) return false
  if (typeof a !== 'object') return false
  if (Array.isArray(a)) {
    if (!Array.isArray(b)) return false
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false
    return true
  }
  const ao = a as Record<string, unknown>
  const bo = b as Record<string, unknown>
  const ak = Object.keys(ao).sort()
  const bk = Object.keys(bo).sort()
  if (ak.length !== bk.length) return false
  for (let i = 0; i < ak.length; i++) {
    if (ak[i] !== bk[i]) return false
    if (!deepEqual(ao[ak[i]!], bo[bk[i]!])) return false
  }
  return true
}
