// protocols/inference-broker.ts - Inference Broker (@synoi/broker) conformance.
//
// Validates the candidate implementation against the published vector set.
// The reference impl is @synoi/broker; any compatible package that exports
// the same surface passes.

import type { Vector, VectorResult } from '../types.js'

interface BrokerImpl {
  scoreComplexity(
    messages: { role: string; content: string }[],
    has_tools: boolean,
    pts_tier:  number,
  ): { tier: string; score: number; reasons: string[] }

  arbitrageModel(
    requested_model: string,
    complexity:       { tier: string; score: number; reasons: string[]; token_est: number },
    has_tools:        boolean,
    opts:             Record<string, unknown>,
  ): {
    model:          string
    provider:       string
    original_model: string
    arbitraged:     boolean
    reason:         string
    estimated_cost: number
    complexity:     unknown
  }

  buildBrokerReceipt(
    inp:    Record<string, unknown>,
    signer?: unknown,
  ): Promise<{
    receipt_id:    string
    tenant_id:     string
    verb:          string
    model:         string
    provider:      string
    cache_decision: string
    cost_usd:      number
    cost_source:   string
    recorded_at:   string
  }>

  NULL_SINK: { write(r: unknown): Promise<void> }

  CoalescenceMap: new <T>() => {
    getOrCreate(key: string, factory: () => Promise<T>): { promise: Promise<T>; coalesced: boolean }
    size: number
  }

  MODEL_REGISTRY: readonly {
    model:             string
    provider:          string
    cost_per_1k_input: number
    min_tier:          string
    supports_tools:    boolean
    context_window:    number
  }[]

  tierGte(a: string, b: string): boolean
}

export async function runInferenceVectors(
  implPath: string,
  vectors:  Vector[],
): Promise<VectorResult[]> {
  let impl: BrokerImpl
  try {
    impl = await loadImpl(implPath)
  } catch (err) {
    return vectors.map(v => ({
      vector_name: v.name,
      passed:      false,
      reason:      `impl load failed: ${(err as Error).message}`,
    }))
  }

  const out: VectorResult[] = []
  for (const v of vectors) {
    const kind = String(v['kind'])
    try {
      if (kind === 'complexity')        out.push(await runComplexityVector(impl, v))
      else if (kind === 'arbitrage')    out.push(await runArbitrageVector(impl, v))
      else if (kind === 'receipt')      out.push(await runReceiptVector(impl, v))
      else if (kind === 'receipt_sink') out.push(await runReceiptSinkVector(impl, v))
      else if (kind === 'coalesce')     out.push(await runCoalesceVector(impl, v))
      else if (kind === 'registry')     out.push(runRegistryVector(impl, v))
      else out.push({ vector_name: v.name, passed: false, reason: `unknown kind: ${kind}` })
    } catch (err) {
      out.push({ vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` })
    }
  }
  return out
}

// ── impl loader ───────────────────────────────────────────────────────────────

async function loadImpl(p: string): Promise<BrokerImpl> {
  const url = pathToFileUrl(p)
  const mod = await import(url) as Record<string, unknown>
  const src = mod['default'] && typeof mod['default'] === 'object'
    ? mod['default'] as Record<string, unknown>
    : mod
  const required = [
    'scoreComplexity', 'arbitrageModel', 'buildBrokerReceipt',
    'NULL_SINK', 'CoalescenceMap', 'MODEL_REGISTRY', 'tierGte',
  ] as const
  for (const k of required) {
    if (src[k] === undefined) throw new Error(`broker impl ${p} missing export "${k}"`)
  }
  return src as unknown as BrokerImpl
}

function pathToFileUrl(p: string): string {
  if (p.startsWith('file://')) return p
  const normalized = p.replace(/\\/g, '/')
  return normalized.startsWith('/') ? `file://${normalized}` : `file:///${normalized}`
}

// ── vector runners ─────────────────────────────────────────────────────────

async function runComplexityVector(impl: BrokerImpl, v: Vector): Promise<VectorResult> {
  const inp = v['input'] as {
    messages:   { role: string; content: string }[]
    has_tools:  boolean
    pts_tier:   number
  }
  const expected = v['expected'] as {
    tier:             string
    score_range:      [number, number]
    reasons_include?: string[]
  }

  const result = impl.scoreComplexity(inp.messages, inp.has_tools, inp.pts_tier)

  if (result.tier !== expected.tier) {
    return { vector_name: v.name, passed: false, reason: `tier: got ${result.tier}, want ${expected.tier}` }
  }
  const [lo, hi] = expected.score_range
  if (result.score < lo || result.score > hi) {
    return { vector_name: v.name, passed: false, reason: `score ${result.score} not in [${lo}, ${hi}]` }
  }
  if (expected.reasons_include) {
    for (const substr of expected.reasons_include) {
      if (!result.reasons.some(r => r.includes(substr))) {
        return { vector_name: v.name, passed: false, reason: `reason "${substr}" not in ${JSON.stringify(result.reasons)}` }
      }
    }
  }
  return { vector_name: v.name, passed: true, reason: `tier=${result.tier} score=${result.score}` }
}

async function runArbitrageVector(impl: BrokerImpl, v: Vector): Promise<VectorResult> {
  const inp = v['input'] as {
    requested_model:  string
    complexity_tier:  string
    complexity_score: number
    has_tools:        boolean
    opts:             Record<string, unknown>
  }
  const expected = v['expected'] as {
    arbitraged?:           boolean
    model?:                string
    cheaper_than_gpt4o?:   boolean
    model_supports_tools?: boolean
    cost_per_1k_lte?:      number
  }

  const complexity = {
    tier: inp.complexity_tier, score: inp.complexity_score,
    reasons: [], token_est: 100,
  }
  const result = impl.arbitrageModel(inp.requested_model, complexity, inp.has_tools, inp.opts)

  if (expected.arbitraged !== undefined && result.arbitraged !== expected.arbitraged) {
    return { vector_name: v.name, passed: false, reason: `arbitraged: got ${result.arbitraged}, want ${expected.arbitraged}` }
  }
  if (expected.model !== undefined && result.model !== expected.model) {
    return { vector_name: v.name, passed: false, reason: `model: got ${result.model}, want ${expected.model}` }
  }
  if (expected.cheaper_than_gpt4o) {
    const GPT4O_COST = 0.0025
    const chosen = impl.MODEL_REGISTRY.find(m => m.model === result.model)
    if (chosen && chosen.cost_per_1k_input >= GPT4O_COST) {
      return { vector_name: v.name, passed: false, reason: `${result.model} ($${chosen.cost_per_1k_input}/1k) not cheaper than gpt-4o ($${GPT4O_COST}/1k)` }
    }
  }
  if (expected.model_supports_tools) {
    const spec = impl.MODEL_REGISTRY.find(m => m.model === result.model)
    if (spec && !spec.supports_tools) {
      return { vector_name: v.name, passed: false, reason: `${result.model} does not support tools` }
    }
  }
  if (expected.cost_per_1k_lte !== undefined) {
    const spec = impl.MODEL_REGISTRY.find(m => m.model === result.model)
    if (spec && spec.cost_per_1k_input > expected.cost_per_1k_lte) {
      return { vector_name: v.name, passed: false, reason: `${result.model} cost ${spec.cost_per_1k_input} > ceiling ${expected.cost_per_1k_lte}` }
    }
  }
  return { vector_name: v.name, passed: true, reason: `model=${result.model} arbitraged=${result.arbitraged}` }
}

async function runReceiptVector(impl: BrokerImpl, v: Vector): Promise<VectorResult> {
  const inp = v['input'] as Record<string, unknown>
  const expected = v['expected'] as {
    receipt_id_is_hex64?: boolean
    deterministic?:       boolean
  }

  const nowStr = String(inp['now'] ?? new Date().toISOString())
  const base = { ...inp, now: () => nowStr }

  const r1 = await impl.buildBrokerReceipt(base)
  if (expected.receipt_id_is_hex64 && !/^[0-9a-f]{64}$/.test(r1.receipt_id)) {
    return { vector_name: v.name, passed: false, reason: `receipt_id not 64-char hex: ${r1.receipt_id.slice(0, 16)}…` }
  }
  if (expected.deterministic) {
    const r2 = await impl.buildBrokerReceipt(base)
    if (r1.receipt_id !== r2.receipt_id) {
      return { vector_name: v.name, passed: false, reason: 'receipt_id not deterministic across two identical calls' }
    }
  }
  return { vector_name: v.name, passed: true, reason: `receipt_id=${r1.receipt_id.slice(0, 12)}…` }
}

async function runReceiptSinkVector(impl: BrokerImpl, v: Vector): Promise<VectorResult> {
  const inp = v['input'] as Record<string, unknown>
  const expected = v['expected'] as { no_throw: boolean }

  const receipt = await impl.buildBrokerReceipt(inp)
  let threw = false
  try { await impl.NULL_SINK.write(receipt) } catch { threw = true }

  if (expected.no_throw && threw) {
    return { vector_name: v.name, passed: false, reason: 'NULL_SINK.write threw' }
  }
  return { vector_name: v.name, passed: true, reason: 'NULL_SINK accepted receipt' }
}

async function runCoalesceVector(impl: BrokerImpl, v: Vector): Promise<VectorResult> {
  const inp      = v['input'] as { key: string; call: 'first' | 'second' }
  const expected = v['expected'] as { coalesced: boolean }

  let resolveP!: () => void
  const pending = new Promise<string>(r => { resolveP = () => r('ok') })
  const map = new impl.CoalescenceMap<string>()

  let coalesced: boolean
  if (inp.call === 'first') {
    const r = map.getOrCreate(inp.key, () => pending)
    coalesced = r.coalesced
  } else {
    map.getOrCreate(inp.key, () => pending)
    const r2 = map.getOrCreate(inp.key, () => pending)
    coalesced = r2.coalesced
  }
  resolveP()

  if (coalesced !== expected.coalesced) {
    return { vector_name: v.name, passed: false, reason: `coalesced=${coalesced}, want ${expected.coalesced}` }
  }
  return { vector_name: v.name, passed: true, reason: `coalesced=${coalesced}` }
}

function runRegistryVector(impl: BrokerImpl, v: Vector): VectorResult {
  const expected = v['expected'] as Record<string, unknown>
  const reg      = impl.MODEL_REGISTRY
  const providers = new Set(reg.map(m => m.provider))

  if (expected['min_providers'] !== undefined && providers.size < Number(expected['min_providers'])) {
    return { vector_name: v.name, passed: false, reason: `${providers.size} providers, want ≥${expected['min_providers']}` }
  }
  if (expected['min_models'] !== undefined && reg.length < Number(expected['min_models'])) {
    return { vector_name: v.name, passed: false, reason: `${reg.length} models, want ≥${expected['min_models']}` }
  }
  if (expected['trivial_gte_trivial'] && !impl.tierGte('trivial', 'trivial')) {
    return { vector_name: v.name, passed: false, reason: 'tierGte(trivial, trivial) must be true' }
  }
  if (expected['simple_gte_trivial'] && !impl.tierGte('simple', 'trivial')) {
    return { vector_name: v.name, passed: false, reason: 'tierGte(simple, trivial) must be true' }
  }
  if (expected['expert_gte_complex'] && !impl.tierGte('expert', 'complex')) {
    return { vector_name: v.name, passed: false, reason: 'tierGte(expert, complex) must be true' }
  }
  if (expected['trivial_not_gte_simple'] && impl.tierGte('trivial', 'simple')) {
    return { vector_name: v.name, passed: false, reason: 'tierGte(trivial, simple) must be false' }
  }
  return { vector_name: v.name, passed: true, reason: `${reg.length} models, ${providers.size} providers` }
}
