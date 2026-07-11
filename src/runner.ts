// runner.ts - orchestrates loading + iteration + reporting per protocol.
//
// Re-exports badge.ts so `import { computeTierResult, renderBadgeSvg } from
// '@synoi/conformance'` works from the package's main entry without a
// separate subpath.

import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Protocol, Reporter, RunReport, Vector, VectorResult, VectorStatus } from './types.js'

/**
 * Normalize the status field on a VectorResult.
 * Protocol files that predate the status field omit it; derive from `passed`.
 * Only wasm-shell.ts sets 'not-executable' explicitly.
 * 'stub' is passed through explicitly; it is never derived from `passed`.
 */
function normalizeStatus(r: VectorResult): VectorStatus {
  if (r.status === 'not-executable') return 'not-executable'
  if (r.status === 'stub')           return 'stub'
  if (r.status === 'pass' || r.status === 'fail') return r.status
  return r.passed ? 'pass' : 'fail'
}

/**
 * Protocols that are entirely stub until their reference impl ships real crypto receipts.
 * When a protocol appears in this list, every result is forced to status='stub' and the
 * protocol_status is set to 'stub', excluding it from the conformance badge entirely.
 *
 * Remove a protocol from this list only when it ships DSSE-signed receipts with hybrid
 * (ed25519 AND ml-dsa-65) verify meeting the same bar as the SRAID verifyReceiptV2.
 */
const STUB_PROTOCOLS: ReadonlySet<Protocol> = new Set<Protocol>(['inference-broker'])

// ESM-friendly __dirname equivalent.
const __filename = fileURLToPath(import.meta.url)
const __dirname  = dirname(__filename)

import { runSraidVectors    } from './protocols/sraid.js'
import { runGapVectors      } from './protocols/gap.js'
import { runResolverVectors } from './protocols/oid-resolver.js'
import { runInferenceVectors } from './protocols/inference-broker.js'
import { runCitedOracleInputsVectors } from './protocols/cited-oracle-inputs.js'
import { runWasmShellVectors } from './protocols/wasm-shell.js'

export interface RunnerInput {
  protocol:      Protocol
  /** Path to a JS module exporting the candidate implementation (SRAID + GAP). */
  implPath?:     string
  /** URL of a running OID Resolver to test. */
  resolverUrl?:  string
  /** Optional Bearer token for the Resolver's announce/revoke routes. */
  resolverAuth?: string
  /** Where to find the vector packs. Defaults to package's own vectors dir. */
  vectorsDir?:   string
  reporter:      Reporter
}

export async function runProtocol(input: RunnerInput): Promise<RunReport> {
  const dir = input.vectorsDir ?? defaultVectorsDir(input.protocol)
  const vectors = loadVectors(dir)
  const results: VectorResult[] = []

  switch (input.protocol) {
    case 'sraid':
      if (!input.implPath) throw new Error('SRAID conformance requires --impl=<path>')
      results.push(...await runSraidVectors(input.implPath, vectors))
      break
    case 'gap':
      if (!input.implPath) throw new Error('GAP conformance requires --impl=<path>')
      results.push(...await runGapVectors(input.implPath, vectors))
      break
    case 'oid-resolver':
      if (!input.resolverUrl) throw new Error('OID Resolver conformance requires --url=<resolver-url>')
      results.push(...await runResolverVectors({
        url: input.resolverUrl, auth: input.resolverAuth, vectors,
      }))
      break
    case 'inference-broker':
      if (!input.implPath) throw new Error('Inference Broker conformance requires --impl=<path>')
      results.push(...await runInferenceVectors(input.implPath, vectors))
      break
    case 'cited-oracle-inputs':
      // implPath is optional: vectors run in standalone mode (no impl loaded)
      // until S1.1 ships an implementation. All vectors will fail as expected.
      results.push(...await runCitedOracleInputsVectors(input.implPath, vectors))
      break
    case 'wasm-shell':
      // No implPath needed: canonical-parity and mldsa-hybrid-interop use @synoi/sraid
      // directly. gate-consult-rebind uses verifyAttestation from @synoi/sraid.
      // b1/b2 fixtures shell to the Wasmtime Rust harness binary when available;
      // they report NOT-EXECUTABLE-IN-RUNNER when the binary is absent.
      results.push(...await runWasmShellVectors(dir, vectors))
      break
  }

  // Normalize status on every result so reporters and tallies see a consistent field.
  for (const r of results) {
    r.status = normalizeStatus(r)
  }

  // If the entire protocol is in the stub list, force every result to status='stub'.
  // This is the honest-by-construction gate: stub protocols never contribute a 'pass'
  // to the badge regardless of what the per-vector runner returned.
  const isStubProtocol = STUB_PROTOCOLS.has(input.protocol)
  if (isStubProtocol) {
    for (const r of results) {
      r.status = 'stub'
      r.passed = false
    }
  }

  for (const r of results) input.reporter.onVector(input.protocol, r)

  const passed        = results.filter(r => r.status === 'pass').length
  const notExecutable = results.filter(r => r.status === 'not-executable')
  const failures      = results.filter(r => r.status === 'fail')
  const stubs         = results.filter(r => r.status === 'stub')
  const report: RunReport = {
    protocol:        input.protocol,
    protocol_status: isStubProtocol ? 'stub' : 'conformant',
    vectors_run:     results.length,
    passed,
    failed:          failures.length,
    not_executable:  notExecutable.length,
    stubbed:         stubs.length,
    failures,
    not_executables: notExecutable,
    stubs,
  }
  input.reporter.onProtocolDone(report)
  return report
}

function loadVectors(dir: string): Vector[] {
  if (!existsSync(dir)) return []
  const out: Vector[] = []
  for (const f of readdirSync(dir)) {
    if (!f.endsWith('.json')) continue
    if (f.startsWith('_')) continue       // generator helpers skipped
    const raw = readFileSync(join(dir, f), 'utf8')
    const parsed = JSON.parse(raw) as unknown
    if (Array.isArray(parsed)) {
      for (const v of parsed) {
        if (typeof v === 'object' && v !== null) out.push({ ...(v as Vector), _source: f })
      }
    } else if (typeof parsed === 'object' && parsed !== null && Array.isArray((parsed as { vectors?: unknown[] }).vectors)) {
      for (const v of (parsed as { vectors: unknown[] }).vectors) {
        if (typeof v === 'object' && v !== null) out.push({ ...(v as Vector), _source: f })
      }
    }
  }
  return out
}

function defaultVectorsDir(p: Protocol): string {
  // Walk up from this file: dist/runner.js → ../vectors/<protocol>/  OR
  //                         src/runner.ts  → ../vectors/<protocol>/
  // import.meta.url isn't usable in CJS contexts, so we derive from process.cwd + package layout.
  const candidates = [
    join(process.cwd(), 'vectors', p),
    join(process.cwd(), '..', 'vectors', p),
    join(__dirname, '..', '..', 'vectors', p),
  ]
  for (const c of candidates) if (existsSync(c)) return c
  return candidates[0] ?? join(process.cwd(), 'vectors', p)
}

export {
  TIER_PROTOCOLS,
  computeTier,
  computeTierResult,
  renderBadgeSvg,
  buildBadgeSvg,
  validateManifest,
  buildProjectEntry,
  type BadgeTier,
  type TierResult,
  type ConformanceManifest,
  type ConformantProjectEntry,
} from './badge.js'
