// types.ts - runner + vector + report types.

export type Protocol = 'sraid' | 'gap' | 'oid-resolver' | 'inference-broker' | 'cited-oracle-inputs' | 'wasm-shell'

/** One conformance assertion. Shape depends on the protocol. */
export interface Vector {
  name:   string
  /** Free-form payload - interpreted by the per-protocol runner. */
  [k: string]: unknown
}

export interface VectorPack {
  protocol: Protocol
  /** File the vectors were loaded from (for reporting). */
  source:   string
  vectors:  Vector[]
}

/**
 * Execution status of a single vector.
 *   'pass'           -- runner executed the vector and the implementation agreed.
 *   'fail'           -- runner executed the vector and the implementation disagreed (genuine failure).
 *   'not-executable' -- runner cannot execute this vector in the current environment
 *                       (missing binary, cargo-test-backed, TS-test-backed, etc.).
 *                       NOT counted in `failed`; counted in its own `not_executable` bucket.
 *   'stub'           -- the protocol has not yet shipped real crypto signing; the vector
 *                       executed but its result carries no cryptographic proof.
 *                       NEVER counted in `passed` or `failed`; counted in `stubbed` only.
 *                       Stub protocols are excluded from the conformance badge entirely.
 *
 * Design invariant (enforced in runner.ts):
 *   stub is never passed and never failed; a stub protocol's vectors are excluded
 *   from badge.vectors_passed and badge.vectors_total. This is the honest-by-construction
 *   guarantee: the badge must derive only from conformant-protocol vectors.
 *
 * Back-compat: `passed` is kept as a derived convenience field.
 *   passed === (status === 'pass')
 * New code should read `status` directly.
 */
export type VectorStatus = 'pass' | 'fail' | 'not-executable' | 'stub'

export interface VectorResult {
  vector_name: string
  /** Derived convenience field. true iff status === 'pass'. */
  passed:      boolean
  /**
   * Explicit execution status. Optional at construction; the runner normalizes it via
   * normalizeStatus() before counting. Protocol files that do not set status explicitly
   * get 'pass' or 'fail' derived from `passed`. Only wasm-shell.ts sets 'not-executable'
   * explicitly for vectors that cannot be executed in the current environment.
   */
  status?:     VectorStatus
  reason?:     string
  expected?:   unknown
  actual?:     unknown
}

/**
 * When protocol_status is 'stub', every vector in this report has status='stub'
 * and the protocol is excluded from the conformance badge entirely.
 * When omitted (or 'conformant'), the protocol's vectors count toward the badge.
 */
export type ProtocolStatus = 'conformant' | 'stub'

export interface RunReport {
  protocol:        Protocol
  /** 'conformant' (default) or 'stub'. Stub protocols are excluded from the badge. */
  protocol_status: ProtocolStatus
  vectors_run:     number
  passed:          number
  failed:          number
  not_executable:  number
  /** Vectors with status 'stub' - executed but not cryptographically proven. */
  stubbed:         number
  failures:        VectorResult[]
  not_executables: VectorResult[]
  stubs:           VectorResult[]
}

/**
 * Machine-readable badge surface. Derived from conformant-protocol RunReports only.
 * Stub protocols contribute 0 to both numerator and denominator.
 */
export interface ConformanceBadge {
  conformant_protocols: Protocol[]
  stub_protocols:       Protocol[]
  vectors_passed:       number
  vectors_total:        number
}

/** Reporters take a stream of results + a final report and emit output. */
export interface Reporter {
  onVector(protocol: Protocol, result: VectorResult): void
  onProtocolDone(report: RunReport): void
  /** Final summary across all protocols. Returns process exit code. */
  finish(reports: RunReport[]): number
}
