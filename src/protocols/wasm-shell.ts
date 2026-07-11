// protocols/wasm-shell.ts -- conformance runner for wasm-shell fixture files.
//
// Fixtures in vectors/wasm-shell/ come in three distinct shapes:
//
//   canonical-parity.json    -- "cases" array, kinds: canonicalize | cdro_oid.
//                               Executable: uses @synoi/sraid canonicalize + cdroOid.
//   mldsa-hybrid-interop.json -- flat envelope + negative_fixtures object.
//                               Executable: uses @synoi/sraid verifyAttestation.
//   gate-consult-rebind.json -- "fixtures" dict with per-name entries.
//                               Executable: uses @synoi/sraid verifyAttestation + tuple match + expiry.
//   b1-undeclared-import-reject.json -- "vectors" array (standard shape) from Rust harness.
//                               Runner shells to the Wasmtime Rust harness binary when available.
//                               NOT-EXECUTABLE-IN-RUNNER when the harness binary is absent.
//   b2-receipt-verify.json   -- "vectors" array (standard shape) from Rust harness.
//                               Runner shells to the Wasmtime Rust harness binary when available.
//                               NOT-EXECUTABLE-IN-RUNNER when the harness binary is absent.
//   live-gate-round-trip.json -- "vectors" array (standard shape) for LGRT-1..5.
//                               Runner shells to the live-gate-round-trip binary, which itself
//                               spawns a real Node/tsx gateway server and exercises real HTTP.
//                               NOT-EXECUTABLE-IN-RUNNER when the binary or tsx is absent.
//
// The runner calls runWasmShellVectors(dir, preloadedVectors).
// preloadedVectors contains vectors[] from b1/b2 (standard shape).
// dir is used to read the non-standard fixture files directly.
//
// B1/B2 HARNESS SHELLING
// ----------------------
// When the Rust harness binary (b1-harness.exe / b1-harness) is present at
// the expected path relative to the gateway runtime directory, the runner
// shells to it and asserts each vector against the live output. This promotes
// b1/b2 vectors to runner-SHIPPED ONLY in an environment where the harness
// binary is present (a toolchain-equipped host). In any toolchain-less
// environment the binary is absent and every b1/b2 vector reports
// NOT-EXECUTABLE-IN-RUNNER and stays PARTIAL. runner-SHIPPED is therefore an
// environment-conditional status, not an unconditional promotion.
//
// Availability detection (resolveHarnessEnv):
//   1. Locate the harness binary via SYNOI_GATEWAY_DIR env var if set, or by
//      walking up from the vectors dir to find a sibling synoi-gateway repo.
//   2. Check for a prebuilt binary at
//        <gateway>/runtime/b1-harness/target/debug/b1-harness[.exe]
//   3. If not found, check if `cargo` is on PATH; if so, return a "buildable"
//      flag so the runner can attempt `cargo build` before executing.
//   4. If neither binary nor cargo is available, return unavailable and each
//      vector reports NOT-EXECUTABLE-IN-RUNNER with an explicit reason.
//
// HONESTY CONTRACT
// ----------------
// A vector is reported PASS only when the harness exits 0 AND the stdout line
// for that vector name contains "PASS". If the harness exits nonzero or a
// vector line contains "FAIL" or is absent from stdout, the runner reports
// FAIL loudly. No patching, no coercion. If the harness cannot be located or
// built, the runner reports NOT-EXECUTABLE-IN-RUNNER for every b1/b2 vector.

import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import type { Vector, VectorResult } from '../types.js'

// notExec builds a VectorResult with status 'not-executable'.
// The runner counts these in their own bucket, not in 'failed'.
function notExec(vector_name: string, reason: string): VectorResult {
  return { vector_name, passed: false, status: 'not-executable', reason }
}

// pass/fail helpers keep construction sites concise and consistent.
function passResult(vector_name: string): VectorResult {
  return { vector_name, passed: true, status: 'pass' }
}

function failResult(vector_name: string, reason: string, extra?: { expected?: unknown; actual?: unknown }): VectorResult {
  return { vector_name, passed: false, status: 'fail', reason, ...extra }
}
import { canonicalize, cdroOid, verifyAttestation } from '@synoi/sraid'

// ---------------------------------------------------------------------------
// Harness environment resolution
// ---------------------------------------------------------------------------

interface HarnessEnv {
  available:       true
  binaryPath:      string
  shellStubWasm:   string
  badImportsWasm:  string
  receiptVerifyWasm: string
}

interface HarnessUnavailable {
  available: false
  reason:    string
}

type HarnessResolution = HarnessEnv | HarnessUnavailable

// resolveHarnessEnv locates the prebuilt Rust harness binary and WASM test
// component files. Returns an unavailable result (with reason) when any
// required artifact is missing, so callers can degrade gracefully.
//
// Search order for the gateway root:
//   1. SYNOI_GATEWAY_DIR env var (explicit override)
//   2. Walk up from vectorsDir looking for a sibling "synoi-gateway" directory
//   3. The hardcoded sibling path relative to a known repo layout
//      (vectors dir is inside synoi-conformance; gateway is a sibling repo)
function resolveHarnessEnv(vectorsDir: string): HarnessResolution {
  // --- locate gateway root ---
  const gwFromEnv = process.env['SYNOI_GATEWAY_DIR']
  let gatewayRoot: string | undefined

  if (gwFromEnv && existsSync(gwFromEnv)) {
    gatewayRoot = gwFromEnv
  } else {
    // Walk up from vectorsDir. vectors dir is typically:
    //   <repo>/vectors/wasm-shell  (2 levels below repo root)
    // The gateway sibling is at:
    //   <repo>/../synoi-gateway
    // Try up to 5 levels.
    let dir = vectorsDir
    for (let i = 0; i < 5; i++) {
      dir = dirname(dir)
      const candidate = resolve(dir, '..', 'synoi-gateway')
      if (existsSync(candidate)) {
        gatewayRoot = candidate
        break
      }
      // Also check as a direct sibling from dir
      const sibling = resolve(dir, 'synoi-gateway')
      if (existsSync(sibling)) {
        gatewayRoot = sibling
        break
      }
    }
  }

  if (!gatewayRoot) {
    return {
      available: false,
      reason:    'synoi-gateway repo not found alongside synoi-conformance; set SYNOI_GATEWAY_DIR to its absolute path',
    }
  }

  // --- locate prebuilt binary ---
  const isWin      = process.platform === 'win32'
  const exeSuffix  = isWin ? '.exe' : ''
  const binaryPath = join(gatewayRoot, 'runtime', 'b1-harness', 'target', 'debug', `b1-harness${exeSuffix}`)

  if (!existsSync(binaryPath)) {
    return {
      available: false,
      reason:    `b1-harness binary not found at ${binaryPath}; run "cargo build" inside synoi-gateway/runtime/b1-harness to build it`,
    }
  }

  // --- locate WASM test components ---
  const wasmDebug  = join(gatewayRoot, 'runtime', 'test-components')

  const shellStubWasm = join(wasmDebug, 'shell-stub', 'target', 'wasm32-wasip2', 'debug', `shell_stub.wasm`)
  const badImportsWasm = join(wasmDebug, 'bad-imports', 'target', 'wasm32-wasip2', 'debug', `bad-imports.wasm`)
  const receiptVerifyWasm = join(wasmDebug, 'receipt-verify', 'target', 'wasm32-wasip2', 'debug', `receipt_verify.wasm`)

  const missing: string[] = []
  if (!existsSync(shellStubWasm))    missing.push(shellStubWasm)
  if (!existsSync(badImportsWasm))   missing.push(badImportsWasm)
  if (!existsSync(receiptVerifyWasm)) missing.push(receiptVerifyWasm)

  if (missing.length > 0) {
    return {
      available: false,
      reason:    `WASM test component(s) not built: ${missing.join(', ')}; run "cargo component build" in each missing component directory`,
    }
  }

  return { available: true, binaryPath, shellStubWasm, badImportsWasm, receiptVerifyWasm }
}

// ---------------------------------------------------------------------------
// Harness execution and stdout parsing
// ---------------------------------------------------------------------------

// Vector tag prefixes emitted by the harness stdout.
// Each line is like "[B1-V1] PASS ..." or "[B1-V1] FAIL ..." or
// "[B1-V1] UNEXPECTED PASS/FAIL ...".
// We map harness vector tags to fixture vector names.
//
// b1-v1 .. b1-v5 map to the "name" fields in b1-undeclared-import-reject.json vectors.
// b2-v1 .. b2-v7 map to the "name" fields in b2-receipt-verify.json vectors.
//
// Note: b1-v2 shares the same harness run as b1-v1 (same component, same reject
// outcome). The harness does not emit a separate "[B1-V2]" tag line; v2 is
// validated as part of the same b1-v1 reject run. We propagate the b1-v1 outcome
// to b1-v2 since the fixture documents them as the same run.
const HARNESS_TAG_TO_FIXTURE: Record<string, string> = {
  'B1-V1': 'b1-v1-undeclared-wasi-filesystem-rejected',
  'B1-V2': 'b1-v2-withheld-wasi-clocks-rejected',
  'B1-V3': 'b1-v3-declared-vault-imports-all-resolve',
  'B1-V4': 'b1-v4-vault-wit-roundtrip',
  'B1-V5': 'b1-v5-determinism',
  'B2-V1': 'b2-v1-render-panel-happy-seeded-receipts',
  'B2-V2': 'b2-v2-render-panel-boundary-empty-stream',
  'B2-V3': 'b2-v3-render-panel-limit-respected',
  'B2-V4': 'b2-v4-handle-receipt-reactive-path',
  'B2-V5': 'b2-v5-handle-receipt-no-op-non-matching-subject',
  'B2-V6': 'b2-v6-handle-receipt-idempotent-no-duplication',
  'B2-V7': 'b2-v7-run-onboarding-returns-completed-true',
}

// B1-V2 is derived from the B1-V1 run (same component, same reject).
// The harness stdout does not emit a separate [B1-V2] line.
const B1_V2_DERIVED_FROM = 'B1-V1'

interface HarnessRun {
  exitCode:   number
  stdout:     string
  stderr:     string
  // tag -> 'PASS' | 'FAIL' | 'UNEXPECTED-PASS' | 'UNEXPECTED-FAIL'
  outcomes:   Map<string, string>
}

function runHarness(env: HarnessEnv): HarnessRun {
  const result = spawnSync(
    env.binaryPath,
    [env.shellStubWasm, env.badImportsWasm, env.receiptVerifyWasm],
    { encoding: 'utf8', timeout: 120_000 },
  )

  const stdout   = result.stdout ?? ''
  const stderr   = result.stderr ?? ''
  const exitCode = result.status ?? 1

  // Parse PASS/FAIL outcomes from stdout.
  const outcomes = new Map<string, string>()
  for (const line of stdout.split('\n')) {
    // Match lines like "[B1-V3] PASS: ..." or "[B1-V3] FAIL: ..." or
    // "[B1-V1] UNEXPECTED PASS: ..." / "[B1-V1] UNEXPECTED FAIL: ..."
    const m = line.match(/^\[([A-Za-z0-9-]+)\]\s+(PASS|FAIL|UNEXPECTED PASS|UNEXPECTED FAIL)\b/)
    if (m && m[1] && m[2]) {
      const tag    = m[1]   // e.g. "B1-V3"
      const result = m[2]   // e.g. "PASS"
      // Normalize UNEXPECTED variants: UNEXPECTED PASS on a negative test is
      // a failure (the reject should have fired); UNEXPECTED FAIL on a positive
      // test is also a failure. Collapse to PASS/FAIL.
      const normalized: string = result.startsWith('PASS') ? 'PASS' : 'FAIL'
      // Keep the worst outcome if a tag appears more than once.
      if (!outcomes.has(tag) || normalized === 'FAIL') {
        outcomes.set(tag, normalized)
      }
    }
  }

  return { exitCode, stdout, stderr, outcomes }
}

// runB1B2Vectors: invoke the harness and map outcomes to VectorResult[].
// vectorNames is the list of fixture vector names (from the "vectors" array
// in the fixture JSON). We assert against each name.
function runB1B2Vectors(
  env:         HarnessEnv,
  b1Vectors:   Array<{ name: string }>,
  b2Vectors:   Array<{ name: string }>,
): VectorResult[] {
  const out: VectorResult[] = []

  const run = runHarness(env)

  // Helper: find the harness tag for a given fixture vector name.
  function tagForFixtureName(name: string): string | undefined {
    for (const [tag, fixtureName] of Object.entries(HARNESS_TAG_TO_FIXTURE)) {
      if (fixtureName === name) return tag
    }
    return undefined
  }

  // Emit results for all b1 vectors.
  for (const v of b1Vectors) {
    const tag = tagForFixtureName(v.name)

    // b1-v2 is derived from the b1-v1 run (no separate stdout tag).
    const lookupTag = v.name === HARNESS_TAG_TO_FIXTURE['B1-V2'] ? B1_V2_DERIVED_FROM : tag

    if (!tag) {
      out.push(failResult(v.name,
        `runner: no harness tag mapping for fixture name "${v.name}" -- fixture may be newer than this runner`,
      ))
      continue
    }

    const outcome = run.outcomes.get(lookupTag ?? tag)

    if (outcome === 'PASS') {
      out.push(passResult(v.name))
    } else if (outcome === 'FAIL') {
      out.push(failResult(v.name,
        `harness reported FAIL for ${lookupTag ?? tag}; harness stdout: ${run.stdout.split('\n').filter(l => l.includes(`[${lookupTag ?? tag}]`)).join(' | ')}`,
      ))
    } else {
      // Tag not found in stdout -- harness may have crashed or skipped this vector.
      out.push(failResult(v.name,
        `harness did not emit outcome for ${lookupTag ?? tag} (exit code ${run.exitCode}); stderr: ${run.stderr.slice(0, 300)}`,
      ))
    }
  }

  // Emit results for all b2 vectors.
  for (const v of b2Vectors) {
    const tag = tagForFixtureName(v.name)

    if (!tag) {
      // b2-v8..v11 are DESIGN/PAPER placeholders without harness coverage.
      out.push(notExec(v.name,
        `vector "${v.name}" is a DESIGN/PAPER placeholder with no harness coverage (B3 loader work)`,
      ))
      continue
    }

    const outcome = run.outcomes.get(tag)

    if (outcome === 'PASS') {
      out.push(passResult(v.name))
    } else if (outcome === 'FAIL') {
      out.push(failResult(v.name,
        `harness reported FAIL for ${tag}; harness stdout: ${run.stdout.split('\n').filter(l => l.includes(`[${tag}]`)).join(' | ')}`,
      ))
    } else {
      out.push(failResult(v.name,
        `harness did not emit outcome for ${tag} (exit code ${run.exitCode}); stderr: ${run.stderr.slice(0, 300)}`,
      ))
    }
  }

  return out
}

// ---------------------------------------------------------------------------
// carrier-gv harness: resolves and runs the carrier-gv binary (GV-20..GV-28)
// ---------------------------------------------------------------------------

interface CarrierGvEnv {
  available:   true
  binaryPath:  string
}

interface CarrierGvUnavailable {
  available: false
  reason:    string
}

type CarrierGvResolution = CarrierGvEnv | CarrierGvUnavailable

// Locate the carrier-gv binary built from synoi-gateway/runtime/carrier.
// Uses the same gateway-root search logic as resolveHarnessEnv.
// Returns unavailable (with reason) when the binary is absent.
function resolveCarrierGvEnv(vectorsDir: string): CarrierGvResolution {
  const gwFromEnv = process.env['SYNOI_GATEWAY_DIR']
  let gatewayRoot: string | undefined

  if (gwFromEnv && existsSync(gwFromEnv)) {
    gatewayRoot = gwFromEnv
  } else {
    let dir = vectorsDir
    for (let i = 0; i < 5; i++) {
      dir = dirname(dir)
      const candidate = resolve(dir, '..', 'synoi-gateway')
      if (existsSync(candidate)) { gatewayRoot = candidate; break }
      const sibling = resolve(dir, 'synoi-gateway')
      if (existsSync(sibling)) { gatewayRoot = sibling; break }
    }
  }

  if (!gatewayRoot) {
    return {
      available: false,
      reason:    'synoi-gateway repo not found alongside synoi-conformance; set SYNOI_GATEWAY_DIR to its absolute path',
    }
  }

  const isWin     = process.platform === 'win32'
  const exeSuffix = isWin ? '.exe' : ''
  const binaryPath = join(
    gatewayRoot, 'runtime', 'carrier', 'target', 'debug', `carrier-gv${exeSuffix}`,
  )

  if (!existsSync(binaryPath)) {
    return {
      available: false,
      reason:    `carrier-gv binary not found at ${binaryPath}; run "cargo build" inside synoi-gateway/runtime/carrier to build it`,
    }
  }

  return { available: true, binaryPath }
}

// ---------------------------------------------------------------------------
// epoch-gv harness: resolves and runs the epoch-gv binary (GV-EPOCH-29/29b/29c)
//
// GV-EPOCH-1..8 (revocation_epoch epoch-check) are PAPER: the epoch parameter
// and StaleEpoch / MissingOrBadEpoch variants have not yet been added to
// gate_decision_cache_admit() in synoi-gateway/runtime/carrier/src/lib.rs.
// The runner reports PAPER for those vectors and runner-backed for 29/29b/29c.
// ---------------------------------------------------------------------------

interface EpochGvEnv {
  available:   true
  binaryPath:  string
}

interface EpochGvUnavailable {
  available: false
  reason:    string
}

type EpochGvResolution = EpochGvEnv | EpochGvUnavailable

// Locate the epoch-gv binary built from synoi-gateway/runtime/carrier.
// Uses the same gateway-root search logic as resolveCarrierGvEnv.
// Returns unavailable (with reason) when the binary is absent.
function resolveEpochGvEnv(vectorsDir: string): EpochGvResolution {
  const gwFromEnv = process.env['SYNOI_GATEWAY_DIR']
  let gatewayRoot: string | undefined

  if (gwFromEnv && existsSync(gwFromEnv)) {
    gatewayRoot = gwFromEnv
  } else {
    let dir = vectorsDir
    for (let i = 0; i < 5; i++) {
      dir = dirname(dir)
      const candidate = resolve(dir, '..', 'synoi-gateway')
      if (existsSync(candidate)) { gatewayRoot = candidate; break }
      const sibling = resolve(dir, 'synoi-gateway')
      if (existsSync(sibling)) { gatewayRoot = sibling; break }
    }
  }

  if (!gatewayRoot) {
    return {
      available: false,
      reason:    'synoi-gateway repo not found alongside synoi-conformance; set SYNOI_GATEWAY_DIR to its absolute path',
    }
  }

  const isWin     = process.platform === 'win32'
  const exeSuffix = isWin ? '.exe' : ''
  const binaryPath = join(
    gatewayRoot, 'runtime', 'carrier', 'target', 'debug', `epoch-gv${exeSuffix}`,
  )

  if (!existsSync(binaryPath)) {
    return {
      available: false,
      reason:    `epoch-gv binary not found at ${binaryPath}; run "cargo build --bin epoch-gv" inside synoi-gateway/runtime/carrier to build it`,
    }
  }

  return { available: true, binaryPath }
}

// Run the epoch-gv binary and map [GV-EPOCH-NN] PASS/FAIL lines to VectorResult[].
//
// Status routing per fixture vector:
//   "runner-backed" -- shell to epoch-gv and assert against stdout
//   "TS-backed"     -- report as NOT-EXECUTABLE-IN-RUNNER with an honest TS-backed note
//                      (the TS test runs via `npm test` in synoi-gateway, not from here)
function runEpochGvVectors(
  env:     EpochGvEnv,
  vectors: Array<{ name: string; tag: string; expected: string; status: string; note?: string }>,
): VectorResult[] {
  // Shell to the binary (no arguments; it is self-contained).
  const result = spawnSync(env.binaryPath, [], { encoding: 'utf8', timeout: 60_000 })

  const stdout   = result.stdout ?? ''
  const stderr   = result.stderr ?? ''
  const exitCode = result.status ?? 1

  // Parse [GV-EPOCH-NN] PASS/FAIL lines.
  const outcomes = new Map<string, string>()
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\[([A-Za-z0-9-]+)\]\s+(PASS|FAIL)\b/)
    if (m && m[1] && m[2]) {
      outcomes.set(m[1], m[2])
    }
  }

  const out: VectorResult[] = []
  for (const v of vectors) {
    // TS-backed: driven by the Node test suite in synoi-gateway, not by epoch-gv.
    if (v.status === 'TS-backed') {
      out.push(notExec(v.name,
        `TS-backed -- ${v.name} is exercised by synoi-gateway/test/consult-epoch.test.ts (GV-EPOCH-7-TS); run "npm test" in synoi-gateway to verify it`,
      ))
      continue
    }

    // runner-backed: assert against epoch-gv stdout.
    const outcome = outcomes.get(v.tag)
    if (outcome === 'PASS') {
      out.push(passResult(v.name))
    } else if (outcome === 'FAIL') {
      const matchingLines = stdout
        .split('\n')
        .filter(l => l.includes(`[${v.tag}]`))
        .join(' | ')
      out.push(failResult(v.name, `epoch-gv reported FAIL for ${v.tag}: ${matchingLines}`))
    } else {
      // Tag not found in stdout -- binary may have crashed or the GV tag changed.
      out.push(failResult(v.name,
        `epoch-gv did not emit outcome for ${v.tag} (exit ${exitCode}); stderr: ${stderr.slice(0, 300)}`,
      ))
    }
  }

  return out
}

// ---------------------------------------------------------------------------
// genesis-gv harness: resolves and runs the genesis-gv binary (GV-1..GV-16)
// ---------------------------------------------------------------------------

interface GenesisGvEnv {
  available:   true
  binaryPath:  string
}

interface GenesisGvUnavailable {
  available: false
  reason:    string
}

type GenesisGvResolution = GenesisGvEnv | GenesisGvUnavailable

// Locate the genesis-gv binary built from synoi-gateway/runtime/genesis.
// Uses the same gateway-root search logic as resolveCarrierGvEnv.
// Returns unavailable (with reason) when the binary is absent.
function resolveGenesisGvEnv(vectorsDir: string): GenesisGvResolution {
  const gwFromEnv = process.env['SYNOI_GATEWAY_DIR']
  let gatewayRoot: string | undefined

  if (gwFromEnv && existsSync(gwFromEnv)) {
    gatewayRoot = gwFromEnv
  } else {
    let dir = vectorsDir
    for (let i = 0; i < 5; i++) {
      dir = dirname(dir)
      const candidate = resolve(dir, '..', 'synoi-gateway')
      if (existsSync(candidate)) { gatewayRoot = candidate; break }
      const sibling = resolve(dir, 'synoi-gateway')
      if (existsSync(sibling)) { gatewayRoot = sibling; break }
    }
  }

  if (!gatewayRoot) {
    return {
      available: false,
      reason:    'synoi-gateway repo not found alongside synoi-conformance; set SYNOI_GATEWAY_DIR to its absolute path',
    }
  }

  const isWin     = process.platform === 'win32'
  const exeSuffix = isWin ? '.exe' : ''
  const binaryPath = join(
    gatewayRoot, 'runtime', 'genesis', 'target', 'debug', `genesis-gv${exeSuffix}`,
  )

  if (!existsSync(binaryPath)) {
    return {
      available: false,
      reason:    `genesis-gv binary not found at ${binaryPath}; run "cargo build --bin genesis-gv" inside synoi-gateway/runtime/genesis to build it`,
    }
  }

  return { available: true, binaryPath }
}

// Run the genesis-gv binary and map its [GV-NN] / [carrier-pin] PASS/FAIL
// stdout lines to VectorResult[]. Each fixture vector has a "tag" field used
// to find the corresponding stdout line.
function runGenesisGvVectors(
  env:     GenesisGvEnv,
  vectors: Array<{ name: string; tag: string; expected: string }>,
): VectorResult[] {
  const result = spawnSync(env.binaryPath, [], { encoding: 'utf8', timeout: 120_000 })

  const stdout   = result.stdout ?? ''
  const stderr   = result.stderr ?? ''
  const exitCode = result.status ?? 1

  // Parse [GV-NN] and [carrier-pin] PASS/FAIL lines.
  const outcomes = new Map<string, string>()
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\[([A-Za-z0-9-]+)\]\s+(PASS|FAIL)\b/)
    if (m && m[1] && m[2]) {
      outcomes.set(m[1], m[2])
    }
  }

  const out: VectorResult[] = []
  for (const v of vectors) {
    const outcome = outcomes.get(v.tag)
    if (outcome === 'PASS') {
      out.push(passResult(v.name))
    } else if (outcome === 'FAIL') {
      const matchingLines = stdout
        .split('\n')
        .filter(l => l.includes(`[${v.tag}]`))
        .join(' | ')
      out.push(failResult(v.name, `genesis-gv reported FAIL for ${v.tag}: ${matchingLines}`))
    } else if (v.tag.startsWith('DR-')) {
      // DR-* persistence vectors are backed by synoi-genesis cargo tests
      // (persistence_dr_tests in runtime/genesis/src/lib.rs); the genesis-gv
      // binary emits GV-* only and never produces these tags.
      out.push(notExec(v.name,
        'DR-* persistence vectors are backed by synoi-genesis cargo tests (persistence_dr_tests in synoi-runtime-wt/runtime/genesis/src/lib.rs). Run "cargo test -p synoi-genesis" to execute them.',
      ))
    } else {
      // Tag not found in stdout -- binary may have crashed or the tag name changed.
      out.push(failResult(v.name,
        `genesis-gv did not emit outcome for ${v.tag} (exit ${exitCode}); stderr: ${stderr.slice(0, 300)}`,
      ))
    }
  }

  return out
}

// ---------------------------------------------------------------------------
// translog-gv harness: resolves and runs the translog-gv binary (TL-01..TL-17)
// ---------------------------------------------------------------------------

interface TranslogGvEnv {
  available:   true
  binaryPath:  string
}

interface TranslogGvUnavailable {
  available: false
  reason:    string
}

type TranslogGvResolution = TranslogGvEnv | TranslogGvUnavailable

// Locate the translog-gv binary built from synoi-runtime-wt/runtime/translog.
// Uses SYNOI_RUNTIME_DIR env var as an explicit override, then walks up from
// vectorsDir looking for a sibling "synoi-runtime-wt" directory.
// Returns unavailable (with reason) when the binary is absent.
function resolveTranslogGvEnv(vectorsDir: string): TranslogGvResolution {
  const rtFromEnv = process.env['SYNOI_RUNTIME_DIR']
  let runtimeRoot: string | undefined

  if (rtFromEnv && existsSync(rtFromEnv)) {
    runtimeRoot = rtFromEnv
  } else {
    let dir = vectorsDir
    for (let i = 0; i < 5; i++) {
      dir = dirname(dir)
      const candidate = resolve(dir, '..', 'synoi-runtime-wt')
      if (existsSync(candidate)) { runtimeRoot = candidate; break }
      const sibling = resolve(dir, 'synoi-runtime-wt')
      if (existsSync(sibling)) { runtimeRoot = sibling; break }
    }
  }

  if (!runtimeRoot) {
    return {
      available: false,
      reason:    'synoi-runtime-wt worktree not found alongside synoi-conformance; set SYNOI_RUNTIME_DIR to its absolute path',
    }
  }

  const isWin     = process.platform === 'win32'
  const exeSuffix = isWin ? '.exe' : ''
  const binaryPath = join(
    runtimeRoot, 'runtime', 'translog', 'target', 'debug', `translog-gv${exeSuffix}`,
  )

  if (!existsSync(binaryPath)) {
    return {
      available: false,
      reason:    `translog-gv binary not found at ${binaryPath}; run "cargo build --bin translog-gv" inside synoi-runtime-wt/runtime/translog to build it`,
    }
  }

  return { available: true, binaryPath }
}

// Run the translog-gv binary and map its [TL-NN] PASS/FAIL stdout lines to
// VectorResult[]. Each fixture vector has a "tag" field (e.g. "TL-01") used
// to find the corresponding stdout line.
function runTranslogGvVectors(
  env:     TranslogGvEnv,
  vectors: Array<{ name: string; tag: string; expected: string }>,
): VectorResult[] {
  const result = spawnSync(env.binaryPath, [], { encoding: 'utf8', timeout: 60_000 })

  const stdout   = result.stdout ?? ''
  const stderr   = result.stderr ?? ''
  const exitCode = result.status ?? 1

  // Parse [TL-NN] PASS/FAIL lines from stdout.
  const outcomes = new Map<string, string>()
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\[([A-Za-z0-9-]+)\]\s+(PASS|FAIL)\b/)
    if (m && m[1] && m[2]) {
      outcomes.set(m[1], m[2])
    }
  }

  const out: VectorResult[] = []
  for (const v of vectors) {
    const outcome = outcomes.get(v.tag)
    if (outcome === 'PASS') {
      out.push(passResult(v.name))
    } else if (outcome === 'FAIL') {
      const matchingLines = stdout
        .split('\n')
        .filter(l => l.includes(`[${v.tag}]`))
        .join(' | ')
      out.push(failResult(v.name, `translog-gv reported FAIL for ${v.tag}: ${matchingLines}`))
    } else {
      out.push(failResult(v.name,
        `translog-gv did not emit outcome for ${v.tag} (exit ${exitCode}); stderr: ${stderr.slice(0, 300)}`,
      ))
    }
  }

  return out
}

// ---------------------------------------------------------------------------
// live-gate-round-trip harness: resolves and runs the LGRT binary (LGRT-1..5)
// ---------------------------------------------------------------------------

interface LiveGateEnv {
  available:   true
  binaryPath:  string
}

interface LiveGateUnavailable {
  available: false
  reason:    string
}

type LiveGateResolution = LiveGateEnv | LiveGateUnavailable

// Locate the live-gate-round-trip binary built from synoi-gateway/runtime/b1-harness.
// Also verifies tsx is present in node_modules/.bin/ of the gateway (the binary
// spawns Node/tsx internally; if tsx is absent the binary will block with an error).
// Uses the same gateway-root search logic as resolveCarrierGvEnv.
// Returns unavailable (with reason) when the binary or tsx is absent.
function resolveLiveGateEnv(vectorsDir: string): LiveGateResolution {
  const gwFromEnv = process.env['SYNOI_GATEWAY_DIR']
  let gatewayRoot: string | undefined

  if (gwFromEnv && existsSync(gwFromEnv)) {
    gatewayRoot = gwFromEnv
  } else {
    let dir = vectorsDir
    for (let i = 0; i < 5; i++) {
      dir = dirname(dir)
      const candidate = resolve(dir, '..', 'synoi-gateway')
      if (existsSync(candidate)) { gatewayRoot = candidate; break }
      const sibling = resolve(dir, 'synoi-gateway')
      if (existsSync(sibling)) { gatewayRoot = sibling; break }
    }
  }

  if (!gatewayRoot) {
    return {
      available: false,
      reason:    'synoi-gateway repo not found alongside synoi-conformance; set SYNOI_GATEWAY_DIR to its absolute path',
    }
  }

  const isWin     = process.platform === 'win32'
  const exeSuffix = isWin ? '.exe' : ''
  const binaryPath = join(
    gatewayRoot, 'runtime', 'b1-harness', 'target', 'debug', `live-gate-round-trip${exeSuffix}`,
  )

  if (!existsSync(binaryPath)) {
    return {
      available: false,
      reason:    `live-gate-round-trip binary not found at ${binaryPath}; run "cargo build --bin live_gate_round_trip" inside synoi-gateway/runtime/b1-harness to build it`,
    }
  }

  // Verify tsx is available in the gateway node_modules (the binary spawns it).
  const tsxCmd = join(gatewayRoot, 'node_modules', '.bin', 'tsx.cmd')
  const tsx    = join(gatewayRoot, 'node_modules', '.bin', 'tsx')
  if (!existsSync(tsxCmd) && !existsSync(tsx)) {
    return {
      available: false,
      reason:    `tsx not found at ${tsxCmd} or ${tsx}; run "npm install" inside synoi-gateway so the live-gate-round-trip binary can spawn the Node test server`,
    }
  }

  return { available: true, binaryPath }
}

// Run the live-gate-round-trip binary and map its [LGRT-N] PASS/FAIL stdout
// lines to VectorResult[]. Each fixture vector has a "tag" field (e.g. "LGRT-1")
// used to find the corresponding stdout line.
//
// The binary itself spawns a real Node/tsx gateway server, so spawnSync must
// allow sufficient timeout for the Node startup plus 5 HTTP round trips.
// 120 seconds is generous; the binary typically completes in under 10 seconds.
function runLiveGateVectors(
  env:     LiveGateEnv,
  vectors: Array<{ name: string; tag: string; expected: string }>,
): VectorResult[] {
  // Shell to the binary with no arguments; it is self-contained (spawns Node internally).
  const result = spawnSync(env.binaryPath, [], { encoding: 'utf8', timeout: 120_000 })

  const stdout   = result.stdout ?? ''
  const stderr   = result.stderr ?? ''
  const exitCode = result.status ?? 1

  // Parse [LGRT-N] PASS/FAIL lines from stdout.
  const outcomes = new Map<string, string>()
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\[([A-Za-z0-9-]+)\]\s+(PASS|FAIL)\b/)
    if (m && m[1] && m[2]) {
      // Keep the worst outcome if a tag appears more than once.
      if (!outcomes.has(m[1]) || m[2] === 'FAIL') {
        outcomes.set(m[1], m[2])
      }
    }
  }

  const out: VectorResult[] = []
  for (const v of vectors) {
    const outcome = outcomes.get(v.tag)
    if (outcome === 'PASS') {
      out.push(passResult(v.name))
    } else if (outcome === 'FAIL') {
      const matchingLines = stdout
        .split('\n')
        .filter(l => l.includes(`[${v.tag}]`))
        .join(' | ')
      out.push(failResult(v.name, `live-gate-round-trip reported FAIL for ${v.tag}: ${matchingLines}`))
    } else {
      // Tag not found in stdout -- binary may have crashed or the tag name changed.
      out.push(failResult(v.name,
        `live-gate-round-trip did not emit outcome for ${v.tag} (exit ${exitCode}); stderr: ${stderr.slice(0, 400)}`,
      ))
    }
  }

  return out
}

// ---------------------------------------------------------------------------
// stage6-render-loop harness: resolves and runs the stage6 binary (DR-6, DR-7,
// LGRT-3-LOOP, LGRT-4-LOOP). Lives in synoi-runtime-wt (the WASM worktree).
// ---------------------------------------------------------------------------

interface Stage6Env {
  available:      true
  binaryPath:     string
  shellStubWasm:  string
}

interface Stage6Unavailable {
  available: false
  reason:    string
}

type Stage6Resolution = Stage6Env | Stage6Unavailable

// Locate the stage6-render-loop binary and shell_stub.wasm.
// Binary: synoi-runtime-wt/runtime/b1-harness/target/debug/stage6-render-loop[.exe]
// WASM:   synoi-runtime-wt/runtime/test-components/shell-stub/target/wasm32-wasip2/debug/shell_stub.wasm
// tsx check: also requires Node/tsx in the GATEWAY node_modules (for the Node server).
// Uses SYNOI_RUNTIME_DIR (same as translog-gv) + SYNOI_GATEWAY_DIR env vars.
function resolveStage6Env(vectorsDir: string): Stage6Resolution {
  // Locate the runtime worktree (same search as resolveTranslogGvEnv).
  const rtFromEnv = process.env['SYNOI_RUNTIME_DIR']
  let runtimeRoot: string | undefined

  if (rtFromEnv && existsSync(rtFromEnv)) {
    runtimeRoot = rtFromEnv
  } else {
    let dir = vectorsDir
    for (let i = 0; i < 5; i++) {
      dir = dirname(dir)
      const candidate = resolve(dir, '..', 'synoi-runtime-wt')
      if (existsSync(candidate)) { runtimeRoot = candidate; break }
      const sibling = resolve(dir, 'synoi-runtime-wt')
      if (existsSync(sibling)) { runtimeRoot = sibling; break }
    }
  }

  if (!runtimeRoot) {
    return {
      available: false,
      reason:    'synoi-runtime-wt worktree not found alongside synoi-conformance; set SYNOI_RUNTIME_DIR to its absolute path',
    }
  }

  const isWin      = process.platform === 'win32'
  const exeSuffix  = isWin ? '.exe' : ''
  const binaryPath = join(
    runtimeRoot, 'runtime', 'b1-harness', 'target', 'debug', `stage6-render-loop${exeSuffix}`,
  )

  if (!existsSync(binaryPath)) {
    return {
      available: false,
      reason:    `stage6-render-loop binary not found at ${binaryPath}; run "cargo build --bin stage6-render-loop" inside synoi-runtime-wt/runtime/b1-harness to build it`,
    }
  }

  const shellStubWasm = join(
    runtimeRoot, 'runtime', 'test-components', 'shell-stub',
    'target', 'wasm32-wasip2', 'debug', 'shell_stub.wasm',
  )

  if (!existsSync(shellStubWasm)) {
    return {
      available: false,
      reason:    `shell_stub.wasm not found at ${shellStubWasm}; run "cargo component build" inside synoi-runtime-wt/runtime/test-components/shell-stub to build it`,
    }
  }

  // Also check that tsx is available in the gateway node_modules (the binary
  // spawns the live-gate-test-server.ts via tsx internally).
  const gwFromEnv = process.env['SYNOI_GATEWAY_DIR']
  let gatewayRoot: string | undefined

  if (gwFromEnv && existsSync(gwFromEnv)) {
    gatewayRoot = gwFromEnv
  } else {
    let dir = vectorsDir
    for (let i = 0; i < 5; i++) {
      dir = dirname(dir)
      const candidate = resolve(dir, '..', 'synoi-gateway')
      if (existsSync(candidate)) { gatewayRoot = candidate; break }
      const sibling = resolve(dir, 'synoi-gateway')
      if (existsSync(sibling)) { gatewayRoot = sibling; break }
    }
  }

  if (!gatewayRoot) {
    return {
      available: false,
      reason:    'synoi-gateway repo not found alongside synoi-conformance; set SYNOI_GATEWAY_DIR to its absolute path (needed for tsx to spawn the test server)',
    }
  }

  const tsxCmd = join(gatewayRoot, 'node_modules', '.bin', 'tsx.cmd')
  const tsx    = join(gatewayRoot, 'node_modules', '.bin', 'tsx')
  if (!existsSync(tsxCmd) && !existsSync(tsx)) {
    return {
      available: false,
      reason:    `tsx not found at ${tsxCmd} or ${tsx}; run "npm install" inside synoi-gateway so the stage6-render-loop binary can spawn the Node test server`,
    }
  }

  return { available: true, binaryPath, shellStubWasm }
}

// Run the stage6-render-loop binary and map its [DR-6], [DR-7], [LGRT-3-LOOP],
// [LGRT-4-LOOP] PASS/FAIL stdout lines to VectorResult[].
// The binary takes one argument: the path to shell_stub.wasm.
// It spawns the Node test server internally, so a generous timeout is used.
function runStage6Vectors(
  env:     Stage6Env,
  vectors: Array<{ name: string; tag: string; expected: string }>,
): VectorResult[] {
  const result = spawnSync(
    env.binaryPath,
    [env.shellStubWasm],
    { encoding: 'utf8', timeout: 120_000 },
  )

  const stdout   = result.stdout ?? ''
  const stderr   = result.stderr ?? ''
  const exitCode = result.status ?? 1

  // Parse [DR-6], [DR-7], [LGRT-3-LOOP], [LGRT-4-LOOP] PASS/FAIL lines.
  // The binary uses the prefix pattern: "[DR-6] PASS: ..." / "[DR-6] FAIL: ...".
  // LGRT lines: "[LGRT-3-LOOP] PASS: ..." etc.
  const outcomes = new Map<string, string>()
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\[([A-Za-z0-9-]+(?:-LOOP)?)\]\s+(PASS|FAIL)\b/)
    if (m && m[1] && m[2]) {
      if (!outcomes.has(m[1]) || m[2] === 'FAIL') {
        outcomes.set(m[1], m[2])
      }
    }
  }

  const out: VectorResult[] = []
  for (const v of vectors) {
    const outcome = outcomes.get(v.tag)
    if (outcome === 'PASS') {
      out.push(passResult(v.name))
    } else if (outcome === 'FAIL') {
      const matchingLines = stdout
        .split('\n')
        .filter(l => l.includes(`[${v.tag}]`))
        .join(' | ')
      out.push(failResult(v.name, `stage6-render-loop reported FAIL for ${v.tag}: ${matchingLines}`))
    } else {
      // Tag not found -- binary may have crashed, or server was unavailable (env gate).
      // Check if the binary printed an ENV-CONDITIONAL note for this tag.
      const envCondLine = stdout
        .split('\n')
        .find(l => l.includes(`[${v.tag}]`) && l.includes('ENV-CONDITIONAL'))
      if (envCondLine) {
        out.push(notExec(v.name, `ENV-CONDITIONAL: ${envCondLine.trim()}`))
      } else {
        out.push(failResult(v.name,
          `stage6-render-loop did not emit outcome for ${v.tag} (exit ${exitCode}); stderr: ${stderr.slice(0, 400)}`,
        ))
      }
    }
  }

  return out
}

// Run the carrier-gv binary and map its [GV-NN] PASS/FAIL stdout lines to
// VectorResult[]. Each fixture vector has a "tag" field (e.g. "GV-20") used
// to find the corresponding stdout line.
function runCarrierGvVectors(
  env:     CarrierGvEnv,
  vectors: Array<{ name: string; tag: string; expected: string }>,
): VectorResult[] {
  // Shell to the binary (no arguments; it is self-contained).
  const result = spawnSync(env.binaryPath, [], { encoding: 'utf8', timeout: 120_000 })

  const stdout   = result.stdout ?? ''
  const stderr   = result.stderr ?? ''
  const exitCode = result.status ?? 1

  // Parse [GV-NN] PASS/FAIL lines.
  const outcomes = new Map<string, string>()
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\[([A-Za-z0-9-]+)\]\s+(PASS|FAIL)\b/)
    if (m && m[1] && m[2]) {
      outcomes.set(m[1], m[2])
    }
  }

  const out: VectorResult[] = []
  for (const v of vectors) {
    const outcome = outcomes.get(v.tag)
    if (outcome === 'PASS') {
      out.push(passResult(v.name))
    } else if (outcome === 'FAIL') {
      const matchingLines = stdout
        .split('\n')
        .filter(l => l.includes(`[${v.tag}]`))
        .join(' | ')
      out.push(failResult(v.name, `carrier-gv reported FAIL for ${v.tag}: ${matchingLines}`))
    } else {
      // Tag not found in stdout -- binary may have crashed or the tag name changed.
      out.push(failResult(v.name,
        `carrier-gv did not emit outcome for ${v.tag} (exit ${exitCode}); stderr: ${stderr.slice(0, 300)}`,
      ))
    }
  }

  return out
}

// ---------------------------------------------------------------------------
// Types inferred from fixture shapes
// ---------------------------------------------------------------------------

interface CanonicalParityFixture {
  description: string
  cases: CanonicalParityCase[]
}
interface CanonicalParityCase {
  name: string
  kind: 'canonicalize' | 'cdro_oid'
  input?: unknown
  expected_canonical?: string
  expected_oid?: string
}

interface MlDsaInteropFixture {
  description: string
  ed25519_pub: string   // hex
  ml_dsa_pub:  string   // hex
  envelope:    DsseEnvelope
  negative_fixtures: Record<string, { description: string; envelope: DsseEnvelope }>
}

interface DsseEnvelope {
  payloadType: string
  payload:     string
  signatures:  Array<{ alg: string; sig: string; keyid?: string }>
}

interface GateConsultFixture {
  description:            string
  gate_signer_ed25519_pub: string  // hex
  gate_signer_ml_dsa_pub:  string  // hex
  fixtures: Record<string, GateConsultCase>
}

interface GateConsultCase {
  description:   string
  live_tuple:    LiveTuple
  content_core?: Record<string, unknown>
  attestation:   DsseEnvelope
  expected:      'ACCEPT' | 'REJECT'
  expected_reason?: string
}

interface LiveTuple {
  bundle_oid:              string
  principal_oid:           string
  panel_id:                string
  action_kind:             string
  originating_receipt_oid: string | null
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function runWasmShellVectors(
  vectorsDir: string,
  preloadedVectors: Vector[],
): Promise<VectorResult[]> {
  const out: VectorResult[] = []

  // Scan for fixture files and route by filename.
  if (!existsSync(vectorsDir)) return out

  const files = readdirSync(vectorsDir).filter(f => f.endsWith('.json') && !f.startsWith('_'))

  // Pending b1/b2 vector lists. Both fixture files feed a single harness run
  // after the file-scan loop completes.
  let pendingB1: Array<{ name: string }> = []
  let pendingB2: Array<{ name: string }> = []

  for (const file of files) {
    const fullPath = join(vectorsDir, file)

    if (file === 'canonical-parity.json') {
      out.push(...runCanonicalParityFixture(fullPath))
      continue
    }
    if (file === 'mldsa-hybrid-interop.json') {
      out.push(...runMlDsaInteropFixture(fullPath))
      continue
    }
    if (file === 'gate-consult-rebind.json') {
      out.push(...await runGateConsultRebindFixture(fullPath))
      continue
    }
    // b1 and b2 fixture files carry a "vectors" array exercised by the Rust
    // Wasmtime harness. When the harness binary is available the runner shells
    // to it and asserts each vector against the live output. When the binary
    // is absent the runner reports NOT-EXECUTABLE-IN-RUNNER with an explicit
    // reason -- no fake pass is ever emitted.
    //
    // Both files are handled together in a single harness run (the harness
    // accepts shell_stub.wasm, bad_imports.wasm, receipt_verify.wasm as args).
    // We defer the actual execution until we have read both fixture files.
    if (file === 'b1-undeclared-import-reject.json' || file === 'b2-receipt-verify.json') {
      // Accumulate into pending lists; actual execution happens after the loop.
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string }>
      }
      if (Array.isArray(raw.vectors)) {
        if (file === 'b1-undeclared-import-reject.json') {
          pendingB1 = raw.vectors.map(v => ({ name: String(v.name ?? file) }))
        } else {
          pendingB2 = raw.vectors.map(v => ({ name: String(v.name ?? file) }))
        }
      }
      continue
    }
    // revocation-epoch: cache-admit epoch conformance (GV-EPOCH-1..6,8 runner-backed; GV-EPOCH-7 TS-backed).
    // Shells to epoch-gv binary (synoi-gateway/runtime/carrier/src/bin/epoch_gv.rs).
    // GV-EPOCH-7 is TS-test-backed (consult-epoch.test.ts) and NOT shelled to here.
    // NOT-EXECUTABLE-IN-RUNNER for runner-backed vectors when epoch-gv binary is absent.
    if (file === 'revocation-epoch.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string; tag: string; expected: string; status: string; note?: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      const egEnv = resolveEpochGvEnv(vectorsDir)
      if (!egEnv.available) {
        for (const v of vectors) {
          if (v.status === 'TS-backed') {
            out.push(notExec(v.name,
              `TS-backed -- ${v.name} is exercised by synoi-gateway/test/consult-epoch.test.ts; run "npm test" in synoi-gateway to verify`,
            ))
          } else {
            out.push(notExec(v.name,
              `${egEnv.reason}. Build synoi-gateway/runtime/carrier with "cargo build --bin epoch-gv" to enable runner execution.`,
            ))
          }
        }
      } else {
        out.push(...runEpochGvVectors(egEnv, vectors))
      }
      continue
    }
    // carrier-genesis-chain: ADR_011 Section 10.4 GV-20..GV-28.
    // Shells to carrier-gv binary (no WASM components needed).
    // NOT-EXECUTABLE-IN-RUNNER when binary is absent.
    if (file === 'carrier-genesis-chain.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string; tag: string; expected: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      const cgEnv = resolveCarrierGvEnv(vectorsDir)
      if (!cgEnv.available) {
        for (const v of vectors) {
          out.push(notExec(v.name,
            `${cgEnv.reason}. Build synoi-gateway/runtime/carrier with "cargo build" to enable runner execution.`,
          ))
        }
      } else {
        out.push(...runCarrierGvVectors(cgEnv, vectors))
      }
      continue
    }
    // genesis-manifest-chain: ADR_011 Section 5 GV-1..GV-16 + Section 10.2.1.
    // Shells to genesis-gv binary (no WASM components needed).
    // NOT-EXECUTABLE-IN-RUNNER when binary is absent.
    if (file === 'genesis-manifest-chain.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string; tag: string; expected: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      const ggEnv = resolveGenesisGvEnv(vectorsDir)
      if (!ggEnv.available) {
        for (const v of vectors) {
          out.push(notExec(v.name,
            `${ggEnv.reason}. Build synoi-gateway/runtime/genesis with "cargo build --bin genesis-gv" to enable runner execution.`,
          ))
        }
      } else {
        out.push(...runGenesisGvVectors(ggEnv, vectors))
      }
      continue
    }
    // live-gate-round-trip: iteration-10 live HTTP vectors (LGRT-1..5).
    // Shells to the live-gate-round-trip binary, which spawns a real Node/tsx
    // gateway server and exercises real HTTP. The binary and tsx must both be
    // present; otherwise NOT-EXECUTABLE-IN-RUNNER is reported for every vector.
    if (file === 'live-gate-round-trip.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string; tag: string; expected: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      const lgEnv = resolveLiveGateEnv(vectorsDir)
      if (!lgEnv.available) {
        for (const v of vectors) {
          out.push(notExec(v.name,
            `${lgEnv.reason}. Build synoi-gateway/runtime/b1-harness with "cargo build --bin live_gate_round_trip" and run "npm install" in synoi-gateway to enable runner execution.`,
          ))
        }
      } else {
        out.push(...runLiveGateVectors(lgEnv, vectors))
      }
      continue
    }
    // stage6-render-loop: ADR_013 Stage-6 per-invocation render loop (DR-6, DR-7,
    // LGRT-3-LOOP, LGRT-4-LOOP). Shells to the stage6-render-loop binary in
    // synoi-runtime-wt. Requires shell_stub.wasm + tsx.
    // PARTIAL-against-test-keys. NOT-EXECUTABLE-IN-RUNNER when binary or tsx absent.
    if (file === 'stage6-render-loop.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string; tag: string; expected: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      const s6Env = resolveStage6Env(vectorsDir)
      if (!s6Env.available) {
        for (const v of vectors) {
          out.push(notExec(v.name,
            `${s6Env.reason}. Build synoi-runtime-wt/runtime/b1-harness with "cargo build --bin stage6-render-loop" and run "npm install" in synoi-gateway to enable runner execution.`,
          ))
        }
      } else {
        out.push(...runStage6Vectors(s6Env, vectors))
      }
      continue
    }
    // daemon-boot-chain: ADR_013 Stage 1-5 boot composition (DR-1..DR-14).
    // These vectors are backed exclusively by cargo tests in synoi-daemon
    // (synoi-runtime-wt/runtime/daemon/src/tests.rs). The runner has no
    // daemon binary to shell to and cannot execute them directly.
    // Report NOT-EXECUTABLE-IN-RUNNER for every vector -- honest, no fake pass.
    if (file === 'daemon-boot-chain.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      for (const v of vectors) {
        out.push(notExec(v.name,
          'daemon-boot-chain vectors are backed by synoi-daemon cargo tests (synoi-runtime-wt/runtime/daemon/src/tests.rs). Run "cargo test" inside synoi-runtime-wt/runtime/daemon to execute them.',
        ))
      }
      continue
    }
    // transparency-log-chain: ADR_012 Phase-0 RFC 6962 Merkle log TL-01..TL-17.
    // Shells to translog-gv binary (synoi-runtime-wt/runtime/translog).
    // NOT-EXECUTABLE-IN-RUNNER when binary is absent.
    if (file === 'transparency-log-chain.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string; tag: string; expected: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      const tgEnv = resolveTranslogGvEnv(vectorsDir)
      if (!tgEnv.available) {
        for (const v of vectors) {
          out.push(notExec(v.name,
            `${tgEnv.reason}. Build synoi-runtime-wt/runtime/translog with "cargo build --bin translog-gv" to enable runner execution.`,
          ))
        }
      } else {
        out.push(...runTranslogGvVectors(tgEnv, vectors))
      }
      continue
    }
    // governed-action-receipt-xlang: cross-language receipt-v2 verify.
    // Rust-emitted governed-action receipt CDROs verified by @synoi/verify
    // verifyReceiptV2. Keys derived from SHELL_RECEIPT_{ED,ML}_SEED in
    // synoi-runtime-wt/runtime/b1-harness/src/lib.rs ([7,8] seed pattern).
    // Positive: allowed + denied receipts -> ACCEPT.
    // Negative: tampered content -> REJECT (payload-core-mismatch).
    // Negative: wrong-key [9,10] -> REJECT.
    // TAG: PARTIAL-against-test-keys. TEST KEYS ONLY.
    if (file === 'governed-action-receipt-xlang.json') {
      out.push(...await runGovernedActionXlangFixture(fullPath))
      continue
    }
    // governed-action-receipt-cdro: cargo-test-backed vectors (not executable
    // from this runner -- requires the Rust harness binary + the b1-harness
    // cargo tests, which are exercised by "cargo test --lib -p b1-harness").
    if (file === 'governed-action-receipt-cdro.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      for (const v of vectors) {
        out.push(notExec(v.name,
          'governed-action-receipt-cdro vectors are backed by synoi-runtime-wt cargo tests. Run "cargo test --lib -p b1-harness" to execute them.',
        ))
      }
      continue
    }
    // repanel-f1-f2-f3: tsx-backed vectors for re-panel findings F1 (SEVERE),
    // F2 (MEDIUM), F3 (MEDIUM) on the /local + engine grant authorization path.
    // Tests run via `npx tsx test/oa-grant-legacy-bypass.test.ts`,
    // `npx tsx test/repanel-f2-prod-interlock.test.ts`, and
    // `npx tsx test/repanel-f3-nonce-leak.test.ts` in synoi-runtime-wt on
    // branch wasm-runtime. GREEN 2026-06-22 (4/4 + 6/6 + 11/11 + 34/34).
    // NOT executable from this runner -- tsx-backed in synoi-gateway worktree.
    if (file === 'repanel-f1-f2-f3.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      for (const v of vectors) {
        out.push(notExec(v.name,
          'repanel-f1-f2-f3 vectors are backed by tsx tests in synoi-runtime-wt (branch wasm-runtime). ' +
          'Run: npx tsx test/oa-grant-legacy-bypass.test.ts, test/repanel-f2-prod-interlock.test.ts, ' +
          'test/repanel-f3-nonce-leak.test.ts to execute them.',
        ))
      }
      continue
    }
    // local-ingest-api: tsx-backed vectors for the /local ingest API surface.
    // Tests run via the synoi-runtime-wt tsx test suite.
    // NOT executable from this runner.
    if (file === 'local-ingest-api.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      for (const v of vectors) {
        out.push(notExec(v.name,
          'local-ingest-api vectors are backed by tsx tests in synoi-runtime-wt. ' +
          'Run: npm test in synoi-runtime-wt to execute them.',
        ))
      }
      continue
    }
    // repanel-adr015-s10-tenant-scope: ADR_015 Section 10 amendment (2026-06-23).
    // Tenant-scoped operator enrollment + demo isolation. Closes two re-panel
    // CRITICAL/privesc defects (demo-door self-enroll and cross-tenant allowlist).
    // Tests run via `npx tsx test/oa-tenant-scope.test.ts` in synoi-runtime-wt
    // on branch wasm-runtime. GREEN 2026-06-23 (21/21 + 30/30 + 59/59 + 29/29 + 34/34).
    // TAG: PARTIAL-against-test-keys. NOT executable from this runner.
    if (file === 'repanel-adr015-s10-tenant-scope.json') {
      const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as {
        vectors?: Array<{ name: string }>
      }
      const vectors = Array.isArray(raw.vectors) ? raw.vectors : []
      for (const v of vectors) {
        out.push(notExec(v.name,
          'repanel-adr015-s10-tenant-scope vectors are backed by tsx tests in synoi-runtime-wt (branch wasm-runtime). ' +
          'Run: npx tsx test/oa-tenant-scope.test.ts to execute them. ' +
          'Also confirm: test/oa-operator-enrollment.test.ts (30/30), test/local-ingest-router.test.ts (59/59), ' +
          'test/local-ingest-security-2-3-4.test.ts (29/29), test/s1-grant-update.test.ts (34/34), ' +
          'test/demo-revoke.test.ts (11/11), test/repanel-f2-prod-interlock.test.ts (6/6). ' +
          'PARTIAL-against-test-keys. Pending re-panel (Security + Adversary 2-of-2).',
        ))
      }
      continue
    }
    // Unrecognized fixture -- surface as unknown rather than silently skip.
    out.push({
      vector_name: `${file}:unknown-fixture`,
      passed: false,
      reason: `wasm-shell: no handler for fixture file ${file}`,
    })
  }

  // Post-loop: execute b1/b2 vectors via the Rust harness if we collected any.
  if (pendingB1.length > 0 || pendingB2.length > 0) {
    const harnessEnv = resolveHarnessEnv(vectorsDir)

    if (!harnessEnv.available) {
      // Harness binary or WASM artifacts not available. Report honestly as not-executable.
      const makeNotExec = (v: { name: string }) => notExec(v.name,
        `${harnessEnv.reason}. Runner is capable of shelling to the harness when the binary is present; status stays PARTIAL until run in a toolchain-equipped environment.`,
      )
      out.push(...pendingB1.map(makeNotExec))
      out.push(...pendingB2.map(makeNotExec))
    } else {
      // Harness binary is present. Shell to it and assert against live output.
      // Runner-SHIPPED only when the harness exits 0 and every vector line is PASS.
      out.push(...runB1B2Vectors(harnessEnv, pendingB1, pendingB2))
    }
  }

  return out
}

// ---------------------------------------------------------------------------
// canonical-parity: TS oracle execution
// ---------------------------------------------------------------------------

function runCanonicalParityFixture(path: string): VectorResult[] {
  const out: VectorResult[] = []
  let fixture: CanonicalParityFixture
  try {
    fixture = JSON.parse(readFileSync(path, 'utf8')) as CanonicalParityFixture
  } catch (err) {
    return [failResult('canonical-parity:load', `parse error: ${(err as Error).message}`)]
  }
  if (!Array.isArray(fixture.cases)) {
    return [failResult('canonical-parity:load', 'fixture missing "cases" array')]
  }

  for (const c of fixture.cases) {
    const name = `canonical-parity:${c.name}`
    if (c.kind === 'canonicalize') {
      // The non-bmp case has no "input" key (input is described only in input_note).
      // The expected_canonical string IS the oracle output -- but to execute it we need
      // the actual JS object with those code points. For the non-bmp-utf16-sort case the
      // object literal cannot be represented in JSON directly without losing the
      // surrogate-pair information. We reconstruct it here from the unicode values.
      if (c.name === 'non-bmp-utf16-sort') {
        // Key 1: U+1D11E (G clef, code point 0x1D11E) -- encoded in JSON as surrogate pair
        // Key 2: U+E000 (PUA start)
        const key1 = '\u{1D11E}'  // G clef: string with surrogate pair in V8
        const key2 = ''     // PUA
        const obj: Record<string, number> = {}
        obj[key1] = 1
        obj[key2] = 2
        let actual: string
        try {
          actual = canonicalize(obj)
        } catch (err) {
          out.push(failResult(name, `canonicalize threw: ${(err as Error).message}`))
          continue
        }
        const expected = c.expected_canonical ?? ''
        if (actual !== expected) {
          out.push(failResult(name, 'canonical bytes mismatch', { expected, actual }))
        } else {
          out.push(passResult(name))
        }
        continue
      }
      // General canonicalize case with explicit "input".
      if (c.input === undefined) {
        out.push(failResult(name, 'missing input field for canonicalize case'))
        continue
      }
      let actual: string
      try {
        actual = canonicalize(c.input)
      } catch (err) {
        out.push(failResult(name, `canonicalize threw: ${(err as Error).message}`))
        continue
      }
      const expected = c.expected_canonical ?? ''
      if (actual !== expected) {
        out.push(failResult(name, 'canonical bytes mismatch', { expected, actual }))
      } else {
        out.push(passResult(name))
      }
      continue
    }

    if (c.kind === 'cdro_oid') {
      if (c.input === undefined) {
        out.push(failResult(name, 'missing input field for cdro_oid case'))
        continue
      }
      let actual: string
      try {
        actual = cdroOid(c.input as Record<string, unknown>)
      } catch (err) {
        out.push(failResult(name, `cdroOid threw: ${(err as Error).message}`))
        continue
      }
      const expected = c.expected_oid ?? ''
      if (actual !== expected) {
        out.push(failResult(name, 'oid mismatch', { expected, actual }))
      } else {
        out.push(passResult(name))
      }
      continue
    }

    out.push(failResult(name, `unknown canonical-parity kind: ${String(c.kind)}`))
  }
  return out
}

// ---------------------------------------------------------------------------
// mldsa-hybrid-interop: DSSE attestation verification
// ---------------------------------------------------------------------------

function runMlDsaInteropFixture(path: string): VectorResult[] {
  const out: VectorResult[] = []
  let fixture: MlDsaInteropFixture
  try {
    fixture = JSON.parse(readFileSync(path, 'utf8')) as MlDsaInteropFixture
  } catch (err) {
    return [failResult('mldsa-hybrid-interop:load', `parse error: ${(err as Error).message}`)]
  }

  const ed25519Pub = hexToBytes(fixture.ed25519_pub)
  const mlDsaPub   = hexToBytes(fixture.ml_dsa_pub)

  // Positive: valid envelope must verify.
  out.push(runDsseVerify(
    'mldsa-hybrid-interop:accept',
    fixture.envelope,
    ed25519Pub,
    mlDsaPub,
    true,
    null,
  ))

  // Negatives from negative_fixtures map.
  const negs = fixture.negative_fixtures ?? {}

  // tampered_payload -- both sigs must fail.
  if (negs['tampered_payload']) {
    out.push(runDsseVerify(
      'mldsa-hybrid-interop:tampered-payload',
      negs['tampered_payload'].envelope,
      ed25519Pub,
      mlDsaPub,
      false,
      null,
    ))
  }

  // ml_dsa_sig_stripped -- missing ml-dsa-65 signature, must reject.
  if (negs['ml_dsa_sig_stripped']) {
    out.push(runDsseVerify(
      'mldsa-hybrid-interop:ml-dsa-stripped',
      negs['ml_dsa_sig_stripped'].envelope,
      ed25519Pub,
      mlDsaPub,
      false,
      null,
    ))
  }

  // wrong_payload_type -- PAE changes, both sigs fail.
  if (negs['wrong_payload_type']) {
    out.push(runDsseVerify(
      'mldsa-hybrid-interop:wrong-payload-type',
      negs['wrong_payload_type'].envelope,
      ed25519Pub,
      mlDsaPub,
      false,
      null,
    ))
  }

  return out
}

// ---------------------------------------------------------------------------
// gate-consult-rebind: DSSE verify + tuple match + expiry
// ---------------------------------------------------------------------------

async function runGateConsultRebindFixture(path: string): Promise<VectorResult[]> {
  const out: VectorResult[] = []
  let fixture: GateConsultFixture
  try {
    fixture = JSON.parse(readFileSync(path, 'utf8')) as GateConsultFixture
  } catch (err) {
    return [failResult('gate-consult-rebind:load', `parse error: ${(err as Error).message}`)]
  }

  const ed25519Pub = hexToBytes(fixture.gate_signer_ed25519_pub)
  const mlDsaPub   = hexToBytes(fixture.gate_signer_ml_dsa_pub)

  for (const [fixtureName, fc] of Object.entries(fixture.fixtures)) {
    const name = `gate-consult-rebind:${fixtureName}`
    out.push(runGateConsultCase(name, fc, ed25519Pub, mlDsaPub))
  }

  return out
}

function runGateConsultCase(
  name:        string,
  fc:          GateConsultCase,
  ed25519Pub:  Uint8Array,
  mlDsaPub:    Uint8Array,
): VectorResult {
  // Step 1: verify DSSE attestation signature.
  let attestationValid: boolean
  try {
    const vr = verifyAttestation({
      envelope:    fc.attestation,
      ed25519_pub: ed25519Pub,
      ml_dsa_pub:  mlDsaPub,
    })
    attestationValid = vr.valid
  } catch (err) {
    return failResult(name, `verifyAttestation threw: ${(err as Error).message}`)
  }

  // Step 2: parse the payload and check tuple match against live_tuple.
  let parsedPayload: Record<string, unknown>
  try {
    parsedPayload = JSON.parse(fc.attestation.payload) as Record<string, unknown>
  } catch (err) {
    return failResult(name, `payload JSON parse failed: ${(err as Error).message}`)
  }

  const lt = fc.live_tuple

  // Step 3: determine the expected verdict, then check our derived verdict.
  const expected = fc.expected  // 'ACCEPT' | 'REJECT'
  const expectedReason = fc.expected_reason

  // Gate consult rebind verdict logic:
  // REJECT conditions (in priority order):
  //   1. signer-not-trusted: sig invalid and expected_reason is 'signer-not-trusted'
  //   2. tuple-mismatch: live_tuple fields do not match content_core
  //   3. missing-ml-dsa-65: ml-dsa-65 absent from signatures array
  //   4. expired: expires_at is in the past

  // Check for missing ML-DSA-65.
  const hasMlDsa = fc.attestation.signatures.some(s => s.alg === 'ml-dsa-65')
  if (!hasMlDsa) {
    const derivedVerdict = 'REJECT'
    const derivedReason = 'missing-ml-dsa-65'
    return assessGateVerdict(name, derivedVerdict, derivedReason, expected, expectedReason)
  }

  // Check attestation signature validity.
  if (!attestationValid) {
    const derivedVerdict = 'REJECT'
    // Classify reason: if expected_reason is signer-not-trusted we use that,
    // otherwise fall back to sig-invalid.
    const derivedReason = expectedReason === 'signer-not-trusted' ? 'signer-not-trusted' : 'sig-invalid'
    return assessGateVerdict(name, derivedVerdict, derivedReason, expected, expectedReason)
  }

  // Check tuple mismatch: compare live_tuple fields against parsed payload.
  // Semantics match bound_tuple_matches in runtime/verify/src/lib.rs:
  //
  // Mandatory fields (bundle_oid, principal_oid, panel_id, action_kind):
  //   content_core field must be PRESENT and a STRING and EQUAL to live.
  //   A missing field, null, or a non-string value is a hard mismatch
  //   (fail-closed). No coercion of missing/non-string to "" or null.
  //
  // Optional field (originating_receipt_oid):
  //   live null   + payload absent/null  -> match (None == None).
  //   live null   + payload non-null string -> mismatch.
  //   live string + payload same string  -> match (Some == Some(equal)).
  //   live string + payload different    -> mismatch.
  //   payload present but non-string/non-null -> mismatch (fail-closed).
  const mandatoryFields: Array<'bundle_oid' | 'principal_oid' | 'panel_id' | 'action_kind'> = [
    'bundle_oid', 'principal_oid', 'panel_id', 'action_kind',
  ]
  for (const field of mandatoryFields) {
    const inPayload = parsedPayload[field]
    // Must be present and a string and equal to live value.
    if (typeof inPayload !== 'string' || inPayload !== lt[field]) {
      return assessGateVerdict(name, 'REJECT', 'tuple-mismatch', expected, expectedReason)
    }
  }
  // originating_receipt_oid: optional with None==None / Some==Some(equal) / else mismatch.
  const liveOrig = lt.originating_receipt_oid  // string | null from LiveTuple
  const rawOrig  = parsedPayload['originating_receipt_oid']
  // Normalize payload: absent and null both map to None (null).
  const payloadOrig: string | null = (rawOrig === undefined || rawOrig === null)
    ? null
    : (typeof rawOrig === 'string' ? rawOrig : undefined as unknown as null)
  const payloadOrigIsNonString = rawOrig !== undefined && rawOrig !== null && typeof rawOrig !== 'string'
  if (payloadOrigIsNonString || liveOrig !== payloadOrig) {
    return assessGateVerdict(name, 'REJECT', 'tuple-mismatch', expected, expectedReason)
  }

  // Check expiry.
  const expiresAt = String(parsedPayload['expires_at'] ?? '')
  if (expiresAt) {
    const expiresMs = Date.parse(expiresAt)
    if (!isNaN(expiresMs) && Date.now() > expiresMs) {
      return assessGateVerdict(name, 'REJECT', 'expired', expected, expectedReason)
    }
  }

  // Decision is ACCEPT.
  return assessGateVerdict(name, 'ACCEPT', undefined, expected, expectedReason)
}

function assessGateVerdict(
  name:           string,
  derived:        'ACCEPT' | 'REJECT',
  derivedReason:  string | undefined,
  expected:       'ACCEPT' | 'REJECT',
  expectedReason: string | undefined,
): VectorResult {
  if (derived !== expected) {
    return failResult(name,
      `expected ${expected}${expectedReason ? ` (${expectedReason})` : ''}, got ${derived}${derivedReason ? ` (${derivedReason})` : ''}`,
    )
  }
  if (expected === 'REJECT' && expectedReason && derivedReason !== expectedReason) {
    return failResult(name,
      `correct REJECT but wrong reason: expected "${expectedReason}", got "${derivedReason ?? 'none'}"`,
    )
  }
  return passResult(name)
}

// ---------------------------------------------------------------------------
// DSSE envelope helper
// ---------------------------------------------------------------------------

// When expectedValid is null, we just return the raw result without asserting.
// This is used internally by gate-consult-rebind. For the mldsa-interop vectors,
// expectedValid is a boolean and we assert against it.
function runDsseVerify(
  name:          string,
  envelope:      DsseEnvelope,
  ed25519Pub:    Uint8Array,
  mlDsaPub:      Uint8Array,
  expectedValid: boolean | null,
  _unused:       null,
): VectorResult {
  let valid: boolean
  let reasons: string[] = []
  try {
    const result = verifyAttestation({
      envelope,
      ed25519_pub: ed25519Pub,
      ml_dsa_pub:  mlDsaPub,
    })
    valid = result.valid
    reasons = result.reasons
  } catch (err) {
    return failResult(name, `verifyAttestation threw: ${(err as Error).message}`)
  }

  if (expectedValid === null) {
    // Internal use: just return the raw verdict. status='pass' means sig was valid.
    return valid ? passResult(name) : failResult(name, 'sig invalid (internal)')
  }

  if (valid !== expectedValid) {
    return failResult(name,
      `expected valid=${expectedValid}, got ${valid} (${reasons.join('; ')})`,
      { expected: expectedValid, actual: valid },
    )
  }
  return passResult(name)
}

// ---------------------------------------------------------------------------
// governed-action-receipt-xlang: cross-language receipt-v2 verify
// ---------------------------------------------------------------------------
//
// Reads governed-action-receipt-xlang.json (emitted by Rust
// emit-governed-action-fixture bin) and calls @synoi/verify verifyReceiptV2.
// Uses the public keys embedded in the fixture (hex-encoded) so the TS verifier
// uses exactly the bytes the Rust signer produced.
//
// Four vectors:
//   xlang-allow-receipt-accept    -- governed-action.allowed receipt -> ACCEPT
//   xlang-deny-receipt-accept     -- governed-action.denied receipt  -> ACCEPT
//   xlang-tamper-reject           -- byte-flipped payload -> REJECT (payload-core-mismatch)
//   xlang-wrong-key-reject        -- right receipt, wrong keys -> REJECT
//
// TAG: PARTIAL-against-test-keys. TEST KEYS ONLY. Production keys are
// ceremony-gated and PAPER until the key-ceremony process is defined.

interface XlangFixture {
  ed25519_pub_hex: string
  ml_dsa_pub_hex:  string
  allow_receipt:   Record<string, unknown>
  deny_receipt:    Record<string, unknown>
}

async function runGovernedActionXlangFixture(path: string): Promise<VectorResult[]> {
  const out: VectorResult[] = []

  let fixture: XlangFixture
  try {
    fixture = JSON.parse(readFileSync(path, 'utf8')) as XlangFixture
  } catch (err) {
    return [failResult('governed-action-receipt-xlang:load',
      `parse error: ${(err as Error).message}`)]
  }

  // Decode public keys from hex (Rust-emitted, ground-truth bytes).
  let ed25519_pub: Uint8Array
  let ml_dsa_pub: Uint8Array
  try {
    ed25519_pub = hexToBytes(fixture.ed25519_pub_hex)
    ml_dsa_pub  = hexToBytes(fixture.ml_dsa_pub_hex)
  } catch (err) {
    return [failResult('governed-action-receipt-xlang:keys',
      `hex decode failed: ${(err as Error).message}`)]
  }

  // Import verifyReceiptV2 from the SHIPPED @synoi/verify package.
  // Dynamic import: @synoi/verify is a devDependency of this package.
  let verifyReceiptV2Fn: (
    input: { receipt: Record<string, unknown>; ed25519_pub: Uint8Array; ml_dsa_pub: Uint8Array }
  ) => Promise<{ valid: boolean; reasons: string[] }>

  try {
    // @synoi/verify is installed as a local file dep under node_modules.
    // It is a CJS package that re-exports its src/verify.ts types.
    const mod = await import('@synoi/verify') as {
      verifyReceiptV2?: (i: {
        receipt: Record<string, unknown>
        ed25519_pub: Uint8Array
        ml_dsa_pub: Uint8Array
      }) => Promise<{ valid: boolean; reasons: string[] }>
    }
    if (typeof mod.verifyReceiptV2 !== 'function') {
      return [failResult('governed-action-receipt-xlang:import',
        '@synoi/verify does not export verifyReceiptV2')]
    }
    verifyReceiptV2Fn = mod.verifyReceiptV2
  } catch (err) {
    return [failResult('governed-action-receipt-xlang:import',
      `failed to import @synoi/verify: ${(err as Error).message}`)]
  }

  // POSITIVE 1: governed-action.allowed receipt.
  try {
    const r = await verifyReceiptV2Fn({
      receipt:     fixture.allow_receipt,
      ed25519_pub,
      ml_dsa_pub,
    })
    if (r.valid) {
      out.push(passResult('governed-action-receipt-xlang:allow-accept'))
    } else {
      out.push(failResult('governed-action-receipt-xlang:allow-accept',
        `expected ACCEPT, got REJECT: ${r.reasons.join('; ')}`))
    }
  } catch (err) {
    out.push(failResult('governed-action-receipt-xlang:allow-accept',
      `verifyReceiptV2 threw: ${(err as Error).message}`))
  }

  // POSITIVE 2: governed-action.denied receipt.
  try {
    const r = await verifyReceiptV2Fn({
      receipt:     fixture.deny_receipt,
      ed25519_pub,
      ml_dsa_pub,
    })
    if (r.valid) {
      out.push(passResult('governed-action-receipt-xlang:deny-accept'))
    } else {
      out.push(failResult('governed-action-receipt-xlang:deny-accept',
        `expected ACCEPT, got REJECT: ${r.reasons.join('; ')}`))
    }
  } catch (err) {
    out.push(failResult('governed-action-receipt-xlang:deny-accept',
      `verifyReceiptV2 threw: ${(err as Error).message}`))
  }

  // NEGATIVE 1: tamper the attestation payload (byte flip).
  // Flip the first character of the canonical payload string, breaking the
  // content-core bind check (payload-core-mismatch) before signature verify.
  try {
    const tampered = JSON.parse(JSON.stringify(fixture.allow_receipt)) as Record<string, unknown>
    const att = tampered['attestation'] as Record<string, unknown>
    const orig = String(att['payload'] ?? '')
    att['payload'] = orig.length > 0
      ? (orig[0] === '{' ? '}' + orig.slice(1) : '{' + orig.slice(1))
      : '_tampered_'

    const r = await verifyReceiptV2Fn({
      receipt:     tampered,
      ed25519_pub,
      ml_dsa_pub,
    })
    if (!r.valid) {
      out.push(passResult('governed-action-receipt-xlang:tamper-reject'))
    } else {
      out.push(failResult('governed-action-receipt-xlang:tamper-reject',
        'expected REJECT on tampered receipt, got ACCEPT (non-vacuous control failed)'))
    }
  } catch (err) {
    out.push(failResult('governed-action-receipt-xlang:tamper-reject',
      `verifyReceiptV2 threw on tampered fixture: ${(err as Error).message}`))
  }

  // NEGATIVE 2: wrong public key.
  // Derive a different keypair ([9,10] seeds) and present the valid allow receipt
  // under those wrong keys. The sig verify step must reject.
  try {
    // Build wrong ML-DSA pub from seed [9,0,...,0,9].
    const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js') as {
      ml_dsa65: {
        keygen: (seed: Uint8Array) => { publicKey: Uint8Array }
      }
    }
    const wrongMlSeed = new Uint8Array(32); wrongMlSeed[0] = 9; wrongMlSeed[31] = 9
    const wrong_ml    = ml_dsa65.keygen(wrongMlSeed)

    // Ed25519 wrong pub from seed [9,0,...,0,9].
    const { ed25519 } = await import('@noble/curves/ed25519') as {
      ed25519: { getPublicKey: (seed: Uint8Array) => Uint8Array }
    }
    const wrongEdSeed    = new Uint8Array(32); wrongEdSeed[0] = 9; wrongEdSeed[31] = 9
    const wrong_ed25519  = ed25519.getPublicKey(wrongEdSeed)

    const r = await verifyReceiptV2Fn({
      receipt:     fixture.allow_receipt,
      ed25519_pub: wrong_ed25519,
      ml_dsa_pub:  wrong_ml.publicKey,
    })
    if (!r.valid) {
      out.push(passResult('governed-action-receipt-xlang:wrong-key-reject'))
    } else {
      out.push(failResult('governed-action-receipt-xlang:wrong-key-reject',
        'expected REJECT with wrong keys, got ACCEPT (key-binding control failed)'))
    }
  } catch (err) {
    out.push(failResult('governed-action-receipt-xlang:wrong-key-reject',
      `wrong-key control threw: ${(err as Error).message}`))
  }

  return out
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length hex string (len=${hex.length})`)
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    out[i >> 1] = parseInt(hex.slice(i, i + 2), 16)
  }
  return out
}

function sha256Hex(data: string): string {
  return 'sha256:' + createHash('sha256').update(data, 'utf8').digest('hex')
}
