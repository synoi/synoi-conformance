// badge.test.ts - unit tests for the tier computation, SVG badge render,
// manifest validation, and conformant-projects entry builder.
//
// Fixture-driven: constructs RunReport[] directly (rather than running a
// full conformance pass) so the tier-boundary logic is exercised precisely,
// including the "no partial credit" and "no skipping a lower tier" rules.

import {
  TIER_PROTOCOLS, computeTier, computeTierResult, renderBadgeSvg, buildBadgeSvg,
  validateManifest, buildProjectEntry,
} from '../src/badge.ts'
import type { RunReport, Protocol } from '../src/types.ts'

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

function report(protocol: Protocol, opts: Partial<RunReport> = {}): RunReport {
  return {
    protocol,
    protocol_status: 'conformant',
    vectors_run:     10,
    passed:          10,
    failed:          0,
    not_executable:  0,
    stubbed:         0,
    failures:        [],
    not_executables: [],
    stubs:           [],
    ...opts,
  }
}

function main(): void {
  // ── Tier boundaries ──────────────────────────────────────────────────
  ok('TIER_PROTOCOLS order is sraid, gap, oid-resolver, cited-oracle-inputs',
     JSON.stringify(TIER_PROTOCOLS) === JSON.stringify(['sraid', 'gap', 'oid-resolver', 'cited-oracle-inputs']))

  ok('empty reports -> tier 0',           computeTier([]) === 0)
  ok('only gap passing (no sraid) -> tier 0 (cannot skip a lower tier)',
     computeTier([report('gap')]) === 0)
  ok('only sraid passing -> tier 1',        computeTier([report('sraid')]) === 1)
  ok('sraid + gap passing -> tier 2',       computeTier([report('sraid'), report('gap')]) === 2)
  ok('sraid + gap + oid-resolver -> tier 3', computeTier([report('sraid'), report('gap'), report('oid-resolver')]) === 3)
  ok('all four -> tier 4',
     computeTier([report('sraid'), report('gap'), report('oid-resolver'), report('cited-oracle-inputs')]) === 4)

  // A protocol with ANY failure does not count, even if most vectors pass.
  const sraidWithOneFailure = report('sraid', { passed: 9, failed: 1 })
  ok('sraid with 1 failure (of 10) -> tier 0 (no partial credit within a protocol)',
     computeTier([sraidWithOneFailure, report('gap')]) === 0)

  // A stub protocol never counts even if it "passed" its own internal bookkeeping.
  const stubSraid = report('sraid', { protocol_status: 'stub', passed: 0, failed: 0, stubbed: 10 })
  ok('stub sraid (protocol_status=stub) -> tier 0 (stub protocols never gate a tier)',
     computeTier([stubSraid, report('gap')]) === 0)

  // A protocol that ran zero vectors does not count as "passing clean".
  const emptySraid = report('sraid', { vectors_run: 0, passed: 0 })
  ok('sraid with vectors_run=0 -> tier 0 (never run != passed)',
     computeTier([emptySraid]) === 0)

  // inference-broker and wasm-shell never gate tiers even if conformant.
  const brokerPassing = report('inference-broker' as Protocol)
  ok('inference-broker passing (hypothetically) does not raise the tier past what sraid/gap/resolver earn',
     computeTier([report('sraid'), report('gap'), brokerPassing]) === 2)

  // ── computeTierResult ────────────────────────────────────────────────
  const full = computeTierResult([report('sraid'), report('gap'), report('oid-resolver'), report('cited-oracle-inputs')])
  ok('computeTierResult.tier === 4',                     full.tier === 4)
  ok('computeTierResult.qualifying_protocols has 4 entries', full.qualifying_protocols.length === 4)
  ok('computeTierResult.badge.vectors_passed sums conformant protocols', full.badge.vectors_passed === 40)
  ok('computeTierResult.badge.vectors_total sums conformant protocols',  full.badge.vectors_total === 40)

  // ── SVG rendering ────────────────────────────────────────────────────
  const svgL4 = renderBadgeSvg(full)
  ok('L4 SVG contains "Conformant - L4"',    svgL4.includes('Conformant - L4'))
  ok('L4 SVG is a well-formed <svg> root',   svgL4.trim().startsWith('<svg') && svgL4.trim().endsWith('</svg>'))
  ok('L4 SVG has no external references (no xlink:href, no <image>)',
     !svgL4.includes('xlink:href') && !svgL4.includes('<image'))
  ok('L4 SVG escapes XML-unsafe characters if present in label (no raw &)', !/[^;]&[^a-z#]/.test(svgL4))

  const zero = computeTierResult([])
  const svgL0 = renderBadgeSvg(zero)
  ok('L0 SVG says "not conformant", not a fabricated tier label',
     svgL0.includes('not conformant') && !svgL0.includes('Conformant - L0'))

  const { svg: svgFromBuild, result: resultFromBuild } = buildBadgeSvg([report('sraid')])
  ok('buildBadgeSvg tier matches computeTierResult',        resultFromBuild.tier === 1)
  ok('buildBadgeSvg svg matches renderBadgeSvg(result)',    svgFromBuild === renderBadgeSvg(resultFromBuild))

  // ── Manifest validation ──────────────────────────────────────────────
  const validManifest = {
    schema: 'synoi.conformance.manifest/v1',
    project: 'my-project',
    repo_url: 'https://github.com/example/my-project',
    protocols: ['sraid', 'gap'],
    impl_entry: './impl.mjs',
  }
  const v1 = validateManifest(validManifest)
  ok('valid manifest -> ok:true', v1.ok === true)

  const missingSchema = validateManifest({ ...validManifest, schema: 'wrong' })
  ok('wrong schema -> ok:false', missingSchema.ok === false)

  const missingProject = validateManifest({ ...validManifest, project: '' })
  ok('empty project -> ok:false', missingProject.ok === false)

  const badProtocol = validateManifest({ ...validManifest, protocols: ['not-a-real-protocol'] })
  ok('unknown protocol in manifest -> ok:false', badProtocol.ok === false)

  const noVerifySurface = validateManifest({ ...validManifest, impl_entry: undefined })
  ok('manifest with no impl_entry/resolver_url -> ok:false (claim must be verifiable)', noVerifySurface.ok === false)

  const resolverManifest = validateManifest({
    schema: 'synoi.conformance.manifest/v1',
    project: 'my-resolver',
    repo_url: 'https://github.com/example/my-resolver',
    protocols: ['oid-resolver'],
    resolver_url: 'http://localhost:4000',
  })
  ok('manifest with resolver_url (no impl_entry) -> ok:true', resolverManifest.ok === true)

  ok('validateManifest rejects non-object input', validateManifest('not an object').ok === false)
  ok('validateManifest rejects null', validateManifest(null).ok === false)

  // ── Conformant-projects entry builder ───────────────────────────────
  const entry = buildProjectEntry(
    { project: 'demo-project', repo_url: 'https://github.com/example/demo-project' },
    [report('sraid'), report('gap')],
    '2026-07-03T00:00:00.000Z',
  )
  ok('buildProjectEntry.project matches input',   entry.project === 'demo-project')
  ok('buildProjectEntry.tier === 2',              entry.tier === 2)
  ok('buildProjectEntry.qualifying_protocols === [sraid, gap]',
     JSON.stringify(entry.qualifying_protocols) === JSON.stringify(['sraid', 'gap']))
  ok('buildProjectEntry.verified_at echoes the passed timestamp', entry.verified_at === '2026-07-03T00:00:00.000Z')
  ok('buildProjectEntry.vectors_passed/total from badge math',    entry.vectors_passed === 20 && entry.vectors_total === 20)

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

main()
