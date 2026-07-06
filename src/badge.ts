// badge.ts - "SynOI GAP Conformant - L<tier>" SVG badge, driven by actual
// conformance-run results (RunReport[] from runProtocol()). Reuses the same
// ConformanceBadge math reporter.ts already computes (badge.vectors_passed /
// badge.vectors_total, stub-exclusion) - this module does not re-derive
// pass/fail from anything other than RunReport[].
//
// Tier definition (L1-L4), honest-by-construction:
//   The badge tier is the count of TIER_PROTOCOLS that are both (a) present
//   in the run, (b) protocol_status === 'conformant' (never a stub - see
//   STUB_PROTOCOLS in runner.ts), and (c) failed === 0 with vectors_run > 0.
//   A protocol that was never run does not count. A protocol with any
//   failure does not count, even if most of its vectors passed. There is no
//   partial credit inside a protocol; a tier level requires that protocol's
//   full vector pack to pass clean.
//
//   L0 (no badge issued) - fewer than 1 qualifying protocol, or 'sraid' itself
//                           (the base canonicalization/signature protocol)
//                           did not pass clean.
//   L1 - sraid passes clean (canonicalization + hybrid signature verification).
//   L2 - L1 + gap passes clean (Governed Action Protocol type/OID validators).
//   L3 - L2 + oid-resolver passes clean (resolver HTTP surface).
//   L4 - L3 + cited-oracle-inputs passes clean (cited-oracle receipt binding).
//
// wasm-shell and inference-broker are intentionally excluded from the tier
// ladder: wasm-shell vectors legitimately report not-executable in
// environments without the Wasmtime harness binary (see wasm-shell.ts), and
// inference-broker is a permanent stub protocol per STUB_PROTOCOLS until it
// ships DSSE-signed hybrid receipts. Neither can honestly gate a badge tier
// today; see ARCHIVE note in runner.ts if that changes.

import type { ConformanceBadge, Protocol, RunReport } from './types.js'

/** Protocols that gate badge tiers, in tier order. Index 0 => L1, etc. */
export const TIER_PROTOCOLS: readonly Protocol[] = ['sraid', 'gap', 'oid-resolver', 'cited-oracle-inputs']

export type BadgeTier = 0 | 1 | 2 | 3 | 4

/** A protocol "passes clean" for tier purposes: conformant, ran >=1 vector, zero failures. */
function passesClean(report: RunReport | undefined): boolean {
  if (!report) return false
  if (report.protocol_status !== 'conformant') return false
  if (report.vectors_run === 0) return false
  return report.failed === 0
}

/**
 * Compute the badge tier from a set of RunReports. Walks TIER_PROTOCOLS in
 * order and stops at the first protocol that is missing or did not pass
 * clean - a tier can never be claimed by skipping a lower one.
 */
export function computeTier(reports: RunReport[]): BadgeTier {
  const byProtocol = new Map<Protocol, RunReport>()
  for (const r of reports) byProtocol.set(r.protocol, r)

  let tier: BadgeTier = 0
  for (let i = 0; i < TIER_PROTOCOLS.length; i++) {
    const proto = TIER_PROTOCOLS[i]!
    if (!passesClean(byProtocol.get(proto))) break
    tier = (i + 1) as BadgeTier
  }
  return tier
}

export interface TierResult {
  tier:    BadgeTier
  badge:   ConformanceBadge
  /** Which TIER_PROTOCOLS entries passed clean, in order, up to the tier reached. */
  qualifying_protocols: Protocol[]
}

function buildConformanceBadge(reports: RunReport[]): ConformanceBadge {
  const conformant = reports.filter(r => r.protocol_status === 'conformant')
  const stubs      = reports.filter(r => r.protocol_status === 'stub')
  return {
    conformant_protocols: conformant.map(r => r.protocol),
    stub_protocols:       stubs.map(r => r.protocol),
    vectors_passed:       conformant.reduce((a, r) => a + r.passed,      0),
    vectors_total:        conformant.reduce((a, r) => a + r.vectors_run - r.not_executable, 0),
  }
}

/** Compute the full tier result (tier + underlying badge numbers) from a run. */
export function computeTierResult(reports: RunReport[]): TierResult {
  const tier = computeTier(reports)
  return {
    tier,
    badge: buildConformanceBadge(reports),
    qualifying_protocols: TIER_PROTOCOLS.slice(0, tier),
  }
}

// ── SVG rendering ────────────────────────────────────────────────────────

const TIER_COLOR: Record<BadgeTier, string> = {
  0: '#9e9e9e', // grey - no badge earned
  1: '#8bc34a', // light green
  2: '#4caf50', // green
  3: '#2e7d32', // dark green
  4: '#1b5e20', // deepest green
}

function escXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** Rough monospace-ish width estimate (shields.io-style, ~6.2px/char at 11px Verdana). */
function textWidth(s: string): number {
  return Math.round(s.length * 6.4) + 10
}

/**
 * Render the "SynOI GAP Conformant - L<tier>" badge as a self-contained SVG
 * (no external fonts/images; shields.io-style two-segment badge). L0 renders
 * as "not conformant" in grey rather than a fabricated tier label.
 */
export function renderBadgeSvg(result: TierResult): string {
  const label = 'SynOI GAP'
  const message = result.tier === 0 ? 'not conformant' : `Conformant - L${result.tier}`
  const color = TIER_COLOR[result.tier]

  const labelWidth = textWidth(label)
  const msgWidth   = textWidth(message)
  const totalWidth = labelWidth + msgWidth
  const height = 20

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="${height}" role="img" aria-label="${escXml(label)}: ${escXml(message)}">
  <title>${escXml(label)}: ${escXml(message)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="${height}" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="${height}" fill="#555"/>
    <rect x="${labelWidth}" width="${msgWidth}" height="${height}" fill="${color}"/>
    <rect width="${totalWidth}" height="${height}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelWidth / 2}" y="14">${escXml(label)}</text>
    <text x="${labelWidth + msgWidth / 2}" y="14">${escXml(message)}</text>
  </g>
</svg>`
}

/** Convenience: compute tier from reports and render the SVG in one call. */
export function buildBadgeSvg(reports: RunReport[]): { svg: string; result: TierResult } {
  const result = computeTierResult(reports)
  return { svg: renderBadgeSvg(result), result }
}

// ── Manifest (what a project commits to CLAIM its badge) ───────────────────

/**
 * The manifest a project commits (e.g. `.synoi-conformance.json` at repo
 * root) to claim a badge. This is the input contract, not the output: the
 * actual tier is always recomputed from a live conformance run against
 * `impl_entry` / `resolver_url`, never trusted from the manifest's
 * `claimed_tier` field alone. `claimed_tier` is advisory (what the project
 * believes it earned, e.g. for README badge markdown) and MUST be verified
 * before being surfaced as a real badge.
 */
export interface ConformanceManifest {
  /** Manifest schema version. */
  schema: 'synoi.conformance.manifest/v1'
  /** Project name as it should appear in the conformant-projects list. */
  project: string
  /** Repository URL (for the conformant-projects list link). */
  repo_url: string
  /** Protocols this project claims conformance for, subset of TIER_PROTOCOLS
   *  plus optionally 'wasm-shell' / 'inference-broker' for informational
   *  (non-tier-gating) display. */
  protocols: Protocol[]
  /** Advisory only - see doc comment above. Not trusted without a live run. */
  claimed_tier?: BadgeTier
  /** How to run conformance against this project. At least one of these
   *  must be present for the badge to be verifiable, not just claimed. */
  impl_entry?:   string  // JS module path/specifier for SRAID/GAP-style protocols
  resolver_url?: string  // URL for oid-resolver-style protocols
}

/** Runtime validation of a ConformanceManifest (no schema library dependency). */
export function validateManifest(input: unknown): { ok: true; manifest: ConformanceManifest } | { ok: false; error: string } {
  if (input === null || typeof input !== 'object') return { ok: false, error: 'manifest must be a JSON object' }
  const m = input as Record<string, unknown>
  if (m.schema !== 'synoi.conformance.manifest/v1') {
    return { ok: false, error: `unsupported schema: ${String(m.schema)} (expected synoi.conformance.manifest/v1)` }
  }
  if (typeof m.project !== 'string' || m.project.length === 0) {
    return { ok: false, error: 'project must be a non-empty string' }
  }
  if (typeof m.repo_url !== 'string' || m.repo_url.length === 0) {
    return { ok: false, error: 'repo_url must be a non-empty string' }
  }
  if (!Array.isArray(m.protocols) || m.protocols.length === 0) {
    return { ok: false, error: 'protocols must be a non-empty array' }
  }
  const validProtocols: Protocol[] = ['sraid', 'gap', 'oid-resolver', 'inference-broker', 'cited-oracle-inputs', 'wasm-shell']
  for (const p of m.protocols) {
    if (!validProtocols.includes(p as Protocol)) {
      return { ok: false, error: `unknown protocol in manifest: ${String(p)}` }
    }
  }
  if (m.impl_entry === undefined && m.resolver_url === undefined) {
    return { ok: false, error: 'manifest must provide impl_entry and/or resolver_url so the claim is verifiable' }
  }
  return { ok: true, manifest: m as unknown as ConformanceManifest }
}

// ── Conformant-projects seed list ───────────────────────────────────────────

/** One entry in the public conformant-projects list (consumed by the /conformance web page). */
export interface ConformantProjectEntry {
  project:  string
  repo_url: string
  tier:     BadgeTier
  qualifying_protocols: Protocol[]
  vectors_passed: number
  vectors_total:  number
  /** ISO 8601 timestamp of when this entry's conformance run was recorded. */
  verified_at: string
}

/** Build one seed-list entry from a manifest + the RunReports of its actual run. */
export function buildProjectEntry(
  manifest: Pick<ConformanceManifest, 'project' | 'repo_url'>,
  reports: RunReport[],
  verifiedAt: string = new Date().toISOString(),
): ConformantProjectEntry {
  const { tier, badge, qualifying_protocols } = computeTierResult(reports)
  return {
    project:  manifest.project,
    repo_url: manifest.repo_url,
    tier,
    qualifying_protocols,
    vectors_passed: badge.vectors_passed,
    vectors_total:  badge.vectors_total,
    verified_at:    verifiedAt,
  }
}
