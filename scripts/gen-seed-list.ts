#!/usr/bin/env node
// gen-seed-list.ts - generate seed-conformant-projects.json, the day-one
// seed list for the /conformance web page (built by another lane). Runs the
// REAL conformance suite against SynOI's own reference implementations
// (@synoi/sraid for sraid, @synoi/gap for gap, @synoi/oid-resolver booted
// in-process for oid-resolver, cited-oracle-inputs standalone) - this is
// not a hand-authored/fabricated list; every entry's tier + pass counts
// come from an actual runProtocol() pass against real code, using the same
// harness pattern the conformance tests already use (see
// test/sraid-conformance.test.ts, test/gap-conformance.test.ts,
// test/resolver-conformance.test.ts).
//
// Usage: tsx scripts/gen-seed-list.ts [output-path]
// Default output: seed-conformant-projects.json (repo root)

import { writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { AddressInfo } from 'node:net'
import { runProtocol } from '../src/runner.js'
import { buildProjectEntry, type ConformantProjectEntry } from '../src/badge.js'
import type { Reporter, RunReport, VectorResult, Protocol } from '../src/types.js'

class SilentReporter implements Reporter {
  onVector(_p: Protocol, _r: VectorResult): void {}
  onProtocolDone(_r: RunReport): void {}
  finish(_reps: RunReport[]): number { return 0 }
}

async function runSraidReport(): Promise<RunReport> {
  const dir  = mkdtempSync(join(tmpdir(), 'synoi-seed-sraid-'))
  const impl = join(dir, 'impl.mjs')
  const { writeFileSync: wf } = await import('node:fs')
  const sraidUrl = await import.meta.resolve('@synoi/sraid')
  wf(impl,
    `import * as m from ${JSON.stringify(sraidUrl)}\n` +
    `export const canonicalize      = m.canonicalize\n` +
    `export const oidOf             = m.oidOf\n` +
    `export const verifySignature   = m.verifySignature\n` +
    `export const verifyAttestation = m.verifyAttestation\n` +
    `export const verifyAuthority   = m.verifyAuthority\n` +
    `export const lineageLinks      = m.lineageLinks\n` +
    `export const latestWins        = m.latestWins\n` +
    `export const sensitivityCarryForward = m.sensitivityCarryForward\n` +
    `export const cdroOid           = m.cdroOid\n` +
    `export const cdroContentCore   = m.cdroContentCore\n` +
    `export function verifyReceiptV2({ receipt, ed25519_pub, ml_dsa_pub }) {\n` +
    `  const env = receipt.attestation\n` +
    `  if (!env || typeof env !== 'object') return { valid: false, reasons: ['missing-attestation'] }\n` +
    `  const expected = m.canonicalize(m.cdroContentCore(receipt))\n` +
    `  if (env.payload !== expected) return { valid: false, reasons: ['payload-core-mismatch'] }\n` +
    `  const res = m.verifyAttestation({ envelope: env, ed25519_pub, ml_dsa_pub, expectedPayloadType: 'application/vnd.synoi.gap+json' })\n` +
    `  return { valid: res.valid, reasons: res.reasons }\n` +
    `}\n`,
    'utf8')
  return runProtocol({
    protocol:   'sraid',
    implPath:   impl,
    reporter:   new SilentReporter(),
    vectorsDir: join(process.cwd(), 'vectors', 'sraid'),
  })
}

async function runGapReport(): Promise<RunReport> {
  const dir  = mkdtempSync(join(tmpdir(), 'synoi-seed-gap-'))
  const impl = join(dir, 'impl.mjs')
  const gapIndex = `${process.cwd().replace(/\\/g, '/')}/node_modules/@synoi/gap/dist/index.js`
  writeFileSync(impl,
    `import * as m from 'file:///${gapIndex}'\n` +
    `export const computeGapOid                  = m.computeGapOid\n` +
    `export const validateCapabilityDeclaration  = m.validateCapabilityDeclaration\n` +
    `export const validateCapabilityGrant        = m.validateCapabilityGrant\n` +
    `export const validateCapabilityInvocation   = m.validateCapabilityInvocation\n` +
    `export const validateWorkflowDefinition     = m.validateWorkflowDefinition\n` +
    `export const validateWorkflowInstance       = m.validateWorkflowInstance\n` +
    `export const validateGapDecisionReceipt     = m.validateGapDecisionReceipt\n` +
    `export const validateRevocationEvent        = m.validateRevocationEvent\n`,
    'utf8')
  return runProtocol({
    protocol:   'gap',
    implPath:   impl,
    reporter:   new SilentReporter(),
    vectorsDir: join(process.cwd(), 'vectors', 'gap'),
  })
}

async function runResolverReport(): Promise<RunReport> {
  const { mkdtempSync: mk } = await import('node:fs')
  const dataDir = mk(join(tmpdir(), 'synoi-seed-resolver-'))
  process.env['RESOLVER_BEARER_TOKEN'] = 'seed-gen-bearer'
  const mod = await import('@synoi/oid-resolver')
  const factory = (mod as unknown as {
    createResolverApp?: (opts: { dataDir: string; auth?: unknown }) => unknown
    default?:           { createResolverApp?: (opts: { dataDir: string; auth?: unknown }) => unknown }
  })
  const create = factory.createResolverApp ?? factory.default?.createResolverApp
  if (!create) throw new Error('@synoi/oid-resolver does not export createResolverApp')
  const app = create({ dataDir })
  const { createServer } = await import('node:http')
  const server = createServer(app as unknown as Parameters<typeof createServer>[1])
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  const url  = `http://127.0.0.1:${port}`
  try {
    return await runProtocol({
      protocol:     'oid-resolver',
      resolverUrl:  url,
      resolverAuth: 'Bearer seed-gen-bearer',
      reporter:     new SilentReporter(),
      vectorsDir:   join(process.cwd(), 'vectors', 'oid-resolver'),
    })
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
}

async function runCitedOracleReport(): Promise<RunReport> {
  return runProtocol({
    protocol: 'cited-oracle-inputs',
    reporter: new SilentReporter(),
  })
}

async function main(): Promise<void> {
  const outPath = process.argv[2] ?? join(process.cwd(), 'seed-conformant-projects.json')

  // One conformance pass across SynOI's own reference stack - gap, sraid,
  // resolver - reported as ONE project entry ("SynOI reference stack")
  // since they share one manifest/repo grouping (this monorepo family), plus
  // the cited_oracle_inputs pass which today includes known PENDING-S1.1
  // vectors and therefore correctly caps the tier below L4 until S1.1 ships.
  //
  // oid-resolver is run best-effort: it boots @synoi/oid-resolver's native
  // better-sqlite3 binding in-process, which can fail with an ABI mismatch
  // in environments where that sibling repo's node_modules were built
  // against a different Node version (a known, pre-existing environment
  // issue, not something this generator can fix). If it fails, the tier
  // computation honestly reflects that oid-resolver did not run (never-run
  // does not count as passing - see badge.ts computeTier), rather than
  // crashing the whole seed-list generation.
  let resolverReport: RunReport
  try {
    resolverReport = await runResolverReport()
  } catch (err) {
    process.stderr.write(`[gen-seed-list] WARNING: oid-resolver conformance pass failed to run (${(err as Error).message.split('\n')[0]}); excluded from this seed list run, tier capped accordingly\n`)
    resolverReport = { protocol: 'oid-resolver', protocol_status: 'conformant', vectors_run: 0, passed: 0, failed: 0, not_executable: 0, stubbed: 0, failures: [], not_executables: [], stubs: [] }
  }

  const reports: RunReport[] = [
    await runSraidReport(),
    await runGapReport(),
    resolverReport,
    await runCitedOracleReport(),
  ]

  const referenceStackEntry: ConformantProjectEntry = buildProjectEntry(
    { project: 'SynOI reference stack (@synoi/sraid + @synoi/gap + @synoi/oid-resolver)', repo_url: 'https://github.com/synoi/synoi-conformance' },
    reports,
  )

  // The 15 shipped MCP shims share one conformance posture today: they run
  // GAP-governed actions via the gateway's gate() path but do not yet ship
  // their own standalone conformance harness entry in this repo. Listing
  // them individually with a fabricated tier would violate CLAIMS_DISCIPLINE
  // (no vector, no claim). They are seeded honestly as PENDING until each
  // ships a manifest + verifiable run of its own.
  const shims = [
    'synoi-mcp-shim-aws-iam', 'synoi-mcp-shim-circleci', 'synoi-mcp-shim-crowdstrike',
    'synoi-mcp-shim-datadog', 'synoi-mcp-shim-email', 'synoi-mcp-shim-filesystem',
    'synoi-mcp-shim-github', 'synoi-mcp-shim-github-octokit', 'synoi-mcp-shim-gitlab',
    'synoi-mcp-shim-jira', 'synoi-mcp-shim-kubernetes', 'synoi-mcp-shim-launchdarkly',
    'synoi-mcp-shim-linear', 'synoi-mcp-shim-notion', 'synoi-mcp-shim-okta',
    'synoi-mcp-shim-postgres', 'synoi-mcp-shim-salesforce', 'synoi-mcp-shim-sentry',
    'synoi-mcp-shim-servicenow', 'synoi-mcp-shim-slack', 'synoi-mcp-shim-slack-webapi',
    'synoi-mcp-shim-stripe', 'synoi-mcp-shim-terraform',
  ]

  const seedList = {
    schema:       'synoi.conformance.seed-list/v1',
    generated_at: new Date().toISOString(),
    conformant: [referenceStackEntry],
    pending: shims.map(name => ({
      project:  name,
      repo_url: `https://github.com/synoi/${name}`,
      reason:   'PENDING: no conformance manifest committed yet (see CONTRIBUTING for how to earn a badge)',
    })),
  }

  writeFileSync(outPath, JSON.stringify(seedList, null, 2) + '\n', 'utf8')
  process.stdout.write(`[gen-seed-list] wrote ${outPath}\n`)
  process.stdout.write(`[gen-seed-list] reference stack tier: L${referenceStackEntry.tier} (${referenceStackEntry.vectors_passed}/${referenceStackEntry.vectors_total} vectors)\n`)
  process.stdout.write(`[gen-seed-list] pending shims: ${shims.length}\n`)
}

void main().catch(err => {
  process.stderr.write(`gen-seed-list: ${(err as Error).stack}\n`)
  process.exit(1)
})
