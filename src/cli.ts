#!/usr/bin/env node
// cli.ts - synoi-conformance entry. Spec made executable.
//
//   synoi-conformance --protocol=sraid --impl=./my-sraid.js
//   synoi-conformance --protocol=gap --impl=./my-gap.js
//   synoi-conformance --protocol=oid-resolver --url=http://localhost:4000 --auth="Bearer X"
//   synoi-conformance --all --impl-dir=./impls/
//   synoi-conformance --reporter=json
//   synoi-conformance --help

import { writeFileSync } from 'node:fs'
import { runProtocol } from './runner.js'
import { makeReporter } from './reporter.js'
import { buildBadgeSvg } from './badge.js'
import type { Protocol, RunReport } from './types.js'

const HELP = `synoi-conformance - run the conformance suite against any implementation.

Usage:
  synoi-conformance --protocol=<protocol> [--impl=<path>] [--url=<url>] [--auth=<value>]
                    [--reporter=text|json] [--vectors-dir=<dir>]
  synoi-conformance --all --impl-dir=<dir> [--resolver-url=<url>]
  synoi-conformance --help

Protocols:
  sraid            SRAID L0 (wire protocol id 'sraid') - canonicalize, oidOf, verifySignature
  gap              GAP (Governed Action Protocol) - type validators + computeGapOid
  oid-resolver     OID Resolver - HTTP endpoints
  inference-broker (stub - vectors run against @synoi/broker but the protocol carries
                    no DSSE-signed hybrid-verified receipts yet; excluded from the badge)

Options:
  --protocol=<p>      Required (unless --all). One of the protocols above.
  --impl=<path>       JS module path for SRAID/GAP candidate. Bare specifiers
                       like '@synoi/sraid' are accepted.
  --url=<url>         OID Resolver URL (e.g. http://localhost:4000).
  --auth=<value>      Raw Authorization header to send on Resolver writes.
  --reporter=text|json  Default: text. JSON output is single-document for CI.
  --vectors-dir=<dir> Override the built-in vectors location.
  --all               Run every protocol (best-effort; needs --impl-dir).
  --impl-dir=<dir>    Directory holding sraid.js + gap.js + resolver-url config.
  --resolver-url=<url>  Used with --all to point at the candidate Resolver.
  --badge-svg=<path>  Write a "SynOI GAP Conformant - L<tier>" SVG badge to
                       this path, computed from the actual run's results.
  --badge-json=<path> Write the tier computation (tier, badge, qualifying
                       protocols) as JSON to this path.

Exit code:
  0 on full pass, 1 on any failure or usage error.
`

interface Args {
  protocol?:    string
  impl?:        string
  url?:         string
  auth?:        string
  reporter?:    string
  vectorsDir?:  string
  all?:         boolean
  implDir?:     string
  resolverUrl?: string
  help?:        boolean
  badgeSvg?:    string
  badgeJson?:   string
}

function parseArgs(argv: string[]): Args {
  const out: Args = {}
  for (const a of argv) {
    if (a === '--help' || a === '-h')                       { out.help = true; continue }
    if (a === '--all')                                       { out.all  = true; continue }
    const m = a.match(/^--([a-z-]+)=(.*)$/)
    if (!m) continue
    const k = m[1]!, v = m[2]!
    switch (k) {
      case 'protocol':     out.protocol    = v; break
      case 'impl':         out.impl        = v; break
      case 'url':          out.url         = v; break
      case 'auth':         out.auth        = v; break
      case 'reporter':     out.reporter    = v; break
      case 'vectors-dir':  out.vectorsDir  = v; break
      case 'impl-dir':     out.implDir     = v; break
      case 'resolver-url': out.resolverUrl = v; break
      case 'badge-svg':    out.badgeSvg    = v; break
      case 'badge-json':   out.badgeJson   = v; break
    }
  }
  return out
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) { process.stdout.write(HELP); return 0 }

  const reporterKind = args.reporter === 'json' ? 'json' : 'text'
  const reporter = makeReporter(reporterKind)
  const reports: RunReport[] = []

  if (args.all) {
    if (!args.implDir) {
      process.stderr.write('--all requires --impl-dir\n'); return 1
    }
    const sraidPath = `${args.implDir}/sraid.js`
    const gapPath   = `${args.implDir}/gap.js`
    reports.push(await runProtocol({ protocol: 'sraid', implPath: sraidPath, reporter }))
    reports.push(await runProtocol({ protocol: 'gap',   implPath: gapPath, reporter }))
    if (args.resolverUrl) {
      const baseInput: Parameters<typeof runProtocol>[0] = {
        protocol: 'oid-resolver', resolverUrl: args.resolverUrl, reporter,
      }
      if (args.auth) baseInput.resolverAuth = args.auth
      reports.push(await runProtocol(baseInput))
    }
    reports.push(await runProtocol({ protocol: 'inference-broker', reporter }))
    writeBadgeOutputs(reports, args)
    return reporter.finish(reports)
  }

  if (!args.protocol) {
    process.stderr.write(HELP); return 1
  }
  const allowed: Protocol[] = ['sraid', 'gap', 'oid-resolver', 'inference-broker', 'cited-oracle-inputs', 'wasm-shell']
  if (!allowed.includes(args.protocol as Protocol)) {
    process.stderr.write(`unknown --protocol=${args.protocol}\n`); return 1
  }
  const input: Parameters<typeof runProtocol>[0] = {
    protocol: args.protocol as Protocol,
    reporter,
  }
  if (args.impl)        input.implPath     = args.impl
  if (args.url)         input.resolverUrl  = args.url
  if (args.auth)        input.resolverAuth = args.auth
  if (args.vectorsDir)  input.vectorsDir   = args.vectorsDir

  reports.push(await runProtocol(input))
  writeBadgeOutputs(reports, args)
  return reporter.finish(reports)
}

/**
 * Write --badge-svg / --badge-json outputs (if requested) from the actual
 * RunReport[] this invocation produced. Never derives the tier from
 * anything other than the reports just run - no manifest-claimed tier is
 * ever trusted here.
 */
function writeBadgeOutputs(reports: RunReport[], args: Args): void {
  if (!args.badgeSvg && !args.badgeJson) return
  const { svg, result } = buildBadgeSvg(reports)
  if (args.badgeSvg) {
    writeFileSync(args.badgeSvg, svg, 'utf8')
    process.stdout.write(`[synoi-conformance] wrote badge SVG (L${result.tier}) to ${args.badgeSvg}\n`)
  }
  if (args.badgeJson) {
    writeFileSync(args.badgeJson, JSON.stringify(result, null, 2) + '\n', 'utf8')
    process.stdout.write(`[synoi-conformance] wrote badge JSON (L${result.tier}) to ${args.badgeJson}\n`)
  }
}

void main().then(code => { process.exit(code) }).catch(err => {
  process.stderr.write(`synoi-conformance: ${(err as Error).message}\n`)
  process.exit(1)
})
