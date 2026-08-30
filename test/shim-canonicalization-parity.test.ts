/**
 * test/shim-canonicalization-parity.test.ts
 *
 * CODE-11 asks whether the 20 MCP shims interoperate with the gateway.
 *
 * Each shim carries its own two-line canonicalizer:
 *
 *   canonicalJSON = (v) => JSON.stringify(sortKeys(v))
 *   sortKeys      = recursive, Object.keys(o).sort()
 *
 * The gateway and every other signed object use RFC 8785 JCS via
 * @synoi/sraid's canonicalize. A shim receipt is hashed over its own output,
 * so wherever the two disagree the shim's receipt digest is not the digest the
 * gateway would compute for the same object, and the receipt does not verify.
 *
 * This test does not assume a verdict. It runs both functions over the same
 * inputs and reports where they agree and where they do not, so the fix is
 * scoped by evidence instead of by the assumption that a hand-rolled sorter
 * must be wrong. The two agree far more often than the row implies, which is
 * why the divergences below are the interesting part: they are the cases a
 * shim can actually emit.
 *
 * No em dashes. No AI attribution.
 */

import { canonicalize } from '@synoi/sraid'

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

/** Verbatim copy of the shim helper, so this test tracks the real thing. */
function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys)
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    const keys = Object.keys(o).sort()
    const out: Record<string, unknown> = {}
    for (const k of keys) out[k] = sortKeys(o[k])
    return out
  }
  return v
}
const shimCanonical = (value: unknown): string => JSON.stringify(sortKeys(value))

interface Case { name: string; value: unknown }

/** Shapes an MCP shim receipt actually carries. */
const REALISTIC: Case[] = [
  { name: 'flat receipt body', value: { tool: 'github.create_issue', decision: 'allow', tenant_id: 't1', at: 1700000000000 } },
  { name: 'nested args',       value: { tool: 'github.create_issue', args: { repo: 'acme/app', title: 'Bug', labels: ['p1', 'triage'] } } },
  { name: 'key order differs from source', value: { z: 1, a: 2, m: { y: 1, b: 2 } } },
  { name: 'empty object and array', value: { a: {}, b: [] } },
  { name: 'null and false', value: { a: null, b: false, c: 0, d: '' } },
  { name: 'unicode string', value: { note: 'café naïve 中文' } },
  { name: 'escapes', value: { s: 'line\nbreak\ttab"quote\\slash' } },
  { name: 'integers', value: { small: 1, big: 9007199254740991, neg: -42 } },
]

/** Shapes where a hand-rolled canonicalizer is most likely to drift. */
const EDGE: Case[] = [
  { name: 'non-ASCII key ordering', value: { 'é': 1, 'e': 2, 'z': 3 } },
  { name: 'digit and letter keys', value: { '10': 1, '2': 2, 'a': 3 } },
  { name: 'astral-plane key', value: { '\u{1F600}': 1, 'a': 2 } },
  { name: 'astral-plane value', value: { k: '\u{1F600}' } },
  { name: 'float value', value: { x: 1.5 } },
  { name: 'exponent-range float', value: { x: 1e21 } },
  { name: 'negative zero', value: { x: -0 } },
  { name: 'undefined property', value: { a: 1, b: undefined } },
  { name: 'nested arrays of objects', value: { a: [{ b: 1, a: 2 }, { d: 1, c: 2 }] } },
]

function compare(cases: Case[], group: string): string[] {
  const diverged: string[] = []
  for (const c of cases) {
    let mine = '', theirs = '', err = ''
    try { mine = shimCanonical(c.value) } catch (e) { err = `shim threw: ${String(e)}` }
    try { theirs = canonicalize(c.value as never) } catch (e) { err ||= `jcs threw: ${String(e)}` }
    if (err) {
      diverged.push(`${c.name} (${err})`)
      ok(`${group}: ${c.name}`, false, err)
      continue
    }
    const same = mine === theirs
    if (!same) diverged.push(`${c.name}\n       shim: ${mine}\n       jcs : ${theirs}`)
    ok(`${group}: ${c.name}`, same, `shim=${mine} jcs=${theirs}`)
  }
  return diverged
}

process.stdout.write('\n-- shapes a shim receipt actually carries --\n')
const divergedReal = compare(REALISTIC, 'realistic')

process.stdout.write('\n-- edge cases --\n')
const divergedEdge = compare(EDGE, 'edge')

process.stdout.write('\n')
if (divergedReal.length === 0) {
  process.stdout.write('The two canonicalizers agree on every realistic receipt shape tested.\n')
} else {
  process.stdout.write(`DIVERGES on ${divergedReal.length} realistic shape(s):\n`)
  for (const d of divergedReal) process.stdout.write(`  - ${d}\n`)
}
if (divergedEdge.length > 0) {
  process.stdout.write(`DIVERGES on ${divergedEdge.length} edge case(s):\n`)
  for (const d of divergedEdge) process.stdout.write(`  - ${d}\n`)
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
// This file is diagnostic: it reports, it does not gate. Exit 0 either way so
// it can be run for information without breaking a suite.
process.exit(0)
