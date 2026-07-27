// completeness-spine-conformance.test.ts
//
// Language-neutral conformance proof for the population-completeness spine
// (build1-completeness-witnessing, P3). The spine is an ordered hash-chain
// PLUS an RFC 6962 Merkle root over the receipted population, in Journal order.
//
// Format freezes proven here (irreversible once the first root is witnessed):
//   ADR_023 D1 (FORK-B): the Merkle leaf preimage is the 64-char hex OID
//     STRING, i.e. leafHash(utf8(oid_hex_64)). It is NOT the raw 32 digest
//     bytes. The d1_negative control proves the raw-byte variant yields a
//     different, non-conformant root.
//   ADR_023 D2 (FORK-A): the root uses ordered RFC 6962 construction ONLY,
//     never a sorted-and-deduped tree. The d2_negative control proves sorting
//     the leaves yields a different, non-conformant root.
//
// This test depends on node:crypto ONLY. It reproduces every pinned value in
// vectors/completeness-spine/spine.json from ordered_oids alone, so any
// reimplementation in any language proves agreement the same way. If the
// gateway's src/completeness/engine.ts spine ever drifts from these bytes, a
// previously-witnessed inclusion proof would silently fail an independent
// Rekor check; this vector fails loudly instead.
//
// No em dashes.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'

const LEAF_PREFIX     = Buffer.from([0x00])
const INTERNAL_PREFIX = Buffer.from([0x01])

// ADR_023 D1: hash the hex STRING (utf-8), not the raw digest bytes.
function leafHash(oidHex: string): Buffer {
  return createHash('sha256').update(LEAF_PREFIX).update(Buffer.from(oidHex, 'utf-8')).digest()
}
function internalHash(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(INTERNAL_PREFIX).update(left).update(right).digest()
}
function largestPow2LessThan(n: number): number { let k = 1; while (k * 2 < n) k *= 2; return k }

// ADR_023 D2: ordered RFC 6962 MTH. No sorting, no dedup.
function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return createHash('sha256').update(Buffer.alloc(0)).digest()
  if (leaves.length === 1) return leaves[0]!
  const k = largestPow2LessThan(leaves.length)
  return internalHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)))
}

const GENESIS = createHash('sha256').update('SYNOI-COMPLETENESS-SPINE-v1').digest('hex')

function chainSteps(oids: string[]): string[] {
  const steps: string[] = []
  let prev = GENESIS
  for (const o of oids) {
    prev = createHash('sha256').update(`${prev}|${o}`).digest('hex')
    steps.push(prev)
  }
  return steps
}
function chainHead(oids: string[]): string {
  const steps = chainSteps(oids)
  return steps.length === 0 ? GENESIS : steps[steps.length - 1]!
}
function rootHex(oids: string[]): string { return merkleRoot(oids.map(leafHash)).toString('hex') }

interface SpineCase {
  name: string
  ordered_oids: string[]
  expected: {
    size: number
    root_sha256: string
    genesis_hash: string
    head_hash: string
    first_divergent_chain_index_vs_baseline?: number
  }
  d1_negative?: { root_if_raw_bytes_hashed: string }
  d2_negative?: { root_if_leaves_sorted: string }
}
interface SpineVector { kind: string; constants: Record<string, string>; cases: SpineCase[] }

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

const vectorsPath = join(process.cwd(), 'vectors', 'completeness-spine', 'spine.json')
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8')) as SpineVector

ok('completeness-spine: loaded a non-empty case set', vector.cases.length > 0, `count=${vector.cases.length}`)
ok('completeness-spine: genesis constant matches sha256("SYNOI-COMPLETENESS-SPINE-v1")',
   vector.constants['chain_genesis_hash'] === GENESIS,
   `pinned=${vector.constants['chain_genesis_hash']} computed=${GENESIS}`)

const byName = new Map(vector.cases.map(c => [c.name, c]))

for (const c of vector.cases) {
  const size = c.ordered_oids.length
  const root = rootHex(c.ordered_oids)
  const head = chainHead(c.ordered_oids)

  ok(`[${c.name}] size == ordered_oids.length`, size === c.expected.size, `got ${size} expected ${c.expected.size}`)
  ok(`[${c.name}] root_sha256 reproduces pinned value`, root === c.expected.root_sha256, `got ${root} expected ${c.expected.root_sha256}`)
  ok(`[${c.name}] head_hash reproduces pinned value`, head === c.expected.head_hash, `got ${head} expected ${c.expected.head_hash}`)
  ok(`[${c.name}] genesis_hash is the domain-separated completeness genesis`, c.expected.genesis_hash === GENESIS)
  ok(`[${c.name}] root_sha256 is bare 64-hex, no prefix`, /^[0-9a-f]{64}$/.test(c.expected.root_sha256))

  // D1 lock: raw-byte leaf variant must differ from the conformant root.
  if (c.d1_negative) {
    const rawVariant = merkleRoot(c.ordered_oids.map(o =>
      createHash('sha256').update(LEAF_PREFIX).update(Buffer.from(o, 'hex')).digest()
    )).toString('hex')
    ok(`[${c.name}] D1: raw-byte leaf variant reproduces the pinned negative`, rawVariant === c.d1_negative.root_if_raw_bytes_hashed,
       `got ${rawVariant}`)
    ok(`[${c.name}] D1: conformant root != raw-byte variant (leaf hashes the hex string)`, root !== rawVariant)
  }

  // D2 lock: sorted-leaf variant must differ from the conformant root.
  if (c.d2_negative) {
    const sorted = [...c.ordered_oids].sort()
    const sortedVariant = rootHex(sorted)
    ok(`[${c.name}] D2: sorted-leaf variant reproduces the pinned negative`, sortedVariant === c.d2_negative.root_if_leaves_sorted,
       `got ${sortedVariant}`)
    ok(`[${c.name}] D2: conformant root != sorted variant (ordered RFC 6962 only)`, root !== sortedVariant)
    ok(`[${c.name}] D2: Journal order genuinely differs from sorted order`,
       JSON.stringify(c.ordered_oids) !== JSON.stringify(sorted))
  }
}

// Interior-tamper coupling: mutating the middle leaf breaks both the root and
// the chain, and the chain first diverges at the tampered index.
{
  const base = byName.get('interior_tamper_baseline')
  const mut  = byName.get('interior_tamper_mutated')
  ok('interior_tamper: both baseline and mutated cases present', !!base && !!mut)
  if (base && mut) {
    ok('interior_tamper: root changes when the middle leaf is tampered',
       base.expected.root_sha256 !== mut.expected.root_sha256)
    ok('interior_tamper: head_hash changes when the middle leaf is tampered',
       base.expected.head_hash !== mut.expected.head_hash)
    const baseSteps = chainSteps(base.ordered_oids)
    const mutSteps  = chainSteps(mut.ordered_oids)
    let firstDiv = -1
    for (let i = 0; i < baseSteps.length; i++) { if (baseSteps[i] !== mutSteps[i]) { firstDiv = i; break } }
    ok('interior_tamper: chain first diverges at index 1 (the middle of 3)', firstDiv === 1, `got ${firstDiv}`)
    ok('interior_tamper: pinned first_divergent_chain_index matches computed',
       mut.expected.first_divergent_chain_index_vs_baseline === firstDiv,
       `pinned=${mut.expected.first_divergent_chain_index_vs_baseline} computed=${firstDiv}`)
  }
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
