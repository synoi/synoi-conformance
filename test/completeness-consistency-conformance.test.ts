// completeness-consistency-conformance.test.ts
//
// Language-neutral conformance proof for RFC 6962 section 2.1.2 consistency
// proofs over the population-completeness receipt tree
// (build1-completeness-witnessing, P5). A consistency proof between tree sizes
// m < n proves tree(m) is a leaf-prefix of tree(n): the first m leaves are
// unchanged, unreordered, unremoved, and growth was append-only at the tail.
//
// Verification is the RFC 9162 section 2.1.4.2 iterative algorithm (byte-
// identical to certificate-transparency-go / Trillian VerifyConsistencyProof).
//
// Two independent anchors:
//   1. rfc6962_reference: the canonical CT reference 8-leaf tree (raw-byte
//      leaves). Every MTH root is cross-checked against the hardcoded published
//      RFC 6962 reference constants below, and every published consistency proof
//      reproduces and verifies. This proves byte-for-byte agreement with
//      sigstore Rekor / Trillian, independent of the vector file.
//   2. synoi_completeness: leaves follow ADR_023 D1 (leafHash of the 64-char hex
//      OID STRING). Covers a valid append-only extension (accept), a power-of-
//      two prior (proof omits the prior root), and rewritten / reordered /
//      mutated / truncated histories (reject).
//
// HONESTY BOUNDARY: a consistency proof establishes ONLY the append-only
// structural relation between two roots. It does not prove the leaves are
// complete or honest, does not catch back-dating into the still-unwitnessed tail
// (indices m..n), and does not anchor either root to a public log.
//
// Depends on node:crypto ONLY. Reproduces every pinned value from the ordered
// inputs alone, so any reimplementation proves agreement the same way.
//
// No em dashes.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'

const LEAF_PREFIX     = Buffer.from([0x00])
const INTERNAL_PREFIX = Buffer.from([0x01])

const leafRaw = (buf: Buffer): Buffer =>
  createHash('sha256').update(LEAF_PREFIX).update(buf).digest()
// ADR_023 D1: hash the hex STRING (utf-8), not the raw digest bytes.
const leafHexStr = (oidHex: string): Buffer => leafRaw(Buffer.from(oidHex, 'utf-8'))
const internalHash = (l: Buffer, r: Buffer): Buffer =>
  createHash('sha256').update(INTERNAL_PREFIX).update(l).update(r).digest()
function largestPow2LessThan(n: number): number { let k = 1; while (k * 2 < n) k *= 2; return k }

function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return createHash('sha256').update(Buffer.alloc(0)).digest()
  if (leaves.length === 1) return leaves[0]!
  const k = largestPow2LessThan(leaves.length)
  return internalHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)))
}

// RFC 6962 section 2.1.2 PROOF(m, D[n]) = SUBPROOF(m, D[n], true).
function consistencyProof(leaves: Buffer[], m: number): Buffer[] {
  const n = leaves.length
  if (m < 0 || m > n) throw new RangeError('m out of range')
  if (m === 0 || m === n) return []
  return subProof(m, leaves, true)
}
function subProof(m: number, D: Buffer[], b: boolean): Buffer[] {
  const n = D.length
  if (m === n) return b ? [] : [merkleRoot(D)]
  const k = largestPow2LessThan(n)
  if (m <= k) return [...subProof(m, D.slice(0, k), b), merkleRoot(D.slice(k))]
  return [...subProof(m - k, D.slice(k), false), merkleRoot(D.slice(0, k))]
}

// RFC 9162 section 2.1.4.2 verification. Fail-closed on every structural fault.
function verifyConsistency(m: number, rootM: Buffer, n: number, rootN: Buffer, proof: Buffer[]): boolean {
  if (!Number.isInteger(m) || !Number.isInteger(n)) return false
  if (m < 0 || n < 0) return false
  if (m > n) return false
  if (m === n) return proof.length === 0 && rootM.equals(rootN)
  if (m === 0) return proof.length === 0
  if (proof.length === 0) return false
  let node = m - 1, last = n - 1
  while (node % 2 === 1) { node = Math.floor(node / 2); last = Math.floor(last / 2) }
  let idx = 0, h1: Buffer, h2: Buffer
  if (node > 0) { h1 = proof[idx]!; h2 = proof[idx]!; idx++ } else { h1 = rootM; h2 = rootM }
  while (node > 0) {
    if (idx >= proof.length) return false
    if (node % 2 === 1) { h1 = internalHash(proof[idx]!, h1); h2 = internalHash(proof[idx]!, h2); idx++ }
    else if (node < last) { h2 = internalHash(h2, proof[idx]!); idx++ }
    node = Math.floor(node / 2); last = Math.floor(last / 2)
  }
  if (!h1.equals(rootM)) return false
  while (last > 0) { if (idx >= proof.length) return false; h2 = internalHash(h2, proof[idx]!); idx++; last = Math.floor(last / 2) }
  if (!h2.equals(rootN)) return false
  return idx === proof.length
}
const hex = (b: Buffer): string => b.toString('hex')
const toBufs = (hexes: string[]): Buffer[] => hexes.map(h => Buffer.from(h, 'hex'))

// Hardcoded EXTERNAL ground truth: the published RFC 6962 reference roots.
// These are independent of the vector file; if our construction drifts from the
// standard, these fail loudly.
const CANONICAL_RFC_ROOTS: Record<string, string> = {
  '1': '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  '2': 'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  '3': 'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  '4': 'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '5': '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '6': '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  '7': 'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '8': '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
}

interface RfcProof { m: number; n: number; proof: string[]; verify: boolean }
interface SynCase {
  name: string
  note: string
  prior_ordered_oids: string[]
  current_ordered_oids: string[]
  prior_tree_size: number
  expected: {
    prior_root_sha256: string
    current_root_sha256: string
    consistency_proof: string[]
    current_prefix_root_sha256: string
    verify: boolean
  }
}
interface Vector {
  kind: string
  constants: Record<string, string>
  rfc6962_reference: { leaf_inputs_hex: string[]; roots: Record<string, string>; proofs: RfcProof[] }
  synoi_completeness: { cases: SynCase[] }
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

const vectorsPath = join(process.cwd(), 'vectors', 'completeness-consistency', 'consistency.json')
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8')) as Vector

ok('consistency: kind is completeness_consistency_v1', vector.kind === 'completeness_consistency_v1')

// ── RFC 6962 reference anchor ────────────────────────────────────────────────
{
  const inputs = vector.rfc6962_reference.leaf_inputs_hex
  const leaves = inputs.map(h => leafRaw(Buffer.from(h, 'hex')))
  ok('rfc6962: reference tree has 8 leaves', leaves.length === 8)

  for (let s = 1; s <= 8; s++) {
    const root = hex(merkleRoot(leaves.slice(0, s)))
    ok(`rfc6962: MTH(size ${s}) reproduces the pinned vector root`,
       root === vector.rfc6962_reference.roots[String(s)],
       `got ${root} pinned ${vector.rfc6962_reference.roots[String(s)]}`)
    ok(`rfc6962: MTH(size ${s}) matches the canonical published RFC 6962 root`,
       root === CANONICAL_RFC_ROOTS[String(s)],
       `got ${root} canonical ${CANONICAL_RFC_ROOTS[String(s)]}`)
  }

  const rfcRoot = (s: number) => merkleRoot(leaves.slice(0, s))
  for (const rp of vector.rfc6962_reference.proofs) {
    const gen = consistencyProof(leaves.slice(0, rp.n), rp.m).map(hex)
    ok(`rfc6962: consistency(${rp.m},${rp.n}) generated proof reproduces the pinned path`,
       JSON.stringify(gen) === JSON.stringify(rp.proof), `got ${JSON.stringify(gen)}`)
    ok(`rfc6962: consistency(${rp.m},${rp.n}) verifies (pinned verify=${rp.verify})`,
       verifyConsistency(rp.m, rfcRoot(rp.m), rp.n, rfcRoot(rp.n), toBufs(rp.proof)) === rp.verify)
    // A valid proof must not verify against a wrong target root.
    const wrongN = rp.n === 8 ? 7 : 8
    ok(`rfc6962: consistency(${rp.m},${rp.n}) REJECTS a wrong current root (size ${wrongN})`,
       !verifyConsistency(rp.m, rfcRoot(rp.m), rp.n, rfcRoot(wrongN), toBufs(rp.proof)))
  }

  // m = power of two (4,8): the proof omits the prior root (single node).
  const p48 = vector.rfc6962_reference.proofs.find(p => p.m === 4 && p.n === 8)
  ok('rfc6962: m=power-of-two case (4,8) present', !!p48)
  if (p48) {
    ok('rfc6962: (4,8) proof omits the prior root (length 1)', p48.proof.length === 1)
    ok('rfc6962: (4,8) first proof node is NOT rootM',
       p48.proof[0] !== CANONICAL_RFC_ROOTS['4'])
  }
}

// ── SynOI completeness cases (ADR_023 D1 hex-string leaves) ──────────────────
{
  // D1 lock: the hex-string leaf differs from the raw-byte leaf for the same oid.
  const sampleOid = 'a'.repeat(64)
  ok('synoi: D1 hex-string leaf != raw-byte leaf (ADR_023 D1 FORK-B)',
     !leafHexStr(sampleOid).equals(leafRaw(Buffer.from(sampleOid, 'hex'))))

  for (const c of vector.synoi_completeness.cases) {
    const priorLeaves = c.prior_ordered_oids.map(leafHexStr)
    const curLeaves = c.current_ordered_oids.map(leafHexStr)
    const m = c.prior_tree_size
    ok(`[${c.name}] prior_tree_size == prior_ordered_oids.length`, m === c.prior_ordered_oids.length)

    const priorRoot = hex(merkleRoot(priorLeaves))
    const curRoot = hex(merkleRoot(curLeaves))
    const prefixRoot = hex(merkleRoot(curLeaves.slice(0, m)))
    ok(`[${c.name}] prior_root_sha256 reproduces from prior_ordered_oids`,
       priorRoot === c.expected.prior_root_sha256, `got ${priorRoot}`)
    ok(`[${c.name}] current_root_sha256 reproduces from current_ordered_oids`,
       curRoot === c.expected.current_root_sha256, `got ${curRoot}`)
    ok(`[${c.name}] current_prefix_root reproduces`,
       prefixRoot === c.expected.current_prefix_root_sha256, `got ${prefixRoot}`)

    const gen = consistencyProof(curLeaves, m).map(hex)
    ok(`[${c.name}] consistency_proof reproduces from current tree`,
       JSON.stringify(gen) === JSON.stringify(c.expected.consistency_proof), `got ${JSON.stringify(gen)}`)

    // Verify the proof against the HONEST prior root and the current root.
    const v = verifyConsistency(
      m, merkleRoot(priorLeaves),
      c.current_ordered_oids.length, merkleRoot(curLeaves),
      toBufs(c.expected.consistency_proof),
    )
    ok(`[${c.name}] verify against honest prior root == pinned expected (${c.expected.verify})`,
       v === c.expected.verify, `got ${v}`)

    if (c.expected.verify) {
      ok(`[${c.name}] ACCEPT case: current prefix root equals prior root (append-only)`,
         prefixRoot === priorRoot)
    } else {
      ok(`[${c.name}] REJECT case: current prefix root differs from prior root (history rewritten)`,
         prefixRoot !== priorRoot)
    }
  }

  const names = vector.synoi_completeness.cases.map(c => c.name)
  ok('synoi: covers at least one accepting extension',
     vector.synoi_completeness.cases.some(c => c.expected.verify))
  ok('synoi: covers a reordered-history reject', names.includes('reordered_prefix_reject'))
  ok('synoi: covers a mutated-history reject', names.includes('mutated_prefix_reject'))
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
