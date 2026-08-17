// completeness-inclusion-conformance.test.ts
//
// Language-neutral conformance proof for the receipt-to-public-log inclusion
// composer (build1-completeness-witnessing, INC1). One synoi.inclusion.v1 bundle
// per receipt stitches LEG 1 (a local RFC 6962 audit path over receipt OIDs,
// folding to completeness root R) to LEG 2 (a Rekor inclusion proof over R).
//
// Surface frozen here (the half INC1 owns):
//   ADR_023 D1 (FORK-B): the Merkle leaf preimage is the 64-char hex OID STRING,
//     leafHash(utf8(oid_hex_64)), identical to the completeness-spine vector. The
//     d1_control proves the raw-byte variant does not fold to the same root.
//   RFC 6962 fold: current=leaf; for each bottom-up step, hash the sibling on the
//     side named by position; the bundle is local-valid iff current == root_sha256.
//   JOIN: local.root_sha256 MUST equal witness_root. A mismatch is 'root-mismatch'
//     and never 'verified' (the false-AUTHORIZE trap). A null witness_root yields
//     'not-yet-witnessed', never a false 'verified'.
//
// LEG 2's RFC 6962 inclusion math + C2SP checkpoint signature verification is
// frozen separately by the rekor-verify vector; this test does not re-embed a
// p256 checkpoint. It reproduces every pinned R and audit path from ordered_oids
// alone using node:crypto ONLY, so any reimplementation in any language proves
// agreement the same way.
//
// No em dashes.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'

const LEAF_PREFIX = Buffer.from([0x00])
const INTERNAL_PREFIX = Buffer.from([0x01])

// ADR_023 D1: hash the hex STRING (utf-8), not the raw digest bytes.
function leafHashString(oidHex: string): Buffer {
  return createHash('sha256').update(LEAF_PREFIX).update(Buffer.from(oidHex, 'utf-8')).digest()
}
// The rejected FORK-B control: hash the raw 32 digest bytes.
function leafHashRawBytes(oidHex: string): Buffer {
  return createHash('sha256').update(LEAF_PREFIX).update(Buffer.from(oidHex, 'hex')).digest()
}
function internalHash(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(INTERNAL_PREFIX).update(left).update(right).digest()
}
function largestPow2LessThan(n: number): number { let k = 1; while (k * 2 < n) k *= 2; return k }

function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return createHash('sha256').update(Buffer.alloc(0)).digest()
  if (leaves.length === 1) return leaves[0]!
  const k = largestPow2LessThan(leaves.length)
  return internalHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)))
}

interface Step { sibling: string; position: 'L' | 'R' }

// Independent RFC 6962 audit-path builder (bottom-up siblings).
function auditPath(leaves: Buffer[], m: number): Step[] {
  if (leaves.length === 1) return []
  const k = largestPow2LessThan(leaves.length)
  if (m < k) {
    const inner = auditPath(leaves.slice(0, k), m)
    inner.push({ sibling: merkleRoot(leaves.slice(k)).toString('hex'), position: 'R' })
    return inner
  }
  const inner = auditPath(leaves.slice(k), m - k)
  inner.push({ sibling: merkleRoot(leaves.slice(0, k)).toString('hex'), position: 'L' })
  return inner
}

// The fold the verifier runs: leaf + audit path -> reproduced root hex.
function foldPath(leaf: Buffer, path: Step[]): string {
  let current = leaf
  for (const step of path) {
    const sib = Buffer.from(step.sibling, 'hex')
    current = step.position === 'L' ? internalHash(sib, current) : internalHash(current, sib)
  }
  return current.toString('hex')
}

interface InclusionCase {
  name: string
  receipt_id: string
  oid_hex: string
  leaf_index: number
  tree_size: number
  ordered_oids: string[]
  local: { algorithm: string; audit_path: Step[]; root_sha256: string }
  witness_root: string | null
  d1_control?: { leaf_preimage_mode: string }
  expected: {
    local_folds_to_root: boolean
    local_folds_to_root_raw_byte_variant?: boolean
    join_ok: boolean | null
    terminal_status: string | null
    expected_verified: boolean
  }
}
interface InclusionVector { kind: string; constants: Record<string, string>; cases: InclusionCase[] }

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

// Reproduce the INC1 verifier's terminal decision over the leg-1 + join surface.
// LEG 2 (Rekor) is out of scope here (frozen by the rekor-verify vector); a
// join-passing, locally-valid, witnessed bundle returns null (defers to leg 2).
function terminalStatus(c: InclusionCase): string | null {
  const leaf = leafHashString(c.oid_hex)
  const folds = foldPath(leaf, c.local.audit_path) === c.local.root_sha256
  if (!folds) return 'local-invalid'
  if (c.witness_root === null) return 'not-yet-witnessed'
  if (c.local.root_sha256.toLowerCase() !== c.witness_root.toLowerCase()) return 'root-mismatch'
  return null
}

const vectorsPath = join(process.cwd(), 'vectors', 'completeness-inclusion', 'inclusion.json')
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8')) as InclusionVector

ok('completeness-inclusion: loaded a non-empty case set', vector.cases.length > 0, `count=${vector.cases.length}`)
ok('completeness-inclusion: schema constant is synoi.inclusion.v1', vector.constants['schema'] === 'synoi.inclusion.v1')

for (const c of vector.cases) {
  const leaves = c.ordered_oids.map(leafHashString)

  // 1. R reproduces from ordered_oids alone (ADR_023 D1 string preimage).
  const R = merkleRoot(leaves).toString('hex')
  ok(`[${c.name}] root_sha256 reproduces from ordered_oids`, R === c.local.root_sha256,
     `got ${R} expected ${c.local.root_sha256}`)
  ok(`[${c.name}] root_sha256 is bare 64-hex`, /^[0-9a-f]{64}$/.test(c.local.root_sha256))
  ok(`[${c.name}] tree_size === ordered_oids.length`, c.tree_size === c.ordered_oids.length)

  // 2. The pinned audit_path is exactly the one derived for leaf_index (only for
  //    cases that are meant to fold; tampered/control cases carry a doctored path).
  if (c.expected.local_folds_to_root && c.name !== 'd1_raw_byte_preimage_would_not_fold') {
    const derived = auditPath(leaves, c.leaf_index)
    ok(`[${c.name}] pinned audit_path === independently derived path`,
       JSON.stringify(derived) === JSON.stringify(c.local.audit_path),
       `derived ${JSON.stringify(derived)}`)
    ok(`[${c.name}] ordered_oids[leaf_index] === oid_hex`,
       c.ordered_oids[c.leaf_index] === c.oid_hex)
  }

  // 3. LEG 1 fold: leaf + audit_path -> root (string preimage).
  const foldsString = foldPath(leafHashString(c.oid_hex), c.local.audit_path) === c.local.root_sha256
  ok(`[${c.name}] local fold matches expected`, foldsString === c.expected.local_folds_to_root,
     `got ${foldsString} expected ${c.expected.local_folds_to_root}`)

  // 4. ADR_023 D1 control: raw-byte leaf variant must NOT fold to R.
  if (c.expected.local_folds_to_root_raw_byte_variant !== undefined) {
    const foldsRaw = foldPath(leafHashRawBytes(c.oid_hex), c.local.audit_path) === c.local.root_sha256
    ok(`[${c.name}] D1: raw-byte leaf variant does not fold to R`,
       foldsRaw === c.expected.local_folds_to_root_raw_byte_variant,
       `got ${foldsRaw}`)
    ok(`[${c.name}] D1: string preimage folds AND raw-byte does not (preimage is load-bearing)`,
       foldsString === true && foldsRaw === false)
  }

  // 5. JOIN + terminal status: reproduce the verifier's decision.
  const status = terminalStatus(c)
  ok(`[${c.name}] terminal status matches expected`, status === c.expected.terminal_status,
     `got ${status} expected ${c.expected.terminal_status}`)

  // 6. INVARIANT: a 'verified' result is never claimed by this vector; every case
  //    is expected_verified:false because leg 2 is out of scope here. Crucially the
  //    false-AUTHORIZE case (root-mismatch) and not-yet-witnessed are BOTH false.
  ok(`[${c.name}] expected_verified is false and never contradicts a failing status`,
     c.expected.expected_verified === false &&
     (status === null || status !== 'verified'))
}

// Cross-case: the false-AUTHORIZE guard. A locally-valid bundle whose witness_root
// differs from R must be root-mismatch, distinct from a well-joined bundle.
{
  const good = vector.cases.find(c => c.name === 'good_composed_index1')!
  const bad = vector.cases.find(c => c.name === 'join_root_mismatch_false_authorize')!
  ok('false-AUTHORIZE: good and mismatch share the same honest local half',
     JSON.stringify(good.local.audit_path) === JSON.stringify(bad.local.audit_path) &&
     good.local.root_sha256 === bad.local.root_sha256)
  ok('false-AUTHORIZE: only the witness_root differs', good.witness_root !== bad.witness_root)
  ok('false-AUTHORIZE: mismatch is root-mismatch, good defers to leg 2 (null)',
     terminalStatus(bad) === 'root-mismatch' && terminalStatus(good) === null)
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
