// witness-stub-rejection-conformance.test.ts
//
// Language-neutral conformance proof that a STUB witness proof is REJECTED,
// offline, by the real Rekor inclusion verifier, while a genuine Rekor entry is
// NOT (build1-completeness-witnessing, P6c; the real inclusion verifier is P6a).
//
// Surface frozen here:
//   Rejection predicate (applied BEFORE any network fetch): a proof is rejected
//     when ANY of
//       - witness_kind != "rekor"
//       - uuid startsWith "stub:"
//       - server startsWith "stub://"
//     The rejected result is status "proof-invalid", verified false. proof-invalid
//     (not "unverified"): a stub proof reaching the real verifier is an
//     injection/integrity event and must read loud.
//   Non-emittability: the stub sentinels are values a real Rekor server can never
//     produce. Real Rekor uuids are 64/80-char hex; real servers are https. So a
//     stub proof (even one relabeled witness_kind:"rekor") can never be confused
//     with a genuine one, and the relabel is still caught by the uuid/server
//     sentinels.
//   Genuine acceptance: a real entry passes the guard AND its Rekor inclusion
//     proof folds (RFC 6962: leaf = SHA256(0x00||body), node = SHA256(0x01||L||R),
//     tree-local index) back to the checkpoint rootHash. A stub carries no
//     inclusion proof, so it is structurally incapable of passing the real
//     verifier even if the guard were bypassed.
//
// Reproduces every pinned value from vectors/witness-stub-rejection/rejection.json
// using node:crypto ONLY, so any reimplementation in any language proves agreement
// the same way.
//
// No em dashes.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'

const LEAF_PREFIX = Buffer.from([0x00])
const INTERNAL_PREFIX = Buffer.from([0x01])

let passed = 0
let failed = 0
function ok(label: string, cond: boolean): void {
  if (cond) { console.log('  ok  ', label); passed++ }
  else { console.error('  FAIL', label); failed++ }
}

// ── the frozen rejection predicate (independent reimplementation) ────────────
function isRejectedOffline(proof: { witness_kind: string; uuid: string | null; server: string | null }): boolean {
  return (
    proof.witness_kind !== 'rekor' ||
    (proof.uuid ?? '').startsWith('stub:') ||
    (proof.server ?? '').startsWith('stub://')
  )
}

// ── RFC 6962 inclusion fold (tree-local index), leaf = SHA256(0x00||body) ────
function leafHash(bodyBytes: Buffer): Buffer {
  return createHash('sha256').update(LEAF_PREFIX).update(bodyBytes).digest()
}
function nodeHash(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(INTERNAL_PREFIX).update(left).update(right).digest()
}
function foldInclusion(
  leafIndex: number,
  treeSize: number,
  leaf: Buffer,
  auditPath: Buffer[],
): string | null {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return null
  if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) return null
  let fn = leafIndex
  let sn = treeSize - 1
  let r = leaf
  for (const p of auditPath) {
    if (sn === 0) return null // path too long
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r)
      if ((fn & 1) === 0) {
        do { fn >>= 1; sn >>= 1 } while ((fn & 1) === 0 && fn !== 0)
      }
    } else {
      r = nodeHash(r, p)
    }
    fn >>= 1
    sn >>= 1
  }
  if (sn !== 0) return null // path too short
  return r.toString('hex')
}

const HEX_UUID = /^[0-9a-f]{64,80}$/i

interface Vector {
  vector: string
  rejection_predicate: { rejected_status: string; rejected_verified: boolean }
  cases: Array<{
    name: string
    proof: {
      witness_kind: string
      server: string | null
      uuid: string | null
      body_b64: string | null
      anchored_root_hex: string
      inclusion_proof: { log_index: number; tree_size: number; root_hash_hex: string; hashes_hex: string[] } | null
    }
    expected_rejected_offline: boolean
    expected_inclusion_reproduces_root?: boolean
    expected_status?: string
    expected_verified?: boolean
  }>
}

const vectorPath = join(process.cwd(), 'vectors', 'witness-stub-rejection', 'rejection.json')
const vector = JSON.parse(readFileSync(vectorPath, 'utf-8')) as Vector

console.log(`\nwitness-stub-rejection conformance (${vector.cases.length} cases)`)
ok('vector is the witness-stub-rejection vector', vector.vector === 'witness-stub-rejection')
ok('rejected status is proof-invalid (loud, not a quiet unverified)',
   vector.rejection_predicate.rejected_status === 'proof-invalid' &&
   vector.rejection_predicate.rejected_verified === false)

for (const c of vector.cases) {
  const rej = isRejectedOffline(c.proof)
  ok(`[${c.name}] rejection predicate matches vector`, rej === c.expected_rejected_offline)

  if (c.expected_rejected_offline) {
    // A rejected proof carries at least one stub sentinel or a non-rekor kind, and
    // has NO inclusion proof, so it is structurally incapable of verifying.
    const carriesSentinel =
      (c.proof.uuid ?? '').startsWith('stub:') || (c.proof.server ?? '').startsWith('stub://')
    ok(`[${c.name}] rejected proof carries a stub sentinel (non-emittable by real Rekor)`, carriesSentinel)
    ok(`[${c.name}] rejected proof has no inclusion proof to fold`, c.proof.inclusion_proof === null)
    // The stub uuid is NOT a real Rekor uuid shape.
    ok(`[${c.name}] stub uuid is not a real hex Rekor uuid`, !HEX_UUID.test(c.proof.uuid ?? ''))
  } else {
    // Genuine: guard passes it through, and its inclusion proof folds to rootHash.
    ok(`[${c.name}] genuine proof carries an inclusion proof`, c.proof.inclusion_proof !== null)
    const ip = c.proof.inclusion_proof!
    const body = Buffer.from(c.proof.body_b64!, 'base64')
    const computed = foldInclusion(
      ip.log_index,
      ip.tree_size,
      leafHash(body),
      ip.hashes_hex.map(h => Buffer.from(h, 'hex')),
    )
    ok(`[${c.name}] RFC 6962 inclusion folds to the checkpoint rootHash (real verifier accepts)`,
       computed !== null && computed.toLowerCase() === ip.root_hash_hex.toLowerCase())
    ok(`[${c.name}] genuine uuid IS a real hex Rekor uuid`, HEX_UUID.test(c.proof.uuid ?? ''))
    ok(`[${c.name}] genuine server is https, not a stub sentinel`,
       (c.proof.server ?? '').startsWith('https://') && !(c.proof.server ?? '').startsWith('stub://'))
    if (c.expected_inclusion_reproduces_root !== undefined) {
      ok(`[${c.name}] inclusion reproduction matches the vector's expectation`,
         (computed !== null && computed.toLowerCase() === ip.root_hash_hex.toLowerCase()) === c.expected_inclusion_reproduces_root)
    }
  }
}

// A stub relabeled witness_kind:"rekor" must still be caught: at least one case
// proves the sentinels alone (independent of kind) are load-bearing.
const relabeled = vector.cases.find(c => c.proof.witness_kind === 'rekor' && c.expected_rejected_offline)
ok('a relabeled stub (witness_kind:rekor) is present and still rejected by the sentinels',
   relabeled !== undefined && isRejectedOffline(relabeled.proof) === true)

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
