// anchor-digest-conformance.test.ts
//
// Language-neutral conformance proof for the anchor-batch digest discriminator.
//
// A SynOI gateway timestamps ONE of two preimages per Merkle batch:
//   'merkle_root'               -> the raw 32-byte RFC 6962 root
//   'countersign_bundle_sha256' -> SHA-256(utf8(synoi.canonical_bundle))
//
// The two values differ for the same batch, so a verifier that is not told
// which one was submitted has to guess and will reject a valid OpenTimestamps
// proof about half the time. This vector freezes the discriminator and the
// two honest non-recomputable states: 'unknown' (a batch predating the field)
// and 'no-timestamp' (nothing was ever submitted). An implementation must
// never collapse 'unknown' into either concrete kind.
//
// Reproduced here with node:crypto ONLY, so any reimplementation in any
// language proves agreement the same way.
//
// No em dashes.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'

type DigestKind = 'merkle_root' | 'countersign_bundle_sha256'
type Verdict = 'recomputable' | 'not-recomputable-unknown-preimage' | 'no-timestamp'

interface AnchorCase {
  name: string
  note: string
  batch: {
    batch_id: string
    merkle_root: string
    leaf_count: number
    ots_proof_present: boolean
    ots_digest_kind: DigestKind | null
    ots_digest_sha256: string | null
    synoi_canonical_bundle: string | null
  }
  expected: {
    verdict: Verdict
    recomputed_digest: string | null
    digest_equals_merkle_root: boolean | null
  }
}
interface AnchorVector { kind: string; constants: Record<string, string>; cases: AnchorCase[] }

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

function sha256Hex(s: string): string {
  return createHash('sha256').update(Buffer.from(s, 'utf-8')).digest('hex')
}

// The verifier's decision procedure, reimplemented from the constants alone.
function decide(b: AnchorCase['batch']): { verdict: Verdict; digest: string | null } {
  if (!b.ots_proof_present) return { verdict: 'no-timestamp', digest: null }
  if (b.ots_digest_kind === null) {
    return { verdict: 'not-recomputable-unknown-preimage', digest: null }
  }
  if (b.ots_digest_kind === 'merkle_root') {
    return { verdict: 'recomputable', digest: b.merkle_root.toLowerCase() }
  }
  if (b.synoi_canonical_bundle === null) {
    // A bundle-kind batch with no bundle stored cannot be recomputed either.
    return { verdict: 'not-recomputable-unknown-preimage', digest: null }
  }
  return { verdict: 'recomputable', digest: sha256Hex(b.synoi_canonical_bundle) }
}

const vectorsPath = join(process.cwd(), 'vectors', 'anchor-digest', 'anchor-digest.json')
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8')) as AnchorVector

ok('anchor-digest: loaded a non-empty case set', vector.cases.length > 0, `count=${vector.cases.length}`)
ok('anchor-digest: schema constant is synoi.anchor.digest.v1',
   vector.constants['schema'] === 'synoi.anchor.digest.v1')

for (const c of vector.cases) {
  const b = c.batch
  const got = decide(b)

  ok(`[${c.name}] verdict matches expected`, got.verdict === c.expected.verdict,
     `got ${got.verdict} expected ${c.expected.verdict}`)
  ok(`[${c.name}] recomputed digest matches expected`,
     got.digest === c.expected.recomputed_digest,
     `got ${String(got.digest)} expected ${String(c.expected.recomputed_digest)}`)

  // The pinned digest in the vector must be exactly what the rule produces.
  if (c.expected.recomputed_digest !== null) {
    ok(`[${c.name}] pinned ots_digest_sha256 equals the recomputed digest`,
       b.ots_digest_sha256 === c.expected.recomputed_digest)
    ok(`[${c.name}] digest is bare 64-hex`, /^[0-9a-f]{64}$/.test(b.ots_digest_sha256 ?? ''))
    const equalsRoot = b.ots_digest_sha256!.toLowerCase() === b.merkle_root.toLowerCase()
    ok(`[${c.name}] digest_equals_merkle_root matches expected`,
       equalsRoot === c.expected.digest_equals_merkle_root,
       `got ${equalsRoot}`)
  } else {
    ok(`[${c.name}] no digest is published when the preimage is not known`,
       b.ots_digest_sha256 === null)
  }
}

// Cross-case: the discriminator is load bearing. The counter-signed case and
// the root case share a merkle_root but timestamp DIFFERENT bytes.
{
  const cs = vector.cases.find(c => c.name === 'countersigned_bundle_anchor')!
  const mr = vector.cases.find(c => c.name === 'merkle_root_anchor')!
  ok('load-bearing: both cases share the same merkle_root',
     cs.batch.merkle_root === mr.batch.merkle_root)
  ok('load-bearing: the timestamped digests differ',
     cs.batch.ots_digest_sha256 !== mr.batch.ots_digest_sha256)
  ok('load-bearing: assuming merkle_root for the counter-signed batch is a false negative',
     cs.batch.ots_digest_sha256 !== cs.batch.merkle_root)
  ok('load-bearing: the bundle hash reproduces from the stored bundle alone',
     sha256Hex(cs.batch.synoi_canonical_bundle!) === cs.batch.ots_digest_sha256)
}

// The two non-recomputable states must stay distinguishable.
{
  const unknown = vector.cases.find(c => c.name === 'legacy_unknown_preimage')!
  const none = vector.cases.find(c => c.name === 'no_timestamp')!
  ok('unknown and no-timestamp are distinct verdicts',
     unknown.expected.verdict !== none.expected.verdict)
  ok('unknown carries a real ots proof; no-timestamp does not',
     unknown.batch.ots_proof_present === true && none.batch.ots_proof_present === false)
  ok('unknown is NOT silently resolved to merkle_root even though the bundle is present',
     decide(unknown.batch).digest === null)
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
