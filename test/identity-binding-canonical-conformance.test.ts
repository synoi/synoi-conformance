// identity-binding-canonical-conformance.test.ts -- pin the identity-binding
// v2 canonical payload against the golden vectors in
// vectors/identity-binding/canonical-v2.json.
//
// The v2 canonical bytes are the single source of truth every producer and
// verifier of an identity binding MUST derive. This suite is the neutral,
// impl-independent contract: the algorithm is recomputed here from each
// vector's `args` and asserted byte-for-byte against `expected`.
//
// Why this matters (red-team, 2026-07): v1 signed a naive ':'-join
// (domain:actor:tenant:cred), which is delimiter-ambiguous: actor='a',
// tenant='bc' collides with actor='ab',tenant='c' (signature confusion). v2
// length-prefixes each field so two distinct field tuples can never produce the
// same bytes. The paired vectors below (a,bc)/(ab,c) and colon-in-cred/
// colon-in-tenant prove the collisions are gone.
//
// Algorithm (v2):
//   domain = 'gap-identity-binding-v2'
//   LP(s)  = utf8ByteLength(s) + ':' + s
//   payload = LP(domain) LP(actor_oid) LP(tenant_id)
//             LP(credential_identifier) LP(nonce) LP(String(not_after_ms))

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const DOMAIN = 'gap-identity-binding-v2'
function lp(field: string): string {
  return `${Buffer.byteLength(field, 'utf-8')}:${field}`
}
function canonicalV2(
  actor_oid: string, tenant_id: string, credential_identifier: string,
  nonce: string, not_after_ms: number,
): string {
  return (
    lp(DOMAIN) + lp(actor_oid) + lp(tenant_id) +
    lp(credential_identifier) + lp(nonce) + lp(String(not_after_ms))
  )
}

interface Vector {
  name: string
  kind: string
  args: [string, string, string, string, number]
  expected: string
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

function main(): void {
  const file = join(process.cwd(), 'vectors', 'identity-binding', 'canonical-v2.json')
  const vectors = JSON.parse(readFileSync(file, 'utf8')) as Vector[]

  ok('identity-binding: vectors_run > 0', vectors.length > 0)

  for (const v of vectors) {
    const got = canonicalV2(...v.args)
    ok(`canonical-v2 matches expected: ${v.name}`, got === v.expected,
       `got ${JSON.stringify(got)} expected ${JSON.stringify(v.expected)}`)
  }

  // DEFECT 4 disambiguation: the paired vectors MUST differ byte-for-byte.
  const byName = new Map(vectors.map(v => [v.name, v.expected]))
  const abc = byName.get('v2 delimiter-injection (a,bc)')
  const ab_c = byName.get('v2 delimiter-injection (ab,c)')
  ok('DEFECT4: (a,bc) and (ab,c) canonical bytes differ',
     abc !== undefined && ab_c !== undefined && abc !== ab_c)
  const colCred = byName.get('v2 colon-in-cred')
  const colTen  = byName.get('v2 colon-in-tenant')
  ok('DEFECT4: colon-in-cred and colon-in-tenant canonical bytes differ',
     colCred !== undefined && colTen !== undefined && colCred !== colTen)

  process.stdout.write(`\n${passed} passed, ${failed} failed (${vectors.length} identity-binding vectors)\n`)
  process.exit(failed > 0 ? 1 : 0)
}

main()
