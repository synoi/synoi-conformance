// identity-binding-oidc-canonical-conformance.test.ts -- pin the OIDC
// trust-anchor holder-consent canonical payload (Caveat Wave B) against the
// golden vectors in vectors/identity-binding/canonical-oidc.json.
//
// The OIDC holder-consent bytes are what the actor's Ed25519 consent key signs
// so an identity_verified OIDC binding can project that key as the persona-consent
// trust anchor. It is a length-prefixed, domain-separated encoding under a domain
// distinct from v1/v2/v3, so an OIDC holder signature can never cross-replay as any
// other binding signature. This suite recomputes the algorithm from each vector's
// args and asserts byte-for-byte against expected.
//
// Algorithm (oidc):
//   domain = 'gap-identity-binding-oidc-v1'
//   LP(s)  = utf8ByteLength(s) + ':' + s
//   payload = LP(domain) LP(actor_oid) LP(tenant_id) LP(issuer)
//             LP(oidc_subject) LP(consent_pubkey) LP(nonce) LP(String(not_after_ms))

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const DOMAIN = 'gap-identity-binding-oidc-v1'
function lp(field: string): string {
  return `${Buffer.byteLength(field, 'utf-8')}:${field}`
}
function canonicalOidc(
  actor_oid: string, tenant_id: string, issuer: string, oidc_subject: string,
  consent_pubkey: string, nonce: string, not_after_ms: number,
): string {
  return (
    lp(DOMAIN) + lp(actor_oid) + lp(tenant_id) + lp(issuer) +
    lp(oidc_subject) + lp(consent_pubkey) + lp(nonce) + lp(String(not_after_ms))
  )
}

interface Vector {
  name: string
  kind: string
  args: [string, string, string, string, string, string, number]
  expected: string
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

function main(): void {
  const file = join(process.cwd(), 'vectors', 'identity-binding', 'canonical-oidc.json')
  const vectors = JSON.parse(readFileSync(file, 'utf8')) as Vector[]

  ok('identity-binding-oidc: vectors_run > 0', vectors.length > 0)

  for (const v of vectors) {
    const got = canonicalOidc(...v.args)
    ok(`canonical-oidc matches expected: ${v.name}`, got === v.expected,
       `got ${JSON.stringify(got)} expected ${JSON.stringify(v.expected)}`)
  }

  // Delimiter disambiguation: the paired vectors MUST differ byte-for-byte.
  const byName = new Map(vectors.map(v => [v.name, v.expected]))
  const abc = byName.get('oidc delimiter (a,bc)')
  const ab_c = byName.get('oidc delimiter (ab,c)')
  ok('OIDC delimiter: (a,bc) and (ab,c) canonical bytes differ',
     abc !== undefined && ab_c !== undefined && abc !== ab_c)

  process.stdout.write(`\n${passed} passed, ${failed} failed (${vectors.length} identity-binding-oidc vectors)\n`)
  process.exit(failed > 0 ? 1 : 0)
}

main()
