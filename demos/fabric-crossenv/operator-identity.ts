// operator-identity.ts
//
// Computes OID_op, the operator identity anchor both Runtime A (game) and
// Runtime B (work) reference as the acting subject. This is deliberately
// the ONLY file the two runtimes both read from disk (the shared fact "who
// is the operator"). Neither runtime imports code from the other or from
// this file's signing logic; there is none here to import, this script only
// computes a content-addressed OID over a small identity descriptor.
//
// Uses ONLY @synoi/sraid (open, MIT). No gateway code.
//
// Run: npx tsx operator-identity.ts
//
// NO em dashes. NO AI attribution.

import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { oidOf } from '@synoi/sraid'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, 'out')
mkdirSync(outDir, { recursive: true })

// A minimal, self-describing operator identity descriptor. In the real
// SynOI stack this would be a signed SRAID identity record resolved through
// the OID Resolver; for this proof it is enough that OID_op is a REAL
// content-addressed OID (sha256 of canonical bytes), computed with the same
// oidOf() function the gateway itself uses, not a made-up string.
const descriptor = {
  type: 'sraid:operator_identity',
  sraid_version: '2.0',
  label: 'demo-operator-crossenv-proof',
  note: 'minimal proof identity descriptor, not a resolvable production OID',
}

const oid = oidOf(descriptor)

writeFileSync(
  join(outDir, 'operator-identity.json'),
  JSON.stringify({ oid, descriptor }, null, 2) + '\n',
)

process.stdout.write(`OID_op = ${oid}\n`)
