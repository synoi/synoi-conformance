/**
 * test/license-compat.test.ts — the published package must not carry a
 * copyleft runtime dependency.
 *
 * On 2026-08-27 a licence scan found this package declaring `Apache-2.0` while
 * listing `@synoi/oid-resolver` (AGPL-3.0-or-later) in `dependencies`. Anyone
 * installing it would have pulled AGPL code and inherited AGPL obligations,
 * while the manifest told them Apache. It had not bitten only because the
 * package is unpublished (npm returns E404), which made it cheap to fix then
 * and expensive to fix after a first publish.
 *
 * The dependency was never needed at runtime: the AGPL resolver is used only by
 * `test/resolver-conformance.test.ts` and `scripts/gen-seed-list.ts`, neither of
 * which ships, since `files` publishes dist, src, vectors, README, LICENSE and
 * NOTICE. Published `src/` imports `@synoi/sraid` and nothing else. So the fix
 * was to drop it from `dependencies` and keep it in `devDependencies`.
 *
 * This test pins the invariant rather than the incident: any strongly copyleft
 * runtime dependency fails, not just that one package. A dev dependency is
 * fine, which is why only `dependencies` is inspected.
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.join(__dirname, '..')

/** Licence families incompatible with distributing an Apache-2.0 package. */
const COPYLEFT = /\b(AGPL|GPL-\d|GPL-2|GPL-3|SSPL|OSL|EUPL|CPAL)/i

/** Permissive enough to ship inside an Apache-2.0 distribution. */
const PERMISSIVE = /\b(MIT|Apache-2\.0|BSD|ISC|CC0|Unlicense|Zlib|Python-2\.0|0BSD|WTFPL)/i

function licenceOf(pkgName: string): string | null {
  // Resolve from node_modules rather than guessing: a workspace junction still
  // has a real package.json at the end of it.
  const p = path.join(ROOT, 'node_modules', ...pkgName.split('/'), 'package.json')
  if (!fs.existsSync(p)) return null
  try {
    const j = JSON.parse(fs.readFileSync(p, 'utf8')) as { license?: unknown; licenses?: unknown }
    if (typeof j.license === 'string') return j.license
    if (Array.isArray(j.licenses)) {
      const first = j.licenses[0] as { type?: string } | undefined
      return first?.type ?? null
    }
    return null
  } catch { return null }
}

async function main(): Promise<void> {
  let passed = 0, failed = 0, skipped = 0
  function ok(label: string, cond: boolean, detail?: string) {
    if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
    else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
  }

  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as {
    license?: string
    dependencies?: Record<string, string>
    devDependencies?: Record<string, string>
  }

  ok('package declares a licence', typeof pkg.license === 'string' && pkg.license.length > 0)
  ok('package is Apache-2.0', pkg.license === 'Apache-2.0', `got ${pkg.license}`)

  const deps = Object.keys(pkg.dependencies ?? {})
  ok('has at least one runtime dependency to check', deps.length > 0)

  // The specific regression, named so a reader knows what this file is about.
  ok('@synoi/oid-resolver (AGPL) is not a runtime dependency',
     !deps.includes('@synoi/oid-resolver'),
     'it is dev-only: used by resolver-conformance and gen-seed-list, neither of which ships')
  ok('@synoi/oid-resolver is still available for tests',
     Object.keys(pkg.devDependencies ?? {}).includes('@synoi/oid-resolver'))

  // The general invariant.
  for (const dep of deps) {
    const lic = licenceOf(dep)
    if (lic === null) {
      skipped++
      process.stdout.write(`SKIP ${dep} — not installed, cannot read licence\n`)
      continue
    }
    const copyleft = COPYLEFT.test(lic) && !PERMISSIVE.test(lic)
    ok(`runtime dep ${dep} is not copyleft (${lic})`, !copyleft,
       'a copyleft runtime dependency contradicts the Apache-2.0 declaration')
  }

  process.stdout.write(`\n${passed} passed, ${failed} failed, ${skipped} skipped\n`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch(err => { console.error(err); process.exit(1) })
