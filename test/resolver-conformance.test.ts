// resolver-conformance.test.ts - boot @synoi/oid-resolver in-process and run
// the OID Resolver conformance vectors against it. Every vector must pass.

import { runProtocol } from '../src/runner.ts'
import type { Reporter, RunReport, VectorResult, Protocol } from '../src/types.ts'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { AddressInfo } from 'node:net'

class SilentReporter implements Reporter {
  onVector(_p: Protocol, _r: VectorResult): void {}
  onProtocolDone(_r: RunReport): void {}
  finish(_reps: RunReport[]): number { return 0 }
}

let passed = 0, failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' - ' + detail : ''}\n`) }
}

async function main(): Promise<void> {
  const dataDir = mkdtempSync(join(tmpdir(), 'synoi-conf-resolver-'))
  // Pre-set the bearer the auth layer reads.
  process.env['RESOLVER_BEARER_TOKEN'] = 'conf-test-bearer'

  // Boot the reference Resolver via the package's exported app factory.
  const mod = await import('@synoi/oid-resolver')
  const factory = (mod as unknown as {
    createResolverApp?: (opts: { dataDir: string; auth?: unknown }) => unknown
    default?:           { createResolverApp?: (opts: { dataDir: string; auth?: unknown }) => unknown }
  })
  const create = factory.createResolverApp ?? factory.default?.createResolverApp
  if (!create) {
    process.stderr.write('FAIL: @synoi/oid-resolver does not export createResolverApp\n')
    process.exit(1)
  }
  const app = create({ dataDir })
  const { createServer } = await import('node:http')
  // The exported factory returns an express app. Wrap it in a node http server.
  const server = createServer(app as unknown as Parameters<typeof createServer>[1])
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  const url  = `http://127.0.0.1:${port}`

  try {
    const report = await runProtocol({
      protocol:     'oid-resolver',
      resolverUrl:  url,
      resolverAuth: 'Bearer conf-test-bearer',
      reporter:     new SilentReporter(),
      vectorsDir:   join(process.cwd(), 'vectors', 'oid-resolver'),
    })

    ok('resolver: vectors_run > 0',         report.vectors_run > 0)
    ok('resolver: all vectors passed',      report.failed === 0,
       report.failures.map(f => `${f.vector_name}: ${f.reason}`).join(' / '))
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()))
  }

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

void main()
