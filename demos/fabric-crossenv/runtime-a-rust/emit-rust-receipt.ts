// runtime-a-rust/emit-rust-receipt.ts
//
// RUNTIME A - now a GENUINELY CROSS-LANGUAGE, independent implementation: a
// real Rust binary, `emit-governed-action-fixture` from
// synoi-gateway/runtime/b1-harness. This is the SAME binary that already
// backs synoi-conformance/vectors/_verify-governed-action-xlang.ts (a
// PARTIAL-against-test-keys conformance vector proving Rust-signed receipts
// verify under the TS @synoi/verify path).
//
// READ-ONLY use of the gateway repo: this script only EXECUTES an already
// -built binary (target/debug/emit-governed-action-fixture.exe) and reads
// its stdout. It does NOT modify any gateway source file. If the binary is
// missing, it builds ONLY that one bin target of the b1-harness crate
// (`cargo build --bin emit-governed-action-fixture`), never the full
// workspace and never WASM.
//
// HONESTY NOTE (do not fake the action type): the fixture's payload is
// FIXED in the Rust source (main() takes no parameters) -- it emits a
// governed-action receipt for subject "governed-action.allowed",
// body.action_kind "render-panel", tenant_id "xlang-test". This script does
// NOT relabel it as a "game" action; R1 is used and described exactly as
// the Rust binary produced it. Framing it as a literal in-game purchase
// would require parameterizing/rebuilding the Rust emitter, which is out
// of scope for a read-only proof.
//
// A second honest tradeoff, spelled out here and in README.md: because the
// payload is fixed, R1's `created_by` is the Rust harness's own baked-in
// test identity (derived from SHELL_RECEIPT_ED_SEED/SHELL_RECEIPT_ML_SEED),
// NOT this demo's OID_op. The single-operator-identity claim is carried by
// R2 (created_by = OID_op) and the cryptographic link R2.prev === R1.oid;
// R1 itself is used verbatim, unmodified, exactly as the independent Rust
// runtime signed it.
//
// Run: npx tsx runtime-a-rust/emit-rust-receipt.ts
//
// NO em dashes. NO AI attribution.

import { execFileSync } from 'node:child_process'
import { existsSync, writeFileSync, mkdirSync } from 'node:fs'
import { createPublicKey } from 'node:crypto'
import * as fs from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, '..', 'out')
mkdirSync(outDir, { recursive: true })

// Resolved RELATIVE to this file, not as an absolute path.
//
// This was hardcoded to E:\client\synoi\synoi-gateway\... — the tree layout
// from before the 2026-08-06 migration into synoi-systems. After the move the
// binary was still present, but at a different absolute path, so existsSync
// missed it, the script fell through to `cargo build`, and the demo failed on
// any machine without a Rust toolchain. The symptom that surfaced first was a
// stale `invocation` field in out/runtime-a-provenance.json; hand-editing that
// output would have corrected the record while leaving the cause in place.
//
// synoi-gateway is a sibling of synoi-conformance, so four levels up from
// runtime-a-rust/ is the tree root. Survives the tree being relocated again.
const B1_HARNESS_DIR = join(
  here, '..', '..', '..', '..', 'synoi-gateway', 'runtime', 'b1-harness',
)
const EXE = join(B1_HARNESS_DIR, 'target', 'debug', 'emit-governed-action-fixture.exe')

if (!existsSync(EXE)) {
  process.stdout.write(
    'runtime-a-rust: prebuilt binary not found, building ONLY this bin target ' +
      '(no WASM, no full workspace build)...\n',
  )
  execFileSync(
    'cargo',
    ['build', '--bin', 'emit-governed-action-fixture'],
    { cwd: B1_HARNESS_DIR, stdio: 'inherit' },
  )
}

// Execute the existing Rust binary. Read-only: no source touched, just runs
// a compiled artifact and captures stdout.
const stdout = execFileSync(EXE, [], { cwd: B1_HARNESS_DIR, encoding: 'utf8' })
const fixture = JSON.parse(stdout) as {
  allow_receipt: Record<string, unknown>
  ed25519_pub_hex: string
  ml_dsa_pub_hex: string
  tag: string
}

if (fixture.tag !== 'PARTIAL-against-test-keys') {
  throw new Error(`runtime-a-rust: unexpected fixture tag "${fixture.tag}", refusing to proceed`)
}

// R1 is used VERBATIM -- no field added, removed, or edited. Any edit would
// break its own attestation (the payload is the exact canonical bytes the
// Rust process signed).
const r1 = fixture.allow_receipt

writeFileSync(join(outDir, 'r1.json'), JSON.stringify(r1, null, 2) + '\n')

// ── Public key bundle, in the same PublicKeyBundle shape @synoi/verify-core
// expects: SPKI PEM for Ed25519, raw base64 for ML-DSA-65. ──────────────────
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
function ed25519PublicKeyPem(rawHex: string): string {
  const raw = Buffer.from(rawHex, 'hex')
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw])
  return createPublicKey({ key: der, format: 'der', type: 'spki' })
    .export({ format: 'pem', type: 'spki' })
    .toString()
}

writeFileSync(
  join(outDir, 'runtime-a-keys.pub.json'),
  JSON.stringify(
    {
      key_id: 'runtime-a-rust-xlang-fixture-key',
      ed25519_public_key_pem: ed25519PublicKeyPem(fixture.ed25519_pub_hex),
      ml_dsa_public_key_b64: Buffer.from(fixture.ml_dsa_pub_hex, 'hex').toString('base64'),
    },
    null,
    2,
  ) + '\n',
)

// No secret-key file is written here: Runtime A's private key material never
// leaves the Rust process. This demo only ever holds Runtime A's PUBLIC key
// and the R1 receipt it produced, exactly as a real separate implementation
// would hand off to a third-party verifier.
fs.writeFileSync(
  join(outDir, 'runtime-a-provenance.json'),
  JSON.stringify(
    {
      note: 'R1 was emitted by a real Rust binary, not simulated in TypeScript.',
      binary: 'emit-governed-action-fixture (synoi-gateway/runtime/b1-harness)',
      invocation: EXE,
      fixture_tag: fixture.tag,
      fixture_subject: r1.subject,
      fixture_action_kind: (r1.body as { action_kind?: unknown } | undefined)?.action_kind,
      fixture_tenant_id: r1.tenant_id,
      caveat:
        'payload is fixed in Rust source (main() takes no CLI params); used verbatim, ' +
        'not relabeled as a game action per task honesty constraint',
    },
    null,
    2,
  ) + '\n',
)

process.stdout.write(`runtime-a-rust: emitted R1 oid=${String(r1.oid)} (Rust, tenant=${String(r1.tenant_id)})\n`)
