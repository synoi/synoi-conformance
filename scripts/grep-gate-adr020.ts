// scripts/grep-gate-adr020.ts - ADR_020 half-migration guard.
//
// Mirrors ADR_007's grep-clean gate (agp: -> gap:). FAILS the run if any
// retired cof: namespace literal remains anywhere in src/** or vectors/**.
// This is the mechanical proof that the cof: -> sraid: migration
// (ADR_020 Wave 2) is complete, not partially done. A half-migrated set
// that still contains one of these strings can pass the conformance suite
// on the un-migrated subset alone; this gate makes that impossible.
//
// Retired literals (must be ZERO occurrences):
//   cof_version              - the old L0 version KEY (renamed to sraid_version)
//   cof:sro                  - the old L0 SRO type prefix (renamed to sraid:sro)
//   cof/json                 - the old JSON serialization profile id
//   cof/cbor                 - the old (reserved) CBOR serialization profile id
//   synoi:decision_receipt   - the old v2-path decision-receipt type prefix,
//                               unified onto gap:decision_receipt (ADR_020 M6)
//
// Scope: src/** and vectors/** only (per ADR_020 Section 9 verification
// item 1). Excludes node_modules, dist (build output, gitignored), and
// .claude/worktrees (isolated worktree copies, not the pinned truth).
//
// Run standalone: npx tsx scripts/grep-gate-adr020.ts
// Wired into `npm test` as the final step.

import { readdirSync, statSync, readFileSync } from 'node:fs'
import { join, extname } from 'node:path'

const RETIRED_LITERALS = [
  'cof_version',
  'cof:sro',
  'cof/json',
  'cof/cbor',
  'synoi:decision_receipt',
] as const

const SCAN_ROOTS = ['src', 'vectors'] as const
const SCAN_EXTENSIONS = new Set(['.ts', '.json', '.md'])
const EXCLUDE_DIR_NAMES = new Set(['node_modules', '.git'])

// No known exceptions. vectors/wasm-shell/governed-action-receipt-xlang.json
// was regenerated in ADR_020 Wave 4 from the updated Rust
// emit-governed-action-fixture bin (synoi-gateway/runtime/b1-harness), which
// now signs gap:decision_receipt / sraid_version bytes. The prior documented
// exception for that file is removed.
const KNOWN_EXCEPTIONS = new Set<string>([])

interface Hit {
  literal: string
  file:    string
  line:    number
  text:    string
}

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir)) {
    if (EXCLUDE_DIR_NAMES.has(entry)) continue
    const full = join(dir, entry)
    const st = statSync(full)
    if (st.isDirectory()) {
      walk(full, out)
    } else if (SCAN_EXTENSIONS.has(extname(entry))) {
      out.push(full)
    }
  }
}

function main(): void {
  const files: string[] = []
  for (const root of SCAN_ROOTS) {
    try {
      walk(join(process.cwd(), root), files)
    } catch (err) {
      process.stderr.write(`grep-gate-adr020: WARNING could not walk ${root}: ${(err as Error).message}\n`)
    }
  }

  const hits: Hit[] = []
  const skippedExceptions: string[] = []
  for (const file of files) {
    const rel = file.slice(process.cwd().length + 1)
    if (KNOWN_EXCEPTIONS.has(rel)) {
      skippedExceptions.push(rel)
      continue
    }
    let text: string
    try {
      text = readFileSync(file, 'utf8')
    } catch {
      continue
    }
    const lines = text.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!
      for (const literal of RETIRED_LITERALS) {
        if (line.includes(literal)) {
          hits.push({ literal, file, line: i + 1, text: line.trim() })
        }
      }
    }
  }

  if (hits.length > 0) {
    process.stderr.write(`\nFAIL: ADR_020 grep-gate found ${hits.length} retired cof: literal(s):\n\n`)
    for (const h of hits) {
      process.stderr.write(`  [${h.literal}] ${h.file}:${h.line}\n    ${h.text}\n`)
    }
    process.stderr.write(
      '\nThe cof: -> sraid: migration (ADR_020 Wave 2) is not complete. Every one of\n' +
      'cof_version / cof:sro / cof/json / cof/cbor / synoi:decision_receipt must be\n' +
      'ZERO in src/** and vectors/** before this gate passes.\n',
    )
    process.exit(1)
  }

  process.stdout.write(
    `PASS: ADR_020 grep-gate - zero retired cof: literals across ${files.length - skippedExceptions.length} files ` +
    `in ${SCAN_ROOTS.join(', ')}\n`,
  )
  if (skippedExceptions.length > 0) {
    process.stdout.write(
      `  (${skippedExceptions.length} documented exception(s) skipped, pending Wave 3/4 Rust-side regen: ` +
      `${skippedExceptions.join(', ')})\n`,
    )
  }
}

main()
