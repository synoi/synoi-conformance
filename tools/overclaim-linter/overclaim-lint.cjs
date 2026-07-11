#!/usr/bin/env node
/**
 * Overclaim linter - scans markdown files for untagged numeric performance claims.
 *
 * Exit 0: clean. Exit 1: violations found.
 *
 * Focus: bare numeric multipliers (135x, 7.8x, 25-30x) and "measured result"
 * used as a positive assertion. Generic prose hot-words (every, fully, etc.)
 * are policy in CLAIMS_DISCIPLINE.md but are not flagged here because they
 * appear legitimately throughout doc prose; the linter targets the narrow
 * numeric-claim surface that is unambiguously a problem when untagged.
 *
 * A line is SAFE if it also contains one of:
 *   [MODELED  [PAPER  [SHIPPED  [target  [not yet
 *   "not a measured result"  "Do not present"  or a status emoji (checkmark/dot/clipboard)
 *
 * Meta lines (linter rules, CLAIMS_DISCIPLINE self-references) are skipped.
 *
 * Usage:
 *   node overclaim-lint.cjs [dir-or-file ...]
 *   node overclaim-lint.cjs  (defaults to this repo's own docs)
 *
 * Zero external dependencies.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// --- configuration ---

// Regex patterns for bare numeric multipliers.
// Case-SENSITIVE (lowercase x only): a multiplier claim is written "135x", while
// uppercase-X tokens are product/standard names, not claims (Ryzen "3950X",
// IEEE "802.1X"). Matching those was a false positive.
const HOT_PATTERNS = [
  { re: /\b\d+-\d+x\b/,      label: 'multiplier-range' },
  { re: /\b\d+(\.\d+)?x\b/,  label: 'multiplier' },
];

// "measured result" as a POSITIVE assertion (not a prohibition)
const MEASURED_RESULT_RE = /measured result/i;
const MEASURED_RESULT_SAFE_PHRASES = [
  'not a measured result',
  'do not present',
  'until',
  'no.*benchmark',
];

// A line is SAFE (for multiplier patterns) if it contains one of these text anchors.
// Covers the full CLAIMS_DISCIPLINE tag set (SHIPPED / PARTIAL / PAPER / MODELED /
// ASPIRATIONAL) plus an honest MEASURED label and explicit honesty markers, so a line
// that already states its provenance honestly is not flagged.
const SAFE_TEXT_ANCHORS = [
  '[MODELED',
  'MODELED',   // catches "is MODELED", "is MODELED +"
  '[PAPER',
  'PAPER',
  '[SHIPPED',
  'SHIPPED',
  '[PARTIAL',
  '[MEASURED',
  '[ASPIRATIONAL',
  '[target',
  '[not yet',
  'not a measured result',
  'do not present',
  'Do not present',
  // explicit honesty markers (unbuilt / unmeasured / projection caveats)
  'projection',
  'unbenchmarked',
  'unbuilt',
  'not measured',
  'do not state',
  'until measured',
  'not yet measured',
];

// Lines that are part of the linter's own rule definition are skipped
const META_SKIP_RE = /overclaim|hot.word|hot_word|claims.discipline|linter rule/i;
// Lines that quote the forbidden patterns as examples (backtick-enclosed) are skipped
const META_LITERAL_RE = /`\d+(\.\d+)?x`|`\d+-\d+x`/;

// --- naming guard: "AGP" is retired (renamed to GAP via ADR_007). Stray uppercase
// "AGP" in live canon prose is a naming-drift bug. Only uppercase is flagged so wire
// literals (`agp:`) and code-path citations (`src/agp/...`) do not false-positive.
// Historical / ADR / dated-record docs are allowlisted by filename. ---
const NAMING_RE = /\bAGP\b/;
const NAMING_FILE_ALLOW = /ADR_|ARCHIVE_INDEX|PRELAUNCH|PANEL|STATE_L4/i; // historical / dated records
const NAMING_LITERAL_RE = /`[^`]*agp[^`]*`/i;                              // backtick-enclosed agp literal
const NAMING_SAFE_ANCHORS = [
  'historical', 'superseded', 'Superseded', 'signed byte', 'ADR_018', 'ADR_007',
  'negative-test', 'git history', 'was AGP', 'AGP ->', 'AGP→', 'src/agp',
  'git mv', 'do not', 'Do not', 'must NOT', 'preimage',
  'fully retired', 'retired;', 'retired,', 'naming locked',
];

// --- scope guard: SynOI governs ANY execution; "AI" is the wedge, never the stated
// scope. These exact descriptor phrases collapse scope to AI. Wedge / historical /
// invariant framing is allowlisted by anchor (so labeled-wedge lines pass). ---
const SCOPE_PATTERNS = [
  /Operational Integrity for AI\b/,
  /governance layer for AI\b/,
];
const SCOPE_SAFE_ANCHORS = [
  'wedge', 'Wedge', 'Digital Action', 'every action', 'superseded', 'Superseded',
  'RESOLVED', 'historical', 'never write', 'SCOPE INVARIANT', 'not the scope', 'not the boundary',
];

// --- helpers ---

function hasSafeEmoji(line) {
  return /✅|🟡|📋/.test(line) ||
         line.includes('✅') ||
         line.includes('\u{1F7E1}') ||
         line.includes('\u{1F4CB}') ||
         /\[SHIPPED|✅|🟡|📋/.test(line);
}

function isSafe(line) {
  if (hasSafeEmoji(line)) return true;
  return SAFE_TEXT_ANCHORS.some((a) => line.includes(a));
}

function isMeta(line) {
  return META_SKIP_RE.test(line) || META_LITERAL_RE.test(line);
}

function checkLine(line) {
  if (isMeta(line)) return null;

  // "measured result" positive assertion
  if (MEASURED_RESULT_RE.test(line)) {
    const lower = line.toLowerCase();
    const safe = MEASURED_RESULT_SAFE_PHRASES.some((p) => lower.includes(p)) || isSafe(line);
    if (!safe) {
      return 'measured result (positive assertion without tag)';
    }
  }

  // Bare multiplier patterns
  if (!isSafe(line)) {
    for (const { re, label } of HOT_PATTERNS) {
      const m = line.match(re);
      if (m) {
        // Baseline references (<=1x, e.g. "1.0x baseline") are not overclaims.
        if (label === 'multiplier') {
          const val = parseFloat(m[0]);
          if (!Number.isNaN(val) && val <= 1) continue;
        }
        return `${label}: ${m[0]}`;
      }
    }
  }

  return null;
}

// Naming check is filename-aware (allowlist applied by caller). Returns a reason or null.
function checkNaming(line) {
  if (!NAMING_RE.test(line)) return null;
  if (NAMING_LITERAL_RE.test(line)) return null;
  if (NAMING_SAFE_ANCHORS.some((a) => line.includes(a))) return null;
  return 'stray "AGP" (retired -> GAP; see ADR_007)';
}

function checkScope(line) {
  for (const re of SCOPE_PATTERNS) {
    if (re.test(line)) {
      if (SCOPE_SAFE_ANCHORS.some((a) => line.includes(a))) return null;
      return 'scope-collapse: "for AI" stated as scope (use "every action" / "any execution"; AI is the wedge)';
    }
  }
  return null;
}

function collectMarkdown(target, results) {
  let stat;
  try { stat = fs.statSync(target); } catch (e) { return; }
  if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(target)) {
      if (entry === 'node_modules' || entry.startsWith('.')) continue;
      collectMarkdown(path.join(target, entry), results);
    }
  } else if (target.endsWith('.md')) {
    results.push(target);
  }
}

// --- main ---

function resolveTargets(args) {
  if (args.length === 0) {
    return [path.resolve(__dirname, '..', '..')];
  }
  return args.map((a) => path.resolve(a));
}

function lint(targets) {
  const files = [];
  for (const t of targets) collectMarkdown(t, files);

  const violations = [];
  for (const file of files) {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    const base = path.basename(file);
    const namingAllowed = NAMING_FILE_ALLOW.test(base);
    lines.forEach((line, idx) => {
      const reason = checkLine(line);
      if (reason) violations.push({ file, line: idx + 1, text: line.trim(), reason });
      if (!namingAllowed) {
        const nReason = checkNaming(line);
        if (nReason) violations.push({ file, line: idx + 1, text: line.trim(), reason: nReason });
      }
      const sReason = checkScope(line);
      if (sReason) violations.push({ file, line: idx + 1, text: line.trim(), reason: sReason });
    });
  }
  return { files, violations };
}

const args = process.argv.slice(2);
const targets = resolveTargets(args);
const { files, violations } = lint(targets);

if (files.length === 0) {
  console.error('overclaim-lint: no markdown files found');
  process.exit(1);
}

if (violations.length === 0) {
  console.log(`overclaim-lint: clean (${files.length} file(s) scanned)`);
  process.exit(0);
}

console.error(`overclaim-lint: ${violations.length} violation(s) in ${files.length} file(s) scanned:\n`);
for (const v of violations) {
  console.error(`  ${v.file}:${v.line}  [${v.reason}]`);
  console.error(`    ${v.text}`);
}
process.exit(1);
