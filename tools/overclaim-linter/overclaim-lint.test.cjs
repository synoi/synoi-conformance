/**
 * overclaim-lint test suite
 *
 * Written RED-FIRST: the test cases that must fail are identified before
 * the linter logic makes them pass.
 *
 * Run: node overclaim-lint.test.js
 * Exit 0 = all pass. Exit 1 = failures.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const LINTER = path.resolve(__dirname, 'overclaim-lint.cjs');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'overclaim-test-'));

let passed = 0;
let failed = 0;

function write(name, content) {
  const p = path.join(TMP, name);
  fs.writeFileSync(p, content, 'utf8');
  return p;
}

function run(files) {
  const result = spawnSync('node', [LINTER, ...files], { encoding: 'utf8' });
  return result.status;
}

function expect(label, actual, expected) {
  if (actual === expected) {
    console.log(`  PASS  ${label}`);
    passed++;
  } else {
    console.error(`  FAIL  ${label}  (got exit ${actual}, want ${expected})`);
    failed++;
  }
}

console.log('overclaim-lint tests\n');

// --- cases that must exit 1 (violations) ---

const bare135 = write('bare135.md', 'Performance is 135x faster than baseline.\n');
expect('bare 135x with no tag => exit 1', run([bare135]), 1);

const bare78 = write('bare78.md', 'ML-DSA verification is 7.8x native speed.\n');
expect('bare 7.8x with no tag => exit 1', run([bare78]), 1);

const bareMultiplier = write('baremulti.md', 'Reduces latency by 25x in all scenarios.\n');
expect('bare 25x with no tag => exit 1', run([bareMultiplier]), 1);

const rangeMultiplier = write('rangemulti.md', 'Speeds up 25-30x in OID routing path.\n');
expect('bare 25-30x with no tag => exit 1', run([rangeMultiplier]), 1);

const measuredResult = write('measuredresult.md', 'This is a measured result from our production cluster.\n');
expect('"measured result" without anchor => exit 1', run([measuredResult]), 1);

// AST is in the policy hot-word list in CLAIMS_DISCIPLINE.md but is NOT flagged
// by the linter (which focuses on numeric multiplier claims only). This is intentional:
// "AST" appears legitimately in prose and the linter does not flag generic hot words.
// The CLAIMS_DISCIPLINE doc + auditor agent (rule 4) handle generic hot words at publish time.
const hotWordAST = write('hotast.md', '| Feature | AST parsing |\n');
expect('bare AST = exit 0 (numeric linter does not flag prose hot words)', run([hotWordAST]), 0);

// --- cases that must exit 0 (clean) ---

const tagged135 = write('tagged135.md', '| 135x+ with DPU | [MODELED: hardware estimate; not a measured result] |\n');
expect('135x with [MODELED tag => exit 0', run([tagged135]), 0);

const tagged78 = write('tagged78.md', '| ML-DSA native | 7.8x [SHIPPED: synoi-sraid#9 merged] |\n');
expect('7.8x with [SHIPPED tag => exit 0', run([tagged78]), 0);

const taggedPaper = write('taggedpaper.md', '| 25-30x faster | [PAPER + MODELED: design-time analysis only] |\n');
expect('25-30x with [PAPER tag => exit 0', run([taggedPaper]), 0);

const taggedMeasured = write('taggedmeasured.md', 'Do not present as a measured result until benchmarked.\n');
expect('"not a measured result" prohibition line => exit 0', run([taggedMeasured]), 0);

const emoji = write('emoji.md', '| wrap() | ✅ shipped: @synoi/broker wrap() is real |\n');
expect('line with ✅ emoji => exit 0', run([emoji]), 0);

const metaClaims = write('metaclaims.md', 'Also flags bare numeric multipliers (pattern `\\d+(\\d+)?x`, e.g. `135x`, `7.8x`).\n');
expect('linter rule definition in CLAIMS_DISCIPLINE => exit 0 (meta skip)', run([metaClaims]), 0);

const emptyFile = write('empty.md', '# Section\n\nNo claims here.\n');
expect('file with no hot words => exit 0', run([emptyFile]), 0);

// --- naming guard: AGP retired -> GAP (ADR_007) ---

const strayAgp = write('strayagp.md', 'The AGP receipt is signed and portable.\n');
expect('stray "AGP" in live prose => exit 1', run([strayAgp]), 1);

const agpHistorical = write('agphist.md', 'The AGP type values are preserved as signed bytes (historical).\n');
expect('AGP with historical/signed-byte anchor => exit 0', run([agpHistorical]), 0);

const agpPath = write('agppath.md', 'v2 DSSE is live on `src/agp/local-ingest-router.ts:469`.\n');
expect('agp in code-path citation (src/agp) => exit 0', run([agpPath]), 0);

const agpAllowFile = write('ARCHIVE_INDEX.md', 'AGP was the prior name of GAP before the rename.\n');
expect('AGP in allowlisted ARCHIVE_INDEX file => exit 0', run([agpAllowFile]), 0);

const agpLower = write('agplower.md', 'The agp: wire prefix appears in the negative-test vector.\n');
expect('lowercase agp: wire literal => exit 0', run([agpLower]), 0);

const agpFullyRetired = write('agpretired.md', '"SRAID" is protocol-name-only; "AGP" fully retired; L3 is GAP.\n');
expect('"AGP" fully retired declarative statement => exit 0', run([agpFullyRetired]), 0);

// --- scope guard: "for AI" stated as capability scope ---

const scopeCollapse = write('scopecollapse.md', 'SynOI is Operational Integrity for AI, full stop.\n');
expect('"Operational Integrity for AI" as scope => exit 1', run([scopeCollapse]), 1);

const scopeLayer = write('scopelayer.md', 'It is the governance layer for AI that ships today.\n');
expect('"governance layer for AI" as scope => exit 1', run([scopeLayer]), 1);

const scopeWedge = write('scopewedge.md', 'Keep "Operational Integrity for AI" as the wedge pitch.\n');
expect('"for AI" with wedge anchor => exit 0', run([scopeWedge]), 0);

const scopeInvariant = write('scopeinv.md', 'SCOPE INVARIANT: never write "Operational Integrity for AI" as scope.\n');
expect('scope-invariant block (SCOPE INVARIANT / never write) => exit 0', run([scopeInvariant]), 0);

const scopeHook = write('scopehook.md', 'Hook: "Compliance-ready governance for AI agents at scale."\n');
expect('marketing wedge hook (governance for AI agents) => exit 0', run([scopeHook]), 0);

// --- false positives the multiplier regex must NOT flag ---

const cpuName = write('cpuname.md', 'Native verify benchmarked on AMD Ryzen 9 3950X.\n');
expect('CPU model "3950X" (uppercase X) => exit 0', run([cpuName]), 0);

const standard8021x = write('std8021x.md', 'Enforced via 802.1X port-based authentication.\n');
expect('IEEE "802.1X" standard name (uppercase X) => exit 0', run([standard8021x]), 0);

const baseline = write('baseline.md', 'The CPU path is the 1.0x baseline reference.\n');
expect('"1.0x" baseline (value <= 1) => exit 0', run([baseline]), 0);

// --- honest provenance labels must pass (full CLAIMS_DISCIPLINE tag set + markers) ---

const partialTag = write('partialtag.md', 'Native hybrid verify ~8.5x [PARTIAL: gateway path updated; deploy pending].\n');
expect('8.5x with [PARTIAL tag => exit 0', run([partialTag]), 0);

const measuredTag = write('measuredtag.md', 'ZK overhead 14.41x [MEASURED: SRAID proof harness; ZK mode PARTIAL].\n');
expect('14.41x with [MEASURED tag => exit 0', run([measuredTag]), 0);

const projection = write('projection.md', 'The 135x figure is a March-2026 projection, unbenchmarked; do not state publicly.\n');
expect('135x with projection/unbenchmarked markers => exit 0', run([projection]), 0);

// uppercase "135X" written as an actual claim is now NOT caught (case-sensitive tradeoff);
// the auditor catches uppercase-claim prose. A lowercase real claim still fails:
const upperClaimSlip = write('upperclaim.md', 'We deliver 135X faster end to end.\n');
expect('uppercase "135X" claim slips the numeric linter => exit 0 (auditor catches)', run([upperClaimSlip]), 0);

// --- summary ---

console.log(`\n${passed} passed, ${failed} failed`);

// cleanup
fs.rmSync(TMP, { recursive: true, force: true });

process.exit(failed > 0 ? 1 : 0);
