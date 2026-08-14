// certification-r1-r4-conformance.test.ts
//
// The four certification requirements, as executable vectors. "No vector, no
// claim" applies here with full force: a certification program whose
// requirements are prose is a promise, and a certification program whose
// requirements are vectors is a test.
//
// WHAT THIS FILE IS AND IS NOT. It pins the SHAPE of each requirement and the
// evidence that satisfies it, so a candidate implementation and an assessor
// agree on what passing means before anyone runs anything. It does NOT certify
// anything, it names no program, and it carries no mark: the mark class is
// unsettled (see COUNSEL_QUESTION_CERTIFICATION_MARK_2026-08-13.md), and
// building a registry or a badge before a buyer names the requirement is
// explicitly out of scope.
//
// R1  The software holds no long-lived third-party credential it did not
//     receive per-action under a verdict.
//     Test: revoke the grant, confirm the software can no longer act.
//     Black-box, binary. The strongest of the four because it cannot be faked:
//     either the key is absent or it is not.
//
// R2  All outbound to third parties traverses a declared chokepoint.
//     Test: network observation in a harness. Strong but harness-dependent,
//     which is stated rather than hidden.
//
// R3  A receipt per action, plus signed silence.
//     Test: kill the emitter, confirm the gap surfaces.
//
// R4  A published perimeter declaration whose blind-spot list matches observed
//     behaviour.
//     Test: resolve the declaration, compare against harness observation.
//     Medium strength, and it is the honesty requirement. A candidate passing
//     R1 through R3 with a dishonest R4 FAILS, and that is the point: other
//     programs certify that controls exist, this one certifies that the vendor
//     has accurately stated what it cannot see.
//
// No em dashes.

import {
  PERIMETER_DECLARATION_SCHEMA,
  classifySurface,
  validatePerimeterDeclarationBody,
  enforcementWithinCeiling,
} from '@synoi/gap'

let passed = 0, failed = 0
function ok(label: string, cond: unknown, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

/** A requirement's outcome. Tri-state on purpose: see the note below. */
type Outcome = 'pass' | 'fail' | 'indeterminate'

/**
 * INDETERMINATE IS NOT A COURTESY. It is what an assessor must return when the
 * evidence could not support a verdict: the harness did not observe the
 * network, the emitter window fell outside retention, the declaration could
 * not be resolved. Collapsing it into `pass` would mean an unobservable
 * candidate certifies by default, which is the single worst failure mode a
 * certification program can have. Collapsing it into `fail` would punish
 * candidates for the assessor's tooling. It stays its own value.
 */

interface RequirementVector {
  id: 'R1' | 'R2' | 'R3' | 'R4'
  statement: string
  test: string
  evidence_required: string[]
  /** Verdict when the required evidence is absent rather than negative. */
  absent_evidence_outcome: Outcome
  strength: 'strongest' | 'strong' | 'strong-harness-dependent' | 'medium-honesty'
}

const REQUIREMENTS: RequirementVector[] = [
  {
    id: 'R1',
    statement: 'The software holds no long-lived third-party credential it did not receive per-action under a verdict.',
    test: 'Revoke the grant, then confirm the software can no longer perform the action.',
    evidence_required: [
      'the third-party key is absent from the platform secret store',
      'an action succeeds while the grant is live',
      'the same action fails after the grant is revoked, with the software unchanged',
    ],
    absent_evidence_outcome: 'indeterminate',
    strength: 'strongest',
  },
  {
    id: 'R2',
    statement: 'All outbound traffic to third parties traverses a declared chokepoint.',
    test: 'Observe the workload network in a harness for the assessment window.',
    evidence_required: [
      'a declared chokepoint list',
      'an observed flow list for the window',
      'every observed third-party destination maps to a declared chokepoint',
    ],
    absent_evidence_outcome: 'indeterminate',
    strength: 'strong-harness-dependent',
  },
  {
    id: 'R3',
    statement: 'A signed receipt exists per action, and silence is signed.',
    test: 'Kill the emitter for a bounded window and confirm the gap surfaces.',
    evidence_required: [
      'a receipt per observed action',
      'an epoch receipt per epoch across the window',
      'a deliberately induced gap that the continuity check reports',
    ],
    absent_evidence_outcome: 'indeterminate',
    strength: 'strong',
  },
  {
    id: 'R4',
    statement: 'A published perimeter declaration whose blind-spot list matches observed behaviour.',
    test: 'Resolve the declaration and compare it against what the harness observed.',
    evidence_required: [
      'a resolvable, signed perimeter declaration',
      'harness observations of the surfaces actually used',
      'every observed surface is declared, as a chokepoint or as a blind spot',
    ],
    absent_evidence_outcome: 'fail',
    strength: 'medium-honesty',
  },
]

// ── The requirement set itself ──────────────────────────────────────────────

ok('vectors: exactly four requirements', REQUIREMENTS.length === 4)
ok('vectors: ids are R1 through R4',
  REQUIREMENTS.map(r => r.id).join(',') === 'R1,R2,R3,R4')
ok('vectors: every requirement names a concrete test',
  REQUIREMENTS.every(r => r.test.length > 20))
ok('vectors: every requirement names the evidence that would satisfy it',
  REQUIREMENTS.every(r => r.evidence_required.length >= 3),
  'a requirement without stated evidence is an opinion')

ok('vectors: R1 is the strongest and is black-box',
  REQUIREMENTS[0]!.strength === 'strongest' &&
  REQUIREMENTS[0]!.test.includes('Revoke the grant'),
  'either the key is absent or it is not, and no amount of documentation changes that')

ok('vectors: R2 declares its harness dependence rather than hiding it',
  REQUIREMENTS[1]!.strength === 'strong-harness-dependent')

// R4 is the one that differs, and the difference is deliberate: missing
// evidence for R4 is a FAIL, not indeterminate, because R4 is a claim the
// candidate is supposed to have PUBLISHED. A candidate who cannot produce
// their own perimeter declaration has not met the requirement; there is
// nothing for an assessor's tooling to have failed at.
ok('vectors: absent evidence is indeterminate for R1 to R3',
  REQUIREMENTS.slice(0, 3).every(r => r.absent_evidence_outcome === 'indeterminate'),
  'an unobservable candidate must never certify by default')
ok('vectors: absent evidence is a FAIL for R4',
  REQUIREMENTS[3]!.absent_evidence_outcome === 'fail',
  'R4 is a claim the candidate publishes, so its absence is the candidate failing, not the harness')

// ── R4 is executable today against a real declaration ───────────────────────
//
// R1 through R3 need a live candidate deployment, so their vectors above pin
// the protocol rather than run it. R4 can be checked right now, because the
// artifact it tests is a signed object with a shared validator, and that is
// worth demonstrating: it is the requirement that distinguishes this program,
// and it is the one an assessor can run without touching the candidate's
// network.

const declaration = {
  schema: PERIMETER_DECLARATION_SCHEMA,
  governed_subject: { platform: 'candidate-platform', workspace_id: 'ws-1' },
  chokepoints_active: [
    { class: 'C1' as const, surface: 'gateway:brokered-credential:stripe', enforcement: 'structural' as const },
    { class: 'C5' as const, surface: 'mcp:https://gw.example/mcp/proxy',   enforcement: 'structural' as const },
  ],
  blind_spots: [
    {
      surface: 'candidate:cron',
      reason: 'A scheduled job on the build host calls the vendor API directly and is not brokered.',
      class_unavailable: 'C1' as const,
    },
  ],
  completeness_scope: { populations: ['action_log', 'receipts'], from_seq: 1, to_seq: 100 },
  effective_from_ms: 1_750_000_000_000,
}

ok('R4: the declaration validates against the shared validator',
  validatePerimeterDeclarationBody(declaration).ok,
  validatePerimeterDeclarationBody(declaration).errors.join('; '))

// The R4 procedure, run: every observed surface must be declared, as a
// chokepoint OR as a blind spot. Undeclared is the finding.
const observedHonest = ['mcp:https://gw.example/mcp/proxy', 'candidate:cron']
const honestVerdict = observedHonest.every(s => classifySurface(declaration, s) !== 'undeclared')
ok('R4: a candidate whose observations are all declared PASSES', honestVerdict)

// The case the program exists for: controls work, disclosure does not. This
// candidate would pass R1 through R3 and must still fail.
const observedDishonest = [...observedHonest, 'candidate:admin-console']
const dishonestVerdict = observedDishonest.every(s => classifySurface(declaration, s) !== 'undeclared')
ok('R4: a candidate acting on an undeclared surface FAILS', !dishonestVerdict,
  'passing R1 through R3 with a dishonest R4 is exactly the case this program is for')
ok('R4: the failing surface is named, not merely counted',
  classifySurface(declaration, 'candidate:admin-console') === 'undeclared')

// A declared blind spot is NOT a failure. Disclosed uncovered surfaces are the
// honest outcome, and a program that penalized them would teach candidates to
// under-declare, which inverts the requirement.
ok('R4: acting on a DECLARED blind spot is not a failure',
  classifySurface(declaration, 'candidate:cron') === 'declared_blind_spot',
  'penalizing disclosure would teach candidates to under-declare')

// And the overclaim guard applies to a candidate's declaration too: a
// candidate cannot buy strength by describing a webhook feed as structural.
ok('R4: a candidate cannot claim structural enforcement on a C7 feed',
  !enforcementWithinCeiling('C7', 'structural'))

// ── Tier definitions ────────────────────────────────────────────────────────

const TIERS = {
  governable: ['R2', 'R4'],
  governed:   ['R1', 'R2', 'R3', 'R4'],
}
ok('tiers: the entry rung is R2 plus R4',
  TIERS.governable.join(',') === 'R2,R4',
  'expose a declared chokepoint and publish an honest perimeter, without emitting receipts')
ok('tiers: the full rung is all four', TIERS.governed.length === 4)
ok('tiers: R4 is required at EVERY tier',
  TIERS.governable.includes('R4') && TIERS.governed.includes('R4'),
  'honesty is not an upgrade')

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
