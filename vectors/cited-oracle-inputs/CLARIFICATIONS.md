# cited-oracle-inputs vectors: clarifications

**Date:** 2026-06-18
**Authority:** Architect, per S1.12 Tester ambiguity routing.
**Binds:** Builder C3 through C10, Tester, Auditor.
**Source spec:** internal schema spec, Section 6 (amendment block).

This file pins the resolved forms for four ambiguities surfaced against the human-authored seed vectors. The amendment block in the spec is the authoritative text; this file is the operational restatement for Builder and Tester.

## 1. `vault://` `source_url` OID form

**Rule.** Any `vault://<bundle>/<resource>/<oid>` URL written to a receipt MUST carry the full 64-hex sha256 form: `oid-[a-f0-9]{64}`. Shortform is REJECTED on receipts.

**Builder action.** The OFAC adapter MUST emit the full sha256 hex of the snapshot identifier as the OID segment. No truncation, no abbreviation. The shortform tolerance window `oid-[a-f0-9]{6,64}` in spec Section 1.8 applies to PARSER input only (CLI tools resolving shortform to full); it never reaches a signed receipt.

**Tester action.** Verifier MUST reject any `vault://` URL on a receipt whose OID segment is not exactly 64 hex chars. Expected error: `schema_error: source_url vault scheme OID must be full 64-hex sha256`. Add a negative vector covering shortform on receipt (Tester to add `negative-vault-shortform-oid.json` before Builder C4 ships).

**Render-side.** Verifier UI MAY display shortform (first 6 to 12 hex) for brevity in the rendering panel, with a copy affordance for the full OID. Shortform MUST NOT appear in any canonicalized field.

**Vector update.** `valid.json` OFAC entry `source_url` updated from `vault://ofac/snapshot/oid-7f3a2e` to `vault://ofac/snapshot/oid-ab17648aecb55016772715cfcec685934d601b009281b9c6eaf9792709defef7` (sha256 of the deterministic snapshot identifier `ofac-sdn-snapshot-2026-06-17-1`). `value_hash` unchanged: hashes `raw_value` only.

## 2. Weather `temp_f` conversion precision

**Rule.** `temp_f` is a JSON number rounded to ONE decimal place at the producer using IEEE 754 round-half-to-even. Conversion: `f = Math.round((c * 9/5 + 32) * 10) / 10` in TypeScript.

**JCS serialization note (load-bearing).** RFC 8785 inherits ECMAScript number serialization: a double whose mathematical value is an integer serializes WITHOUT a decimal (`78`, not `78.0`). For 25.56 C the producer rounds to `78` (an integer-valued double after rounding) which JCS-serializes as `78`. For 24.0 C -> 75.2 F the JCS form is `75.2`. The one-decimal rule is a *producer rounding* invariant, not a "trailing zero" rule.

**Builder action.** Weather adapter rounds Celsius-to-Fahrenheit result to one decimal BEFORE JCS serialization and `value_hash` computation. Producers that emit `78.0` from a non-ECMAScript repr (e.g. Python `float`) MUST normalize to ECMAScript number form before hashing. The gate's `value_hash` self-check (spec Section 2.5) catches any drift.

**Tester action.** No vector hash change required. Existing `valid.json` weather entry with `temp_f: 78` and `value_hash: sha256:7c3ad7bd23c7d62f55d90ca54bcd05d832b5f58c5893f463efcbde9e436b264a` is correct. Add a positive vector for a non-integer Fahrenheit value (e.g. 24.0 C -> 75.2 F) to confirm one-decimal handling. Tester to add `valid-weather-fractional.json` before Builder C4 ships.

**Out of scope for v1.** No `precision` field on the schema. Precision lives in the adapter contract.

## 3. SMS HITL fetch boundary mocking

**Rule.** The `sms_hitl` adapter accepts an OPTIONAL test-harness injection point as a synchronous-returning function (may return a Promise). EventTarget is NOT used.

**Builder contract.**

```ts
// synoi-gateway/src/agp/pip/sms-hitl/adapter.ts
export interface SmsHitlAdapterOptions {
  onInboundReceived?: (outbound_sid: string) => Promise<{
    body: string;
    provider_message_sid: string;
    received_at: string;
  }>;
}

export class SmsHitlAdapter implements FeedAdapter {
  constructor(private readonly opts: SmsHitlAdapterOptions = {}) {}
  fetch(subject_value: SubjectValue): Promise<Result<FeedResult, FeedError>> {
    // 1. Send outbound via Twilio (or mock outbound in unit tests)
    // 2. If opts.onInboundReceived defined: await opts.onInboundReceived(outbound_sid)
    //    Else: await real inbound webhook with 5-minute window
    // 3. Construct FeedResult from inbound payload
  }
}
```

**Production path.** `opts.onInboundReceived` undefined. Adapter awaits the real inbound webhook on the gate's existing `/twilio/inbound` endpoint, 5-minute window per spec Section 2.4.

**Test path.** Builder/Tester supplies `onInboundReceived` in adapter construction; adapter calls it after dispatching outbound and treats its return value as the inbound. Unit tests do not need a network, do not need EventTarget lifecycle management, and the production code path is the same shape.

**Tester action.** Mock outbound Twilio HTTP via existing HTTP mock; supply `onInboundReceived: async () => ({ body: 'YES', provider_message_sid: 'SM01...', received_at: '2026-06-17T19:36:42.118Z' })` in the unit test setup. `pip-wrapper.json` sms_hitl vector unchanged.

**Binding conformance vectors (TST.2).** `sms-hitl-injection-contract.json` is the authoritative test for this resolution. Three vectors: (1) injection fetch resolves via mock function, not webhook; (2) gate boundary proceeds on correct hash from injection path; (3) gate boundary blocks on tampered hash from injection path. Removing the `opts.onInboundReceived` branch in the adapter causes vector (1) to fail (source_unavailable or timeout). Skipping the hash self-check causes vector (3) to fail (gate returns proceed instead of emit_denial_receipt).

**Rejected alternative.** Async EventTarget the Builder dispatches to. Rejected: one logical consumer, one event, no multiplexing in v1; EventTarget leaks event-driven contract into a synchronous-shaped code path. Revisit only if v1.5 needs concurrent HITL prompts (out of demo scope).

## 4. `source_cursor` rendering contract + Auditor sweep

**Rule.** `source_cursor` is rendered exclusively as "feed version / snapshot identifier". Never as "cache-cursor citation" or anything containing the word "cache". This protects the pattern 13 cache-cursor primitive's PAPER status (spec Section 1.6).

**Verifier UI labels (locked English).**

- OFAC: `Feed snapshot: <source_cursor>`
- Other subject_types: `Feed cursor: <source_cursor>`

**Forbidden copy (extends spec Section 1.5 forbidden list).**

- "cache cursor"
- "cache-cursor citation"
- "fresh as of \<source_cursor\>"
- "stale by \<x\>"
- "snapshot freshness"

**Disclosure (mandatory when both `feed_claimed_at` and `source_cursor` are present).**

> These fields identify which upstream snapshot the gate read. They do not assert freshness; freshness primitive is not yet shipped.

**Auditor sweep (binding, DoD on Builder-C10 and Builder-PDF-leave-behind).**

1. **PDF render check.** Generated PDF text layer MUST NOT contain "cache cursor" or "cache-cursor". Auditor greps. Failure = block ship.
2. **Verifier render check.** Rendered HTML for every vector in this directory MUST NOT contain "cache cursor" or "cache-cursor"; MUST contain "Feed snapshot" or "Feed cursor" for every vector carrying `source_cursor`. Auditor automates via snapshot test in `synoi-verify/test/source-cursor-render.test.ts`. Failure = block ship.

**Tester action.** Add a render-assertion vector annotation (`render_contract`) on every vector in `valid.json` that carries `source_cursor`. The C10 verifier render test reads the annotation and asserts the rendered HTML matches.

**Binding conformance vectors (TST.2).** `source-cursor-render-contract.json` is the authoritative test for this resolution. Three vectors: (1) OFAC entry with `source_cursor` + `feed_claimed_at` co-present -- render label must contain "Feed snapshot"; (2) non-OFAC (weather) entry with `source_cursor` + `feed_claimed_at` co-present -- render label must contain "Feed cursor"; (3) time entry with neither field -- no cursor label rendered. Each vector carries a `render_contract` annotation block. The C10 verifier snapshot test at `synoi-verify/test/source-cursor-render.test.ts` reads `render_contract` and asserts the rendered HTML. Changing the OFAC label to "Cache cursor" or any forbidden variant causes vector (1) to fail. Omitting the disclosure paragraph when both fields are present causes vectors (1) and (2) to fail.

## Summary table

| Item | Vector change | Builder owes | Tester owes | Auditor owes |
|---|---|---|---|---|
| 1. vault OID full form | `valid.json` OFAC source_url updated | Full sha256 hex in OFAC adapter | Add `negative-vault-shortform-oid.json` | nothing |
| 2. temp_f one decimal | none (existing hash preserved) | One-decimal rounding before JCS | Add `valid-weather-fractional.json` (e.g. 75.2 F) | nothing |
| 3. SMS HITL injection | `sms-hitl-injection-contract.json` (TST.2) | Implement `onInboundReceived` option | DONE: 3 vectors (injection fetch + gate proceed + gate block) | nothing |
| 4. source_cursor render | `source-cursor-render-contract.json` (TST.2) + render_contract on valid.json entries | Verifier label + disclosure copy | DONE: 3 vectors (OFAC snapshot + weather cursor + absent cursor baseline) | PDF + verifier sweep at DoD |

Authority: Architect. No em dashes. No AI attribution. Defensible against re-panel: each item closes a determinism gap by reference to existing spec discipline, not by introducing new primitives.
