# @synoi/conformance

**Apache 2.0** conformance test suite for SynOI's open protocols. The spec made executable.

Every open protocol SynOI ships gets a conformance test suite. Vendors, federation peers, third-party gateways: run this against your implementation and prove byte-level compatibility with the reference.

## Install

```bash
npm install --save-dev @synoi/conformance
```

## Run

```bash
# SRAID (L0) - TypeScript / JavaScript module candidate (wire protocol id: sraid)
npx synoi-conformance --protocol=sraid --impl=./my-sraid.js

# GAP - same shape
npx synoi-conformance --protocol=gap --impl=./my-gap.js

# OID Resolver - point at a running server
npx synoi-conformance --protocol=oid-resolver \
  --url=http://localhost:4000 \
  --auth="Bearer my-resolver-token"

# Everything at once
npx synoi-conformance --all \
  --impl-dir=./impls \
  --resolver-url=http://localhost:4000 \
  --auth="Bearer my-resolver-token"

# CI-friendly JSON
npx synoi-conformance --protocol=sraid --impl=./my-sraid.js --reporter=json
```

Exit code 0 on full pass, 1 on any failure or usage error.

## What gets tested

### SRAID (`@synoi/sraid`, wire protocol id `sraid`)
- `canonicalize(x)` matches the reference for 9 inputs (empty object, nested, arrays, integer, fractional double, embedded quote, unicode, etc.)
- `oidOf(x)` matches the reference for the same 9 inputs
- `verifySignature(args)` returns the expected valid/invalid outcome for 4 legacy bare-bytes signature vectors (valid, tampered payload, wrong key, tampered ed25519 sig)
- `verifyAttestation(args)` returns the expected outcome for 5 DSSE attestation vectors (valid hybrid; cross-type confusion blocked by PAE type-binding; expectedPayloadType pin mismatch; missing ml-dsa-65 → hybrid AND policy; tampered payload). The cross-type vector is the T11 fix: signatures minted for one `payloadType` must not verify under another even with identical payload bytes.
- `verifyReceiptV2(args)` returns the expected outcome for 10 Receipt v2 vectors (`receipt_scheme "synoi.receipt/v2"`, payloadType `application/vnd.synoi.gap+json`): one canonical-bytes + OID vector asserting the content-core bytes exactly (no crypto); a valid hybrid receipt → TRUE; and 8 must-fail vectors - ml-dsa-65 stripped (proves PQ-verify engages) / corrupted; ed25519 stripped / corrupted; tampered `settlement.cost.amount` → `payload-core-mismatch`; wrong `payloadType` → `payload-type-mismatch`; missing attestation; wrong ml-dsa key. A v2 receipt is a CDRO carrying a DSSE `attestation`; the verifier binds `canonicalize(cdroContentCore(receipt))` to the envelope payload, then hybrid-verifies (ed25519 AND ml-dsa-65, both required). `verifyReceiptV2` is composed from the L0 primitives `cdroContentCore` + `canonicalize` + `verifyAttestation`.

### GAP (`@synoi/gap-types`)
- 24 validator vectors across 6 top-level types (CapabilityDeclaration, Grant, Invocation, WorkflowDefinition, DecisionReceipt, RevocationEvent). Each type has: well-formed → ok=true; missing field → ok=false; wrong-type field → ok=false; extra unknown key → ok=true (forward compat).
- 6 `computeGapOid` vectors with fixed inputs + expected outputs.

### OID Resolver
- 11 sequence vectors covering health, resolve known/unknown, announce with/without auth, batch resolve, revocations listing (with filters + bad input, including the deliberate `target_kind=decision_receipt` exclusion), malformed-OID rejection.

### Inference Broker
- Stub (by honesty gate, not absence). `vectors/inference-broker/inference.json` runs 17 vectors against the real `@synoi/broker` reference implementation (complexity scoring, arbitrage, receipt shape, coalescence, model registry), but the broker does not yet ship DSSE-signed hybrid-verified (ed25519 AND ml-dsa-65) receipts. Every result is forced to `status='stub'`, never counted in `passed`/`failed`, and the protocol is excluded from the conformance badge (`badge.conformant_protocols`, `badge.vectors_passed`, `badge.vectors_total`) so a stub protocol can never inflate the headline pass rate.

## Regenerating vectors

When the reference packages change, regenerate the SRAID + GAP vector packs (the SRAID pack uses the wire protocol id `sraid`, so its script and directory are `gen:sraid` / `vectors/sraid/`):

```bash
npm run gen:sraid       # writes vectors/sraid/{canonicalize,oid,signatures,attestation,authority}.json
npm run gen:gap         # writes vectors/gap/{validate,oid}.json
npm run gen:receipt-v2  # writes vectors/sraid/receipt-v2.json (10 Receipt v2 vectors)
npm run gen:all         # all three (+ receipt-v1, vault-roundtrip, mldsa-interop, adr019)
```

The generators import `@synoi/sraid` and `@synoi/gap-types` and capture their outputs. **Reference impl outputs = the spec for the v1 vectors.** If the spec drifts ahead of the impl, vectors should be re-grounded against the new spec; for now they track the reference.

## Implementation shape (what your candidate must export)

### SRAID candidate (wire protocol id `sraid`)
```ts
export function canonicalize(x: unknown): string
export function oidOf(x: unknown): string
export function verifySignature(args: {
  canonical:   string | Uint8Array
  envelope:    { ed25519: string; ml_dsa_65: string; signer_kid: string }
  ed25519_pub: Uint8Array
  ml_dsa_pub:  Uint8Array
}): { valid: boolean; reasons: string[] }

// K1 Receipt v2 (optional): bind canonicalize(cdroContentCore(receipt)) to the
// DSSE envelope payload, then hybrid-verify (ed25519 AND ml-dsa-65).
export function verifyReceiptV2(args: {
  receipt:     Record<string, unknown>
  ed25519_pub: Uint8Array
  ml_dsa_pub:  Uint8Array
}): { valid: boolean; reasons: string[] }
```

### GAP candidate
```ts
export function computeGapOid(body: {
  type: string; tenant_id: string; created_at_ms: number; body: unknown
}): string

export function validateCapabilityDeclaration(x: unknown): { ok: boolean; errors: string[] }
export function validateCapabilityGrant(x: unknown):       { ok: boolean; errors: string[] }
export function validateCapabilityInvocation(x: unknown):  { ok: boolean; errors: string[] }
export function validateWorkflowDefinition(x: unknown):    { ok: boolean; errors: string[] }
export function validateGapDecisionReceipt(x: unknown):    { ok: boolean; errors: string[] }
export function validateRevocationEvent(x: unknown):       { ok: boolean; errors: string[] }
```

### OID Resolver candidate
Any HTTP server listening on `--url` that implements the spec endpoints. Auth via the `--auth` header value.

## Adding a new protocol or backend

Drop a `src/protocols/<protocol>.ts` file exposing `run<Protocol>Vectors(input, vectors): Promise<VectorResult[]>`, add a switch arm in `src/runner.ts`, write vectors at `vectors/<protocol>/`. Add a meta-test at `test/<protocol>-conformance.test.ts` that loads the reference impl and asserts every vector passes.

## Layout

```
src/
  cli.ts              argv parser + dispatch
  runner.ts           orchestrate + iterate
  reporter.ts         text + JSON reporters
  types.ts            Vector / VectorResult / RunReport / Reporter
  protocols/
    sraid.ts          loads JS module + runs vectors
    gap.ts            same
    oid-resolver.ts   HTTP black-box runner
    inference-broker.ts  stub
vectors/
  sraid/{canonicalize,oid,signatures,attestation,authority,lineage,sensitivity,receipt-v2}.json
  gap/{validate,oid}.json
  oid-resolver/sequences.json
  inference-broker/README.md         (stub - vectors coming)
test/
  runner.test.ts             meta-tests
  sraid-conformance.test.ts  reference impl conformance
  gap-conformance.test.ts    "
  resolver-conformance.test.ts "
```

## License

Apache 2.0. The patent grant is important: corporate users include compliance proofs (this suite's output) in their products without inheriting MIT/CC0 license worries.
