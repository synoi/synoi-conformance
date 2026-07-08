# fabric-crossenv: minimal cross-language, cross-implementation receipt chain

A MINIMAL PROOF, not a product. It shows two INDEPENDENT, non-gateway
runtimes, written in two DIFFERENT LANGUAGES, emitting a SINGLE linked,
offline-verifiable receipt chain under one operator identity. It proves
two axes at once:

- **implementation independence, now genuinely cross-language**: R1 is
  emitted by a real Rust binary (`emit-governed-action-fixture`, built from
  `synoi-gateway/runtime/b1-harness`); R2 is emitted by a TypeScript script
  that imports none of Runtime A's code, none of the gateway's private
  signing code, and generates its own independent keypair. R1 and R2 verify
  under two different `verifying_key_id` values.
- **chain-linking across the boundary**: R2 carries `prev = R1.oid` INSIDE
  its signed canonical payload, so the two receipts form one tamper-evident
  chain, not two unrelated objects that happen to sit in the same file.

## Which cross-language path was used, and why

Rust, the preferred path. `cargo --version` reported 1.96.0 present, so the
Python fallback was not needed.

Runtime A does not run `cargo build` against the full workspace. It
executes the ALREADY-BUILT binary at
`synoi-gateway/runtime/b1-harness/target/debug/emit-governed-action-fixture.exe`
(the same fixture that already backs
`synoi-conformance/vectors/_verify-governed-action-xlang.ts`). This is
READ-ONLY use of the gateway repo: running a compiled artifact and reading
its stdout, nothing written to gateway source, nothing built. `git status`
in `synoi-gateway` was checked before and after; no gateway file changed
(see REPORT for the transcript). If the binary is ever missing, the emitter
script falls back to `cargo build --bin emit-governed-action-fixture`,
scoped to that one bin target only, never the full workspace and never
WASM; that fallback was not exercised in this run because the binary was
already present.

## Honesty tradeoffs this closure required

The Rust fixture's payload is FIXED in its own source
(`b1-harness/src/bin/emit_governed_action_fixture.rs`, `main()` takes no
parameters): it always emits subject `governed-action.allowed`,
`body.action_kind = "render-panel"`, `tenant_id = "xlang-test"`. Per the
task's honesty constraint, R1 is NOT relabeled as a "game" action, that
would require parameterizing or editing the Rust source, which was
avoided. R1 is used byte-for-byte verbatim as the binary produced it.

Two consequences, both intentional and both documented here rather than
smoothed over:

1. **Tenant pinning.** `@synoi/verify-core` requires every receipt in one
   evidence bundle to share the bundle's declared `tenant_id`. Since R1's
   `tenant_id` is fixed at `"xlang-test"`, R2 (and the bundle) adopt that
   value instead of the earlier demo's `"demo-fabric-crossenv"`.
2. **Operator identity is now carried by R2, not by R1 itself.** R1's
   `created_by` is the Rust harness's own baked-in test identity (derived
   from `SHELL_RECEIPT_ED_SEED` / `SHELL_RECEIPT_ML_SEED`), not this demo's
   `OID_op`, because the fixed payload has no field for it. `OID_op` is
   real (`sha256:` + hex(sha256(canonicalize(descriptor)))) and is bound
   into R2 (`R2.created_by = OID_op`, `R2.authority.subject_oid = OID_op`).
   The single-operator claim across the chain is therefore: "R2 was signed
   under OID_op, and R2 cryptographically points at R1 via `prev`,"
   not "R1 itself asserts OID_op." Making R1 carry OID_op would require
   editing the fixed Rust payload, which was avoided per the task's
   preference for read-only, minimal-or-none gateway changes.

The action-class axis from the earlier draft (game vs work) is replaced by
what is actually true of R1: it is a `render-panel` governed-action
receipt, one of the two fixed fixture receipts the Rust harness emits,
paired against R2's `calendar.write` (work) action. Two distinct action
classes, two distinct languages, one linked chain, no invented framing.

## What is proven

Run `verify-chain.ts` (see Reproduce below) with **no SynOI gateway process
running**. It:

1. Loads R1 (`out/r1.json`, Rust-emitted, unmodified) and R2
   (`out/r2.json`, TypeScript-emitted).
2. Assembles them into a `synoi-evidence-bundle-v2` and calls
   `@synoi/verify-core`'s **shipped** `verifyEvidenceBundle` (not a
   reimplementation), the same function the gateway's own self-verify and
   the `@synoi/verify` CLI both call.
3. Asserts BOTH Ed25519 AND ML-DSA-65 verify for EACH receipt
   (AND-enforced), under each receipt's OWN signer key (two different
   `verifying_key_id` values, one Rust-derived, one TypeScript-generated).
4. Asserts `R2.prev === R1.oid`.
5. Asserts R1 and R2 carry two distinct action classes
   (`render-panel` allow, `calendar.write`), and asserts (via
   `out/runtime-a-provenance.json`) that R1 really did come from the named
   Rust binary.
6. Runs a TAMPER test: flips one byte in R1's signed attestation payload
   and shows the bundle now fails (`content-digest-mismatch` +
   `receipt-signature-invalid`), and a second tamper test that edits a body
   field in R2 without re-signing and shows the payload-binding recompute
   catches it.

The last recorded run: `out/verify-transcript.txt`, **10 passed, 0
failed**. `out/receipts.json` holds R1 + R2 with real computed OIDs and
real hybrid signatures.

## What is NOT proven

- **Not court-admissible, not regulator-accepted.** The bundle's own
  `honesty` block says so explicitly; that is a legal determination this
  code cannot make.
- **Not identity-resolved.** `OID_op` is a real content-addressed OID, but
  it is NOT resolved through the SynOI OID Resolver against a real
  persona.
- **R1 does not itself assert OID_op** (see the honesty tradeoff above);
  the operator-identity claim runs through R2 plus the `prev` link.
- **Test keys, not production keys.** Runtime B generates a fresh Ed25519 +
  ML-DSA-65 keypair in-process on every run (`out/runtime-b-keys.secret.json`,
  labeled TEST KEYS ONLY). Runtime A's private key never leaves the Rust
  process; this demo only ever holds its PUBLIC key, exactly as a real
  separate implementation would hand off to a third-party verifier. The
  Rust fixture itself is tagged `PARTIAL-against-test-keys` at its source
  (`emit_governed_action_fixture.rs`); those are well-known fixed test
  seeds, never used for anything real.
- **No HITL hop.** This proof is exactly R1 -> R2, no out-of-band approval
  gate between them.
- **No absence statements, no Merkle-DAG beyond a two-node chain, no
  resolver, no revocation.** This is the smallest possible proof of the
  target axes, not a general evidence-export feature.

## Files

- `operator-identity.ts`: computes `OID_op` (writes `out/operator-identity.json`).
- `runtime-a-rust/emit-rust-receipt.ts`: Runtime A, Rust. Runs the
  prebuilt `emit-governed-action-fixture.exe`, captures its `allow_receipt`
  verbatim as R1, writes `out/r1.json`, `out/runtime-a-keys.pub.json`
  (derived from the fixture's own published public key hex), and
  `out/runtime-a-provenance.json` (which binary, what it emitted, the
  honesty caveat).
- `runtime-b-work/emit-work-receipt.ts`: Runtime B, TypeScript. Reads
  `out/r1.json` for `R1.oid` only (no shared signing code with Runtime A).
  Signs R2, a `calendar.write` decision receipt with `prev = R1.oid` and
  `created_by = OID_op`. Writes `out/r2.json` + `out/runtime-b-keys.pub.json`
  (+ `.secret.json`, test keys).
- `verify-chain.ts`: the standalone offline verifier described above.
  Writes `out/receipts.json` (the combined evidence) and prints the
  transcript.
- `runtime-a-game/emit-game-receipt.ts`: SUPERSEDED. The original
  all-TypeScript Runtime A from before this cross-language closure. Left in
  place for history; the active pipeline now uses `runtime-a-rust/` instead.
  Not part of the reproduce steps below.
- `out/`: generated evidence from the last run (checked in for review;
  regenerate any time with the commands below).

## Reproduce

From this directory, with no SynOI gateway process running:

```
npx tsx operator-identity.ts
npx tsx runtime-a-rust/emit-rust-receipt.ts
npx tsx runtime-b-work/emit-work-receipt.ts
npx tsx verify-chain.ts
```

Or capture a fresh transcript:

```
npx tsx verify-chain.ts > out/verify-transcript.txt 2>&1
```

## Why no gateway source change was needed

Every field the signed canonical projection needs
(`cdroContentCore`/`canonicalize`/`oidOfCanonical`/`pae`) is public in
`@synoi/sraid`'s published surface (`synoi-sraid/src/index.ts`), and the
verifier (`@synoi/verify-core` `verifyEvidenceBundle`,
`synoi-verify-core/src/bundle.ts`) recomputes the SAME
`canonicalize(cdroContentCore(receipt))` projection to check the
attestation payload, whether the signer was TypeScript or Rust. The Rust
fixture (`synoi-gateway/runtime/b1-harness/src/bin/emit_governed_action_fixture.rs`)
already signs under the same `GAP_RECEIPT_PAYLOAD_TYPE`
(`application/vnd.synoi.gap+json`) and the same canonicalization contract,
which is exactly why the pre-existing
`_verify-governed-action-xlang.ts` conformance vector and this demo's
`verify-chain.ts` both accept it without modification. Nothing here
required copying gateway-private code (e.g. `verify-router.ts`'s
`signCanonicalBytesHybrid` or the `SigningOracle` custody seam), those
exist to manage KEY CUSTODY inside the gateway, not to define the signed
byte shape, which is fully public. Zero gateway source files were changed;
`git status` in `synoi-gateway` before and after this closure is identical.
