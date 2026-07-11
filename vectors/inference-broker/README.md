# Inference Broker vectors - stub (honesty gate)

`inference.json` exercises the real `@synoi/broker` reference implementation (model complexity
scoring, arbitrage selection, receipt shape, coalescence, model registry) and every vector in
it runs against real code. But the broker does not yet ship DSSE-signed, hybrid-verified
(ed25519 AND ml-dsa-65) receipts the way SRAID's `verifyReceiptV2` does - so this protocol is
still marked `stub` in the runner (see `STUB_PROTOCOLS` in `src/runner.ts`).

Every `inference-broker` result is forced to `status='stub'` regardless of what the per-vector
check returns. Stub results are never counted in `passed` or `failed`, and the protocol is
excluded from `badge.conformant_protocols` / `badge.vectors_passed` / `badge.vectors_total`
entirely. This is deliberate: a protocol with no real cryptographic proof must not be able to
inflate the headline conformance badge just because its vectors happen to execute cleanly.

Remove `inference-broker` from `STUB_PROTOCOLS` only when it ships DSSE-signed receipts with
hybrid verify meeting the same bar as SRAID's `verifyReceiptV2` (see `vectors/sraid/receipt-v2.json`
for the target shape), and add vectors here that assert against that hybrid verification path.
