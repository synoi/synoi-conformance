// ADR_019 conformance shim - invokes the REAL @synoi/gap Go SDK projection
// (gapcore.ComputeGapOid and gapcore.CdroOid) so the cross-language gate
// exercises shipped SDK code, not a re-modelled copy. The gap Go module is
// referenced by local path via `replace`; this is a test harness, never
// published.
module github.com/synoi/synoi-conformance/adr019-shim

go 1.22

require github.com/synoi/synoi-gap/go v0.0.0

replace github.com/synoi/synoi-gap/go => ../../../../synoi-gap/go
