// ADR_019 cross-language conformance shim (Go).
//
// Reads a single JSON object (a mixed-vector `input`) on stdin and prints, on
// stdout, the OID the REAL @synoi/gap Go SDK computes for it. As of ADR_019
// Wave 2 both ComputeGapOid and CdroOid use the SAME six-field content-core
// strip {oid, signature, ml_dsa_signature, signature_key_id,
// signature_algorithm, attestation} and KEEP gap_version+supersedes, so both
// now MATCH the sraid normative OID on the ADR_019 mixed vectors (green).
//
// Usage: printf '<json>' | go run . <mode>    where mode = computeGapOid | cdroOid
//
// The gate compares this stdout against the vector's expected_oid.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	gapcore "github.com/synoi/synoi-gap/go/gapcore"
)

func main() {
	mode := "computeGapOid"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		os.Exit(2)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		fmt.Fprintf(os.Stderr, "parse json: %v\n", err)
		os.Exit(2)
	}
	var oid string
	switch mode {
	case "cdroOid":
		oid, err = gapcore.CdroOid(obj)
	default:
		oid, err = gapcore.ComputeGapOid(obj)
	}
	if err != nil {
		// A canonicalize/reject error (e.g. a float vector) prints REJECT so the
		// gate can distinguish "rejected" from "wrong OID".
		fmt.Println("REJECT:" + err.Error())
		return
	}
	fmt.Println(oid)
}
