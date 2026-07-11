"""ADR_019 cross-language conformance shim (Python).

Reads a single JSON object (a mixed-vector ``input``) on stdin and prints, on
stdout, the OID the REAL @synoi/gap Python SDK computes for it via
``synoi_gap.oid.compute_gap_oid``. As of ADR_019 Wave 2 that projection strips
exactly the SIX detached-signature fields {oid, signature, ml_dsa_signature,
signature_key_id, signature_algorithm, attestation} and KEEPS
gap_version+supersedes, so it now MATCHES the sraid normative OID on the ADR_019
mixed vectors (green).

Usage: printf '<json>' | python shim.py

The path to the gap Python package is passed via the SYNOI_GAP_PY env var by the
gate so this file has no hard-coded absolute path.
"""
import json
import os
import sys

gap_py = os.environ.get("SYNOI_GAP_PY")
if gap_py:
    sys.path.insert(0, gap_py)

try:
    from synoi_gap.oid import compute_gap_oid
except Exception as exc:  # pragma: no cover - surfaced to the gate as an error
    sys.stderr.write(f"import synoi_gap failed: {exc}\n")
    sys.exit(2)

try:
    obj = json.load(sys.stdin)
except Exception as exc:
    sys.stderr.write(f"parse json: {exc}\n")
    sys.exit(2)

try:
    print(compute_gap_oid(obj))
except Exception as exc:
    # A float vector raises TypeError; report REJECT so the gate can tell a
    # rejection apart from a wrong OID.
    print("REJECT:" + str(exc))
