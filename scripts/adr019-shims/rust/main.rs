//! ADR_019 cross-language conformance shim (Rust).
//!
//! Reads a single JSON object (a mixed-vector `input`) on stdin and prints, on
//! stdout, the OID the REAL gap-core Rust SDK computes for it. As of ADR_019
//! Wave 2 the gap-core `compute_gap_oid` projection strips exactly the SIX
//! detached-signature fields {oid, signature, ml_dsa_signature,
//! signature_key_id, signature_algorithm, attestation} and KEEPS
//! gap_version+supersedes, so it now MATCHES the sraid normative OID on the
//! ADR_019 mixed vectors (green).
//!
//! Usage: printf '<json>' | adr019-shim <mode>   mode = computeGapOid | cdroOid

use std::io::Read;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "computeGapOid".to_string());
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        eprintln!("read stdin failed");
        std::process::exit(2);
    }
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse json: {e}");
            std::process::exit(2);
        }
    };
    let out = match mode.as_str() {
        // gap-core also ships cdro_oid (the same 6-field content-core projection,
        // fallible on non-object / float input). compute_gap_oid is the GAP
        // SDK's shipped OID; both now yield the sraid normative OID.
        "cdroOid" => match gap_core::cdro_oid(&value) {
            Ok(o) => o,
            Err(e) => format!("REJECT:{e}"),
        },
        _ => gap_core::compute_gap_oid(&value),
    };
    println!("{out}");
}
