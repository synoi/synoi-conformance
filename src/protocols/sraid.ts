// protocols/sraid.ts - SRAID conformance vectors → candidate impl.

import type { Vector, VectorResult } from '../types.js'

interface SraidImpl {
  canonicalize(x: unknown): string
  oidOf(x: unknown): string
  verifySignature(args: {
    canonical:   string | Uint8Array
    envelope:    { ed25519: string; ml_dsa_65: string; signer_kid: string }
    ed25519_pub: Uint8Array
    ml_dsa_pub:  Uint8Array
  }): { valid: boolean; reasons: string[] }
  // L2 DSSE attestation verifier (PAE type-binding, hybrid both-required).
  // Optional so older impls still load; an attestation vector against an impl
  // that lacks it is reported as a clear failure.
  verifyAttestation?(args: {
    envelope: {
      payloadType: string
      payload:     string
      signatures:  Array<{ alg: string; sig: string; keyid?: string }>
    }
    ed25519_pub:         Uint8Array
    ml_dsa_pub:          Uint8Array
    expectedPayloadType?: string
  }): { valid: boolean; reasons: string[] }
  // L4 authority verifier. Optional so older impls still load; an authority
  // vector against an impl that lacks it is reported as a clear failure.
  verifyAuthority?(args: {
    object:             Record<string, unknown>
    action?:            string
    grant?:             Record<string, unknown>
    grant_ed25519_pub?: Uint8Array
    grant_ml_dsa_pub?:  Uint8Array
    // Wall-clock instant the expiry check is evaluated at. Optional by design:
    // omitting it means NO clock check ran, which the result reports through
    // expiry_checked_at_now rather than by silently passing.
    now_ms?:            number
  }): {
    authorized: boolean; reasons: string[]
    expiry_checked_at_now?: boolean
    not_expired_at_now?:    boolean
  }
  // L3 lineage. Optional so older impls still load; a lineage vector against
  // an impl that lacks these is reported as a clear failure.
  lineageLinks?(cdro: Record<string, unknown>): Array<{ rel: string; oid: string }>
  latestWins?(versions: ReadonlyArray<Record<string, unknown>>): {
    ok: boolean; head?: string; reasons: string[]
  }
  // L4 sensitivity (coarse opaque tier + monotone max() carry-forward).
  // Optional so older impls still load; a sensitivity vector against an impl
  // that lacks these is reported as a clear failure.
  sensitivityCarryForward?(sources: ReadonlyArray<string | undefined | null>): string
  cdroOid?(cdro: Record<string, unknown>): string
  // K1 Receipt v2: bind canonicalize(cdroContentCore(receipt)) to the DSSE
  // envelope payload, then hybrid-verify (ed25519 AND ml-dsa-65). Optional so
  // older impls still load; a receipt_v2 vector against an impl that lacks it
  // is reported as a clear failure. cdroContentCore + canonicalize are used by
  // the canonical-mode vector to assert the content-core bytes + OID exactly.
  verifyReceiptV2?(args: {
    receipt:     Record<string, unknown>
    ed25519_pub: Uint8Array
    ml_dsa_pub:  Uint8Array
  }): { valid: boolean; reasons: string[] }
  cdroContentCore?(cdro: Record<string, unknown>): unknown
  // K2 Delegation chain verifier. Optional so older impls still load; a chain
  // vector against an impl that lacks it is reported as a clear failure.
  verifyDelegationChain?(args: {
    leaf:        Record<string, unknown>
    ancestors:   Record<string, unknown>[]
    linkPubkeys: Array<{ ed25519: Uint8Array; ml_dsa: Uint8Array }>
    rootPubkeys: { ed25519: Uint8Array; ml_dsa: Uint8Array }
    action?:     string
    now_ms?:     number
  }): {
    authorized: boolean; reasons: string[]
    expiry_checked_at_now?: boolean
    not_expired_at_now?:    boolean
  }
}

export async function runSraidVectors(implPath: string, vectors: Vector[]): Promise<VectorResult[]> {
  const impl = await loadImpl(implPath)
  const out: VectorResult[] = []

  for (const v of vectors) {
    if (v['kind'] === 'canonicalize') {
      out.push(runCanonicalizeVector(impl, v))
    } else if (v['kind'] === 'canonicalize_reject') {
      out.push(runCanonicalizeRejectVector(impl, v))
    } else if (v['kind'] === 'oid') {
      out.push(runOidVector(impl, v))
    } else if (v['kind'] === 'signature') {
      out.push(runSignatureVector(impl, v))
    } else if (v['kind'] === 'attestation') {
      out.push(runAttestationVector(impl, v))
    } else if (v['kind'] === 'authority') {
      out.push(runAuthorityVector(impl, v))
    } else if (v['kind'] === 'lineage') {
      out.push(runLineageVector(impl, v))
    } else if (v['kind'] === 'sensitivity') {
      out.push(runSensitivityVector(impl, v))
    } else if (v['kind'] === 'receipt_v2') {
      out.push(runReceiptV2Vector(impl, v))
    } else if (v['kind'] === 'oid_determinism') {
      out.push(runOidDeterminismVector(impl, v))
    } else if (v['kind'] === 'cdro_roundtrip') {
      out.push(runCdroRoundtripVector(impl, v))
    } else if (v['kind'] === 'chain') {
      out.push(runChainVector(impl, v))
    } else {
      out.push({
        vector_name: v.name, passed: false,
        reason: `unknown vector kind: ${String(v['kind'])}`,
      })
    }
  }
  return out
}

async function loadImpl(p: string): Promise<SraidImpl> {
  const url = pathToFileUrl(p)
  const mod = await import(url) as Record<string, unknown>
  // Allow `default` re-export or top-level exports.
  const src = mod['default'] && typeof mod['default'] === 'object'
    ? mod['default'] as Record<string, unknown>
    : mod
  const req = ['canonicalize', 'oidOf', 'verifySignature'] as const
  for (const k of req) {
    if (typeof src[k] !== 'function') {
      throw new Error(`SRAID impl ${p} missing export "${k}"`)
    }
  }
  return src as unknown as SraidImpl
}

function runCanonicalizeVector(impl: SraidImpl, v: Vector): VectorResult {
  const input    = v['input']
  const expected = String(v['expected_canonical'])
  let actual: string
  try { actual = impl.canonicalize(input) }
  catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
  if (actual !== expected) {
    return { vector_name: v.name, passed: false, reason: 'canonical bytes mismatch', expected, actual }
  }
  return { vector_name: v.name, passed: true }
}

// canonicalize_reject vectors: the input MUST cause the impl to throw.
// RFC 8785 requires rejection of NaN and Infinity; a conformant impl
// MUST NOT silently coerce those values to null.
function runCanonicalizeRejectVector(impl: SraidImpl, v: Vector): VectorResult {
  const input = v['input_description']  // description only - actual value is JS-side
  // The vector carries a `js_eval` string that encodes the actual value
  // (e.g. "NaN", "Infinity") which cannot be expressed in JSON.
  // The runner evaluates it safely with a fixed allowlist.
  const jsEval = String(v['js_eval'] ?? '')
  let actualInput: unknown
  try {
    actualInput = evalJsLiteral(jsEval)
  } catch (_e) {
    return { vector_name: v.name, passed: false, reason: `cannot evaluate js_eval: ${jsEval}` }
  }
  let threw = false
  try { impl.canonicalize(actualInput) } catch (_e) { threw = true }
  if (!threw) {
    return {
      vector_name: v.name, passed: false,
      reason: `expected canonicalize to throw for ${input ?? jsEval} but it did not`,
    }
  }
  return { vector_name: v.name, passed: true }
}

/**
 * Evaluate a safe JS literal from a fixed allowlist (no eval of arbitrary code).
 *
 * Accepts the three non-finite sentinels (which cannot be expressed in JSON) and
 * ANY finite numeric literal (e.g. "3.14", "1e-10"). The numeric case exists for
 * ADR_019 float-reject vectors: a non-integer number like 3.14 IS valid JSON, so
 * it round-trips through a JSON vector as a real number, but the ADR_019 number
 * rule forbids it - the runner must feed the actual float to `canonicalize` and
 * assert it throws. Parsing is strict: only a value that `Number()` maps to a
 * finite number (or the three sentinels) is allowed; anything else throws, so no
 * arbitrary expression can slip through.
 */
function evalJsLiteral(expr: string): unknown {
  const t = expr.trim()
  switch (t) {
    case 'NaN':       return NaN
    case 'Infinity':  return Infinity
    case '-Infinity': return -Infinity
  }
  // Strict finite-number literal (covers ADR_019 non-integer reject inputs).
  if (/^-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(t)) {
    const n = Number(t)
    if (Number.isFinite(n)) return n
  }
  throw new Error(`js_eval allowlist: unknown expression "${expr}"`)
}

function runOidVector(impl: SraidImpl, v: Vector): VectorResult {
  const input    = v['input']
  const expected = String(v['expected_oid'])
  let actual: string
  try { actual = impl.oidOf(input) }
  catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
  if (actual !== expected) {
    return { vector_name: v.name, passed: false, reason: 'oid mismatch', expected, actual }
  }
  return { vector_name: v.name, passed: true }
}

function runSignatureVector(impl: SraidImpl, v: Vector): VectorResult {
  try {
    const result = impl.verifySignature({
      canonical:   String(v['canonical']),
      envelope:    v['envelope'] as { ed25519: string; ml_dsa_65: string; signer_kid: string },
      ed25519_pub: b64ToBytes(String(v['ed25519_pub_b64'])),
      ml_dsa_pub:  b64ToBytes(String(v['ml_dsa_pub_b64'])),
    })
    const expectedValid = v['expected_valid'] === true
    if (result.valid !== expectedValid) {
      return {
        vector_name: v.name, passed: false,
        reason: `expected valid=${expectedValid}, got ${result.valid} (${result.reasons.join(',')})`,
      }
    }
    return { vector_name: v.name, passed: true }
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
}

function runAttestationVector(impl: SraidImpl, v: Vector): VectorResult {
  if (typeof impl.verifyAttestation !== 'function') {
    return {
      vector_name: v.name, passed: false,
      reason: 'impl does not export verifyAttestation (L2 DSSE attestation unsupported)',
    }
  }
  try {
    const args: {
      envelope: {
        payloadType: string
        payload:     string
        signatures:  Array<{ alg: string; sig: string; keyid?: string }>
      }
      ed25519_pub:          Uint8Array
      ml_dsa_pub:           Uint8Array
      expectedPayloadType?: string
    } = {
      envelope:    v['envelope'] as {
        payloadType: string
        payload:     string
        signatures:  Array<{ alg: string; sig: string; keyid?: string }>
      },
      ed25519_pub: b64ToBytes(String(v['ed25519_pub_b64'])),
      ml_dsa_pub:  b64ToBytes(String(v['ml_dsa_pub_b64'])),
    }
    if (v['expected_payload_type'] !== undefined) {
      args.expectedPayloadType = String(v['expected_payload_type'])
    }
    const result = impl.verifyAttestation(args)
    const expectedValid = v['expected_valid'] === true
    if (result.valid !== expectedValid) {
      return {
        vector_name: v.name, passed: false,
        reason: `expected valid=${expectedValid}, got ${result.valid} (${result.reasons.join(',')})`,
      }
    }
    return { vector_name: v.name, passed: true }
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
}

function runAuthorityVector(impl: SraidImpl, v: Vector): VectorResult {
  if (typeof impl.verifyAuthority !== 'function') {
    return {
      vector_name: v.name, passed: false,
      reason: 'impl does not export verifyAuthority (L4 authority unsupported)',
    }
  }
  try {
    const args: {
      object:             Record<string, unknown>
      action?:            string
      grant?:             Record<string, unknown>
      grant_ed25519_pub?: Uint8Array
      grant_ml_dsa_pub?:  Uint8Array
      now_ms?:            number
    } = { object: v['object'] as Record<string, unknown> }
    if (v['action'] !== undefined) args.action = String(v['action'])
    if (v['grant'] !== undefined) args.grant = v['grant'] as Record<string, unknown>
    if (v['grant_ed25519_pub_b64'] !== undefined) {
      args.grant_ed25519_pub = b64ToBytes(String(v['grant_ed25519_pub_b64']))
    }
    if (v['grant_ml_dsa_pub_b64'] !== undefined) {
      args.grant_ml_dsa_pub = b64ToBytes(String(v['grant_ml_dsa_pub_b64']))
    }
    if (v['now_ms'] !== undefined) args.now_ms = Number(v['now_ms'])
    const result = impl.verifyAuthority(args)
    const expected = v['expected_authorized'] === true
    if (result.authorized !== expected) {
      return {
        vector_name: v.name, passed: false,
        reason: `expected authorized=${expected}, got ${result.authorized} (${result.reasons.join(',')})`,
      }
    }
    const live = livenessMismatch(v, result)
    if (live) return { vector_name: v.name, passed: false, reason: live }
    return { vector_name: v.name, passed: true }
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
}

function runLineageVector(impl: SraidImpl, v: Vector): VectorResult {
  const mode = String(v['mode'])
  try {
    if (mode === 'links') {
      if (typeof impl.lineageLinks !== 'function') {
        return {
          vector_name: v.name, passed: false,
          reason: 'impl does not export lineageLinks (L3 lineage unsupported)',
        }
      }
      const actual = impl.lineageLinks(v['object'] as Record<string, unknown>)
      const expected = v['expected_links'] as Array<{ rel: string; oid: string }>
      const a = JSON.stringify(actual)
      const e = JSON.stringify(expected)
      if (a !== e) {
        return { vector_name: v.name, passed: false, reason: 'lineage links mismatch', expected: e, actual: a }
      }
      return { vector_name: v.name, passed: true }
    }

    if (mode === 'latest_wins') {
      if (typeof impl.latestWins !== 'function') {
        return {
          vector_name: v.name, passed: false,
          reason: 'impl does not export latestWins (L3 lineage unsupported)',
        }
      }
      const result = impl.latestWins(v['versions'] as Array<Record<string, unknown>>)
      const expectedOk = v['expected_ok'] === true
      if (result.ok !== expectedOk) {
        return {
          vector_name: v.name, passed: false,
          reason: `expected ok=${expectedOk}, got ${result.ok} (${result.reasons.join(',')})`,
        }
      }
      if (expectedOk && v['expected_head'] !== undefined && result.head !== String(v['expected_head'])) {
        return {
          vector_name: v.name, passed: false,
          reason: 'head mismatch', expected: String(v['expected_head']), actual: String(result.head),
        }
      }
      return { vector_name: v.name, passed: true }
    }

    return { vector_name: v.name, passed: false, reason: `unknown lineage mode: ${mode}` }
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
}

function runSensitivityVector(impl: SraidImpl, v: Vector): VectorResult {
  const mode = String(v['mode'])
  try {
    if (mode === 'carry_forward') {
      if (typeof impl.sensitivityCarryForward !== 'function') {
        return {
          vector_name: v.name, passed: false,
          reason: 'impl does not export sensitivityCarryForward (L4 sensitivity unsupported)',
        }
      }
      const sources = v['sources'] as Array<string | null>
      const expected = String(v['expected_tier'])
      const actual = impl.sensitivityCarryForward(sources)
      if (actual !== expected) {
        return { vector_name: v.name, passed: false, reason: 'carry-forward tier mismatch', expected, actual }
      }
      return { vector_name: v.name, passed: true }
    }

    if (mode === 'carry_forward_throws') {
      if (typeof impl.sensitivityCarryForward !== 'function') {
        return {
          vector_name: v.name, passed: false,
          reason: 'impl does not export sensitivityCarryForward (L4 sensitivity unsupported)',
        }
      }
      const sources = v['sources'] as Array<string | null>
      let threw = false
      try { impl.sensitivityCarryForward(sources) } catch { threw = true }
      if (!threw) {
        return { vector_name: v.name, passed: false, reason: 'expected carry-forward to throw on an unknown tier, but it did not' }
      }
      return { vector_name: v.name, passed: true }
    }

    if (mode === 'oid_binding') {
      // The sensitivity tier is hashed into the OID: two CDROs that differ
      // ONLY in `sensitivity` MUST produce different OIDs (so the tier cannot
      // be silently stripped or downgraded). `expected_distinct` asserts the
      // two OIDs differ; an absent `b` (same object) asserts they match.
      if (typeof impl.cdroOid !== 'function') {
        return {
          vector_name: v.name, passed: false,
          reason: 'impl does not export cdroOid (cannot check sensitivity OID-binding)',
        }
      }
      const a = impl.cdroOid(v['a'] as Record<string, unknown>)
      const b = impl.cdroOid(v['b'] as Record<string, unknown>)
      const expectedDistinct = v['expected_distinct'] === true
      const actualDistinct = a !== b
      if (actualDistinct !== expectedDistinct) {
        return {
          vector_name: v.name, passed: false,
          reason: `expected distinct=${expectedDistinct}, got ${actualDistinct} (a=${a}, b=${b})`,
        }
      }
      return { vector_name: v.name, passed: true }
    }

    return { vector_name: v.name, passed: false, reason: `unknown sensitivity mode: ${mode}` }
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
}

// K1 Receipt v2. Two vector shapes share the `receipt_v2` kind:
//   mode === 'canonical' - no crypto: assert canonicalize(cdroContentCore(r))
//     equals expected_content_core AND cdroOid(r) equals expected_oid. Proves
//     byte-identical canonicalization of the content core. Bytes are exact.
//   default (verify) - call verifyReceiptV2 and compare valid to expected_valid;
//     when expected_valid is false and expected_reason is present, also assert
//     the reason is reported (mirrors @synoi/verify's reason assertions).
function runReceiptV2Vector(impl: SraidImpl, v: Vector): VectorResult {
  if (v['mode'] === 'canonical') {
    if (typeof impl.canonicalize !== 'function' || typeof impl.cdroContentCore !== 'function') {
      return {
        vector_name: v.name, passed: false,
        reason: 'impl does not export canonicalize + cdroContentCore (cannot check content-core bytes)',
      }
    }
    try {
      const receipt = v['receipt'] as Record<string, unknown>
      const actualCore = impl.canonicalize(impl.cdroContentCore(receipt))
      const expectedCore = String(v['expected_content_core'])
      if (actualCore !== expectedCore) {
        return {
          vector_name: v.name, passed: false,
          reason: 'content-core bytes mismatch', expected: expectedCore, actual: actualCore,
        }
      }
      if (v['expected_oid'] !== undefined) {
        if (typeof impl.cdroOid !== 'function') {
          return {
            vector_name: v.name, passed: false,
            reason: 'impl does not export cdroOid (cannot check receipt OID)',
          }
        }
        const actualOid = impl.cdroOid(receipt)
        const expectedOid = String(v['expected_oid'])
        if (actualOid !== expectedOid) {
          return { vector_name: v.name, passed: false, reason: 'oid mismatch', expected: expectedOid, actual: actualOid }
        }
      }
      return { vector_name: v.name, passed: true }
    } catch (err) {
      return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
    }
  }

  if (typeof impl.verifyReceiptV2 !== 'function') {
    return {
      vector_name: v.name, passed: false,
      reason: 'impl does not export verifyReceiptV2 (K1 receipt-v2 unsupported)',
    }
  }
  try {
    const result = impl.verifyReceiptV2({
      receipt:     v['receipt'] as Record<string, unknown>,
      ed25519_pub: b64ToBytes(String(v['ed25519_pub_b64'])),
      ml_dsa_pub:  b64ToBytes(String(v['ml_dsa_pub_b64'])),
    })
    const expectedValid = v['expected_valid'] === true
    if (result.valid !== expectedValid) {
      return {
        vector_name: v.name, passed: false,
        reason: `expected valid=${expectedValid}, got ${result.valid} (${result.reasons.join(',')})`,
      }
    }
    if (!expectedValid && v['expected_reason'] !== undefined) {
      const wanted = String(v['expected_reason'])
      if (!result.reasons.includes(wanted)) {
        return {
          vector_name: v.name, passed: false,
          reason: `expected reason "${wanted}", got reasons [${result.reasons.join(',')}]`,
        }
      }
    }
    return { vector_name: v.name, passed: true }
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
}

// OID determinism: assert that oidOf called twice on the same input yields the same OID.
// The vector carries expected_oid_1 and expected_oid_2 which are identical by construction
// (both come from the reference impl). A non-deterministic impl would produce different values.
function runOidDeterminismVector(impl: SraidImpl, v: Vector): VectorResult {
  const input = v['input']
  const exp1  = String(v['expected_oid_1'])
  const exp2  = String(v['expected_oid_2'])
  if (exp1 !== exp2) {
    return {
      vector_name: v.name, passed: false,
      reason: 'vector authoring error: expected_oid_1 !== expected_oid_2 (non-deterministic generator)',
    }
  }
  let a1: string, a2: string
  try {
    a1 = impl.oidOf(input)
    a2 = impl.oidOf(input)
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
  if (a1 !== exp1) {
    return { vector_name: v.name, passed: false, reason: 'oid mismatch', expected: exp1, actual: a1 }
  }
  if (a1 !== a2) {
    return {
      vector_name: v.name, passed: false,
      reason: `non-deterministic oidOf: first call=${a1}, second call=${a2}`,
    }
  }
  return { vector_name: v.name, passed: true }
}

// CDRO round-trip: assert that cdroContentCore is deterministic and that cdroOid matches
// oidOf(cdroContentCore(cdro)). The vector carries expected values grounded in the reference impl.
function runCdroRoundtripVector(impl: SraidImpl, v: Vector): VectorResult {
  const cdro = v['cdro'] as Record<string, unknown>

  if (v['expected_deterministic'] !== undefined) {
    // Determinism mode: cdroContentCore must return the same value on two calls.
    if (typeof impl.cdroContentCore !== 'function') {
      return {
        vector_name: v.name, passed: false,
        reason: 'impl does not export cdroContentCore (CDRO round-trip unsupported)',
      }
    }
    try {
      const core1 = impl.canonicalize(impl.cdroContentCore(cdro))
      const core2 = impl.canonicalize(impl.cdroContentCore(cdro))
      const exp1  = String(v['expected_content_core_1'])
      if (core1 !== exp1) {
        return { vector_name: v.name, passed: false, reason: 'content-core mismatch', expected: exp1, actual: core1 }
      }
      if (core1 !== core2) {
        return {
          vector_name: v.name, passed: false,
          reason: `cdroContentCore non-deterministic: first=${core1.slice(0,32)}..., second=${core2.slice(0,32)}...`,
        }
      }
      return { vector_name: v.name, passed: true }
    } catch (err) {
      return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
    }
  }

  if (v['expected_oid'] !== undefined) {
    // OID-binding mode: cdroOid must equal oidOf(cdroContentCore(cdro)).
    if (typeof impl.cdroOid !== 'function' || typeof impl.cdroContentCore !== 'function') {
      return {
        vector_name: v.name, passed: false,
        reason: 'impl does not export cdroOid + cdroContentCore (CDRO OID round-trip unsupported)',
      }
    }
    try {
      const oid  = impl.cdroOid(cdro)
      // oidOf(cdroContentCore(cdro)) - the content-core is an object, so oidOf
      // canonicalizes it (hash over the object's canonical form, same as cdroOid).
      // Do NOT pass canonicalize(cdroContentCore(cdro)) to oidOf, as that would
      // hash the canonical form of a string (adding JSON quotes), yielding a different hash.
      const core    = impl.cdroContentCore(cdro)
      const coreOid = impl.oidOf(core as unknown)
      const expOid  = String(v['expected_oid'])
      const expCore = String(v['expected_core_oid'])
      if (oid !== expOid) {
        return { vector_name: v.name, passed: false, reason: 'cdroOid mismatch', expected: expOid, actual: oid }
      }
      if (coreOid !== expCore) {
        return { vector_name: v.name, passed: false, reason: 'core oid mismatch', expected: expCore, actual: coreOid }
      }
      if (oid !== coreOid) {
        return {
          vector_name: v.name, passed: false,
          reason: `cdroOid !== oidOf(cdroContentCore(cdro)): ${oid} vs ${coreOid}`,
        }
      }
      return { vector_name: v.name, passed: true }
    } catch (err) {
      return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
    }
  }

  return { vector_name: v.name, passed: false, reason: 'cdro_roundtrip vector missing expected_deterministic or expected_oid' }
}

// K2 Delegation chain. The vector carries:
//   leaf, ancestors: CDRO objects (plain JSON)
//   link_pubkeys_b64: array of { ed25519_b64, ml_dsa_b64 }, index-aligned to [leaf, ...ancestors]
//   root_pubkeys_b64: { ed25519_b64, ml_dsa_b64 }
//   action: optional string
//   expected_authorized: boolean
//   expected_reason: optional substring; when present and expected_authorized===false,
//     the reason string must appear (substring match) in result.reasons
function runChainVector(impl: SraidImpl, v: Vector): VectorResult {
  if (typeof impl.verifyDelegationChain !== 'function') {
    return {
      vector_name: v.name, passed: false,
      reason: 'impl does not export verifyDelegationChain (K2 delegation chain unsupported)',
    }
  }
  try {
    const leaf      = v['leaf']      as Record<string, unknown>
    const ancestors = v['ancestors'] as Record<string, unknown>[]
    const lpRaw     = v['link_pubkeys_b64'] as Array<{ ed25519_b64: string; ml_dsa_b64: string }>
    const rpRaw     = v['root_pubkeys_b64'] as { ed25519_b64: string; ml_dsa_b64: string }

    const linkPubkeys = lpRaw.map(k => ({
      ed25519: b64ToBytes(k.ed25519_b64),
      ml_dsa:  b64ToBytes(k.ml_dsa_b64),
    }))
    const rootPubkeys = {
      ed25519: b64ToBytes(rpRaw.ed25519_b64),
      ml_dsa:  b64ToBytes(rpRaw.ml_dsa_b64),
    }

    const args: Parameters<NonNullable<SraidImpl['verifyDelegationChain']>>[0] = {
      leaf, ancestors, linkPubkeys, rootPubkeys,
    }
    if (v['action'] !== undefined) args.action = String(v['action'])
    if (v['now_ms'] !== undefined) args.now_ms = Number(v['now_ms'])

    const result = impl.verifyDelegationChain(args)
    const expected = v['expected_authorized'] === true

    if (result.authorized !== expected) {
      return {
        vector_name: v.name, passed: false,
        reason: `expected authorized=${expected}, got ${result.authorized} (${result.reasons.join(',')})`,
      }
    }
    if (!expected && v['expected_reason'] !== undefined) {
      const wanted = String(v['expected_reason'])
      const found = result.reasons.some(r => r.includes(wanted))
      if (!found) {
        return {
          vector_name: v.name, passed: false,
          reason: `expected reason containing "${wanted}", got reasons [${result.reasons.join(',')}]`,
        }
      }
    }
    const live = livenessMismatch(v, result)
    if (live) return { vector_name: v.name, passed: false, reason: live }
    return { vector_name: v.name, passed: true }
  } catch (err) {
    return { vector_name: v.name, passed: false, reason: `threw: ${(err as Error).message}` }
  }
}

// Shared liveness assertions. A vector that only asserts `expected_authorized`
// can pass for the WRONG REASON: an expired grant might be refused by a
// signature or scope gate while the clock check never ran at all. These let a
// vector pin that the wall-clock gate actually executed, and what it concluded.
function livenessMismatch(
  v: Vector,
  result: { expiry_checked_at_now?: boolean; not_expired_at_now?: boolean },
): string | null {
  if (v['expected_expiry_checked_at_now'] !== undefined) {
    const want = v['expected_expiry_checked_at_now'] === true
    if (result.expiry_checked_at_now !== want) {
      return `expected expiry_checked_at_now=${want}, got ${result.expiry_checked_at_now}`
    }
  }
  if (v['expected_not_expired_at_now'] !== undefined) {
    const want = v['expected_not_expired_at_now'] === true
    if (result.not_expired_at_now !== want) {
      return `expected not_expired_at_now=${want}, got ${result.not_expired_at_now}`
    }
  }
  return null
}

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64, 'base64'))
}

function pathToFileUrl(p: string): string {
  if (p.startsWith('file://')) return p
  // Cross-platform - Node's URL ctor handles Windows paths via pathToFileURL,
  // but we want to also accept package specifiers like '@synoi/sraid'.
  if (!p.includes('/') && !p.includes('\\')) return p   // bare specifier
  // Absolute Windows path → file:///e:/...
  const abs = p.replace(/\\/g, '/')
  return abs.startsWith('/') ? `file://${abs}` : `file:///${abs}`
}
