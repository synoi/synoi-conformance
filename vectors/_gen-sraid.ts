// vectors/_gen-sraid.ts - produce canonical + oid + signature vectors against
// the @synoi/sraid reference impl. Run with `npm run gen:sraid`.
//
// Output files: vectors/sraid/canonicalize.json, oid.json, signatures.json.
// (The vectors/cof/ output directory was renamed to vectors/sraid/ in
// ADR_020 Wave 2, alongside this vector regeneration.)
// The expected values come straight from the reference impl, so when the
// spec changes, regenerate to refresh.

import { writeFileSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize, oidOf, cdroOid, cdroContentCore, pae } from '@synoi/sraid'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes } from 'node:crypto'

const here = dirname(fileURLToPath(import.meta.url))
const sraidDir = join(here, 'sraid')

// ── Canonicalize + OID vectors ──────────────────────────────────────────────

const inputs: Array<{ name: string; input: unknown }> = [
  { name: 'empty object',                     input: {} },
  { name: 'flat object out-of-order keys',    input: { b: 1, a: 'hi' } },
  { name: 'nested object',                    input: { outer: { inner: [1, 2, 3] } } },
  { name: 'array of objects',                 input: [{ x: 1 }, { x: 2 }] },
  { name: 'integer',                          input: 42 },
  // NOTE: no float here. ADR_019 (number rule) forbids non-integer numbers, so
  // `canonicalize(3.14)` / `oidOf(3.14)` now THROW. The former "fractional
  // double" happy-path vector was moved to canonicalize-reject.json (a float is
  // expected-REJECT, not expected-canonical). Keeping it here would crash this
  // generator and re-emit an ADR_019-violating golden vector.
  { name: 'string with embedded quote',       input: 'has "quote" inside' },
  { name: 'string with unicode snowman',      input: 'snowman ☃' },
  { name: 'mixed types',                      input: { s: 'x', n: 1, b: true, nu: null, a: [1, 2] } },
]

const canonicalizeVectors = inputs.map(v => ({
  name:                v.name,
  kind:                'canonicalize',
  input:               v.input,
  expected_canonical:  canonicalize(v.input),
}))

const oidVectors = inputs.map(v => ({
  name:           v.name,
  kind:           'oid',
  input:          v.input,
  expected_oid:   oidOf(v.input),
}))

writeFileSync(
  join(sraidDir, 'canonicalize.json'),
  JSON.stringify(canonicalizeVectors, null, 2) + '\n',
)
// OID determinism vector: oidOf called twice on the same input must yield the same OID.
const oidDeterminismInput = { tenant_id: 'oid-det-tenant', n: 7, nested: { a: [1, 2, 3] } }
const oidDeterminismVector = {
  name:           'oid determinism: same input twice yields identical oid',
  kind:           'oid_determinism',
  input:          oidDeterminismInput,
  expected_oid_1: oidOf(oidDeterminismInput),
  expected_oid_2: oidOf(oidDeterminismInput),
}

writeFileSync(
  join(sraidDir, 'oid.json'),
  JSON.stringify([...oidVectors, oidDeterminismVector], null, 2) + '\n',
)

// ── Signature vectors ───────────────────────────────────────────────────────

const ed_priv = ed25519.utils.randomPrivateKey()
const ed_pub  = ed25519.getPublicKey(ed_priv)
const ml      = ml_dsa65.keygen(randomBytes(32))

const payload = 'conformance-vector-payload'
const payloadBytes = new TextEncoder().encode(payload)
const ed_sig = ed25519.sign(payloadBytes, ed_priv)
const ml_sig = ml_dsa65.sign(payloadBytes, ml.secretKey)

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')

const validVector = {
  name:            'valid signatures verify',
  kind:            'signature',
  canonical:       payload,
  envelope: {
    ed25519:    b64(ed_sig),
    ml_dsa_65:  b64(ml_sig),
    signer_kid: 'conformance-test-2026',
  },
  ed25519_pub_b64: b64(ed_pub),
  ml_dsa_pub_b64:  b64(ml.publicKey),
  expected_valid:  true,
}

// Tampered payload - same envelope, different "canonical"
const tamperedVector = {
  name:            'tampered payload fails',
  kind:            'signature',
  canonical:       payload + ' tampered',
  envelope: {
    ed25519:    b64(ed_sig),
    ml_dsa_65:  b64(ml_sig),
    signer_kid: 'conformance-test-2026',
  },
  ed25519_pub_b64: b64(ed_pub),
  ml_dsa_pub_b64:  b64(ml.publicKey),
  expected_valid:  false,
}

// Wrong ed25519 pub
const ed_priv_other = ed25519.utils.randomPrivateKey()
const wrongKeyVector = {
  name:            'wrong ed25519 pub fails',
  kind:            'signature',
  canonical:       payload,
  envelope: {
    ed25519:    b64(ed_sig),
    ml_dsa_65:  b64(ml_sig),
    signer_kid: 'conformance-test-2026',
  },
  ed25519_pub_b64: b64(ed25519.getPublicKey(ed_priv_other)),
  ml_dsa_pub_b64:  b64(ml.publicKey),
  expected_valid:  false,
}

// Tampered ed25519 signature byte
const tampered_ed = Uint8Array.from(ed_sig)
tampered_ed[0] = (tampered_ed[0] ?? 0) ^ 0xff
const tamperedSigVector = {
  name:            'tampered ed25519 sig fails',
  kind:            'signature',
  canonical:       payload,
  envelope: {
    ed25519:    b64(tampered_ed),
    ml_dsa_65:  b64(ml_sig),
    signer_kid: 'conformance-test-2026',
  },
  ed25519_pub_b64: b64(ed_pub),
  ml_dsa_pub_b64:  b64(ml.publicKey),
  expected_valid:  false,
}

// ML-DSA-65-only tamper vector: isolates the PQ leg by keeping the ed25519 signature
// valid over the same payload but corrupting only the ml_dsa_65 bytes. Proves the
// hybrid verifier actually engages the ML-DSA-65 verify path rather than short-circuiting
// on the ed25519 leg alone.
const ed_priv_ml    = ed25519.utils.randomPrivateKey()
const ed_pub_ml     = ed25519.getPublicKey(ed_priv_ml)
const ml_for_tamper = ml_dsa65.keygen(randomBytes(32))

const mlPayload      = 'ml-dsa-only-conformance-vector-payload'
const mlPayloadBytes = new TextEncoder().encode(mlPayload)
const ed_sig_ml      = ed25519.sign(mlPayloadBytes, ed_priv_ml)
const ml_sig_good    = ml_dsa65.sign(mlPayloadBytes, ml_for_tamper.secretKey)
const ml_sig_tampered = Uint8Array.from(ml_sig_good)
ml_sig_tampered[0] = (ml_sig_tampered[0] ?? 0) ^ 0xff

const mlDsaOnlyTamperedVector = {
  name:            'ml-dsa-65 only: tampered payload fails pq leg',
  kind:            'signature',
  canonical:       mlPayload,
  envelope: {
    ed25519:    b64(ed_sig_ml),
    ml_dsa_65:  b64(ml_sig_tampered),
    signer_kid: 'conformance-test-mldsa-2026',
  },
  ed25519_pub_b64: b64(ed_pub_ml),
  ml_dsa_pub_b64:  b64(ml_for_tamper.publicKey),
  expected_valid:  false,
}

writeFileSync(
  join(sraidDir, 'signatures.json'),
  JSON.stringify(
    [validVector, tamperedVector, wrongKeyVector, tamperedSigVector, mlDsaOnlyTamperedVector],
    null, 2,
  ) + '\n',
)

// ── L2 DSSE attestation vectors ─────────────────────────────────────────────
//
// These exercise verifyAttestation end-to-end. The signatures are computed
// over PAE(payloadType, payload), so the payload TYPE is bound into the
// signed bytes. The decisive vector is "cross-type confusion": signatures
// minted for payloadType A are presented under payloadType B with identical
// payload bytes, and MUST fail (the legacy bare-bytes scheme would have
// accepted them). This is the T11 fix (SRAID F7 / Adversary A4).

const attEdPriv = ed25519.utils.randomPrivateKey()
const attEdPub  = ed25519.getPublicKey(attEdPriv)
const attMl     = ml_dsa65.keygen(randomBytes(32))

const attPayloadType = 'application/vnd.synoi.sraid+json'
const attPayload     = canonicalize({ tenant_id: 't-home', action: 'open_door', risk: 'B' })

function sigsOverPae(pt: string, pl: string): Array<{ alg: string; sig: string; keyid: string }> {
  const msg = pae(pt, pl)
  return [
    { alg: 'ed25519',   keyid: 'att-2026', sig: b64(ed25519.sign(msg, attEdPriv)) },
    { alg: 'ml-dsa-65', keyid: 'att-2026', sig: b64(ml_dsa65.sign(msg, attMl.secretKey)) },
  ]
}

const attEdPubB64 = b64(attEdPub)
const attMlPubB64 = b64(attMl.publicKey)

// Signatures legitimately minted for payloadType A.
const sigsForTypeA = sigsOverPae(attPayloadType, attPayload)

const attestationVectors = [
  {
    name: 'dsse: valid hybrid attestation verifies',
    kind: 'attestation',
    envelope: { payloadType: attPayloadType, payload: attPayload, signatures: sigsForTypeA },
    ed25519_pub_b64: attEdPubB64,
    ml_dsa_pub_b64:  attMlPubB64,
    expected_valid:  true,
  },
  {
    name: 'dsse: cross-type confusion blocked (PAE binds payloadType)',
    kind: 'attestation',
    // Same payload + same sigs, but a DIFFERENT payloadType. PAE binding
    // makes the sigs invalid here. The legacy scheme would have accepted it.
    envelope: { payloadType: 'application/vnd.in-toto+json', payload: attPayload, signatures: sigsForTypeA },
    ed25519_pub_b64: attEdPubB64,
    ml_dsa_pub_b64:  attMlPubB64,
    expected_valid:  false,
  },
  {
    name: 'dsse: expectedPayloadType pin mismatch fails',
    kind: 'attestation',
    envelope: { payloadType: 'application/vnd.in-toto+json', payload: attPayload, signatures: sigsForTypeA },
    expected_payload_type: attPayloadType,
    ed25519_pub_b64: attEdPubB64,
    ml_dsa_pub_b64:  attMlPubB64,
    expected_valid:  false,
  },
  {
    name: 'dsse: missing ml-dsa-65 fails (hybrid AND policy)',
    kind: 'attestation',
    envelope: { payloadType: attPayloadType, payload: attPayload, signatures: [sigsForTypeA[0]] },
    ed25519_pub_b64: attEdPubB64,
    ml_dsa_pub_b64:  attMlPubB64,
    expected_valid:  false,
  },
  {
    name: 'dsse: tampered payload fails both signatures',
    kind: 'attestation',
    envelope: {
      payloadType: attPayloadType,
      payload: canonicalize({ tenant_id: 't-home', action: 'open_door', risk: 'C' }),
      signatures: sigsForTypeA,
    },
    ed25519_pub_b64: attEdPubB64,
    ml_dsa_pub_b64:  attMlPubB64,
    expected_valid:  false,
  },
]

writeFileSync(
  join(sraidDir, 'attestation.json'),
  JSON.stringify(attestationVectors, null, 2) + '\n',
)

// ── L4 authority vectors ──────────────────────────────────────────────────────
//
// These exercise the verifyAuthority verifier end-to-end: a real signed
// grant CDRO, an object referencing it, and the four locally-checkable
// outcomes (authorized / uncovered action / wrong signing key / tampered
// grant body under a fixed OID reference). Revocation + existence are
// resolver-dependent and intentionally NOT covered by a vector - the
// resolver is undeployed (CLAIMS_DISCIPLINE: no vector, no claim).

const grantEdPriv = ed25519.utils.randomPrivateKey()
const grantEdPub = ed25519.getPublicKey(grantEdPriv)
const grantMl = ml_dsa65.keygen(randomBytes(32))

function buildSignedGrant(body: unknown): {
  oid: string; type: string; sraid_version: '2.0'; tenant_id: string
  created_at_ms: number; created_by: string; body: unknown
  signature: { ed25519: string; ml_dsa_65: string; signer_kid: string }
} {
  const core = {
    type: 'gap:capability_grant',
    sraid_version: '2.0' as const,
    tenant_id: 'acme-prod',
    created_at_ms: 1716840000000,
    created_by: 'sha256:' + 'f'.repeat(64),
    body,
  }
  const oid = cdroOid(core)
  const msg = new TextEncoder().encode(canonicalize(core))
  return {
    ...core,
    oid,
    signature: {
      ed25519: b64(ed25519.sign(msg, grantEdPriv)),
      ml_dsa_65: b64(ml_dsa65.sign(msg, grantMl.secretKey)),
      signer_kid: 'conformance-grantor-2026',
    },
  }
}

const authGrant = buildSignedGrant({
  capability_scopes: [{ capability: 'email.*' }],
  expires_at_ms: 1816840000000,
})

const authObject = {
  oid: 'sha256:' + '1'.repeat(64),
  type: 'althing:decision_receipt',
  sraid_version: '2.0',
  tenant_id: 'acme-prod',
  created_at_ms: 1716840001000,
  created_by: 'sha256:' + '2'.repeat(64),
  body: { action: 'delete thread 8821' },
  authority: {
    grant_oid: authGrant.oid,
    decision: 'allow',
    intent_oid: 'sha256:' + '3'.repeat(64),
  },
}

const grantEdPubB64 = b64(grantEdPub)
const grantMlPubB64 = b64(grantMl.publicKey)
const wrongEdPubB64 = b64(ed25519.getPublicKey(ed25519.utils.randomPrivateKey()))

const authorityVectors = [
  {
    name: 'authorized: signed grant covers action',
    kind: 'authority',
    object: authObject,
    action: 'email.bulk_delete',
    grant: authGrant,
    grant_ed25519_pub_b64: grantEdPubB64,
    grant_ml_dsa_pub_b64: grantMlPubB64,
    expected_authorized: true,
  },
  {
    name: 'unauthorized: grant scope does not cover action',
    kind: 'authority',
    object: authObject,
    action: 'fs.delete_all',
    grant: authGrant,
    grant_ed25519_pub_b64: grantEdPubB64,
    grant_ml_dsa_pub_b64: grantMlPubB64,
    expected_authorized: false,
  },
  {
    name: 'unauthorized: wrong grant signing key',
    kind: 'authority',
    object: authObject,
    action: 'email.bulk_delete',
    grant: authGrant,
    grant_ed25519_pub_b64: wrongEdPubB64,
    grant_ml_dsa_pub_b64: grantMlPubB64,
    expected_authorized: false,
  },
  {
    name: 'unauthorized: tampered grant body under fixed OID reference',
    kind: 'authority',
    object: authObject,
    action: 'email.bulk_delete',
    grant: { ...authGrant, body: { capability_scopes: [{ capability: '*' }], expires_at_ms: 1816840000000 } },
    grant_ed25519_pub_b64: grantEdPubB64,
    grant_ml_dsa_pub_b64: grantMlPubB64,
    expected_authorized: false,
  },
  {
    name: 'unauthorized: structure-only, no grant supplied',
    kind: 'authority',
    object: authObject,
    action: 'email.bulk_delete',
    expected_authorized: false,
  },
]

writeFileSync(
  join(sraidDir, 'authority.json'),
  JSON.stringify(authorityVectors, null, 2) + '\n',
)

// ── CDRO round-trip vectors ─────────────────────────────────────────────────
//
// Exercise cdroContentCore + cdroOid end-to-end: content-core must be deterministic,
// and cdroOid(cdro) must equal oidOf(cdroContentCore(cdro)) - these are the same
// object computed two ways. Uses current 'gap:decision_receipt' type naming
// (ADR_020 M6 unification; the retired 'althing:' and 'synoi:' prefixes predate
// this ADR and must not appear in newly authored vectors).

const roundtripCdro = {
  type:          'gap:decision_receipt',
  sraid_version: '2.0' as const,
  tenant_id:     'round-trip-tenant',
  created_at_ms: 1716840000000,
  created_by:    'sha256:' + 'a'.repeat(64),
  body: {
    action: 'open_door',
    risk:   'A',
  },
}

const roundtripCore1 = canonicalize(cdroContentCore(roundtripCdro))
const roundtripCore2 = canonicalize(cdroContentCore(roundtripCdro))
const roundtripOid    = cdroOid(roundtripCdro)
const roundtripCoreOid = oidOf(cdroContentCore(roundtripCdro))

const cdroRoundtripVectors = [
  {
    name:                     'cdro content-core is deterministic',
    kind:                     'cdro_roundtrip',
    cdro:                     roundtripCdro,
    expected_content_core_1:  roundtripCore1,
    expected_content_core_2:  roundtripCore2,
    expected_deterministic:   true,
    note: 'canonicalize(cdroContentCore(cdro)) called twice on same input must return byte-identical string',
  },
  {
    name:              'cdro oid matches oidOf(cdroContentCore(cdro))',
    kind:              'cdro_roundtrip',
    cdro:              roundtripCdro,
    expected_oid:      roundtripOid,
    expected_core_oid: roundtripCoreOid,
    note: 'cdroOid must equal oidOf(cdroContentCore(cdro)) - these are the same object',
  },
]

writeFileSync(
  join(sraidDir, 'cdro-roundtrip.json'),
  JSON.stringify(cdroRoundtripVectors, null, 2) + '\n',
)

// ── K2 Delegation chain vectors ─────────────────────────────────────────────
//
// Build a real 3-link chain: root -> intermediate -> leaf, each signed with
// its own hybrid keypair. Every CDRO carries a DSSE `attestation` (not the
// legacy `signature` field) so verifyDelegationChain's GATE 3 passes.
// Recovered from the orphaned origin/line/f13 branch (ADR_020 history
// reconstruction) and regenerated here under current sraid_version /
// gap: naming - see commit message for what changed and why.
//
// MUTATION DISCIPLINE: each negative vector re-derives the mutated link's OID
// and re-signs its DSSE payload so that GATE 1 (OID honesty) and GATE 3
// (signature payload match) do not mask the intended failing gate. For
// root-mismatch only the caller-supplied rootPubkeys is swapped (no re-sign).

const GRANT_PAYLOAD_TYPE = 'application/vnd.synoi.sraid+json'
const ROOT_OID_  = 'sha256:' + 'aa'.repeat(32)
const INT_OID_   = 'sha256:' + 'bb'.repeat(32)
const LEAF_OID_  = 'sha256:' + 'cc'.repeat(32)
const CHAIN_NOW_MS = 2_000_000_000_000
const CHAIN_T_MS   = CHAIN_NOW_MS + 30 * 24 * 3600 * 1000

function mintKp(): { priv: Uint8Array; pub: Uint8Array; mlPriv: Uint8Array; mlPub: Uint8Array } {
  const priv  = ed25519.utils.randomPrivateKey()
  const pub   = ed25519.getPublicKey(priv)
  const ml    = ml_dsa65.keygen(randomBytes(32))
  return { priv, pub, mlPriv: ml.secretKey, mlPub: ml.publicKey }
}

function buildChainGrant(
  content: Record<string, unknown>,
  signerPriv: Uint8Array,
  signerMlPriv: Uint8Array,
  keyid: string,
): Record<string, unknown> {
  const oid = cdroOid(content)
  const payload = canonicalize(cdroContentCore({ oid, ...content }))
  const msg = pae(GRANT_PAYLOAD_TYPE, payload)
  const attestation = {
    payloadType: GRANT_PAYLOAD_TYPE,
    payload,
    signatures: [
      { alg: 'ed25519',   keyid, sig: b64(ed25519.sign(msg, signerPriv)) },
      { alg: 'ml-dsa-65', keyid, sig: b64(ml_dsa65.sign(msg, signerMlPriv)) },
    ],
  }
  return { oid, ...content, attestation }
}

const rootKp = mintKp()
const intKp  = mintKp()
const leafKp = mintKp()

const rootContent: Record<string, unknown> = {
  type: 'gap:capability_grant',
  sraid_version: '2.0',
  tenant_id: 'conformance',
  created_at_ms: CHAIN_NOW_MS,
  created_by: ROOT_OID_,
  body: {
    grantee:           { actor_oid: INT_OID_ },
    capability_scopes: [{ capability: 'email.*' }],
    expires_at_ms:     CHAIN_T_MS,
  },
}
const rootGrant = buildChainGrant(rootContent, rootKp.priv, rootKp.mlPriv, 'root-2026')

// intermediate.body.granted_by = root.body.grantee.actor_oid = INT_OID_
const intContent: Record<string, unknown> = {
  type: 'gap:capability_grant',
  sraid_version: '2.0',
  tenant_id: 'conformance',
  created_at_ms: CHAIN_NOW_MS,
  created_by: INT_OID_,
  body: {
    granted_by:        INT_OID_,
    grantee:           { actor_oid: LEAF_OID_ },
    capability_scopes: [{ capability: 'email.send.*' }],
    expires_at_ms:     CHAIN_T_MS - 1000,
  },
}
const intGrant = buildChainGrant(intContent, intKp.priv, intKp.mlPriv, 'int-2026')

// leaf.body.granted_by = int.body.grantee.actor_oid = LEAF_OID_
const leafBase: Record<string, unknown> = {
  type: 'gap:capability_grant',
  sraid_version: '2.0',
  tenant_id: 'conformance',
  created_at_ms: CHAIN_NOW_MS,
  created_by: LEAF_OID_,
  body: {
    granted_by:        LEAF_OID_,
    grantee:           { actor_oid: 'sha256:' + 'dd'.repeat(32) },
    capability_scopes: [{ capability: 'email.send.bulk' }],
    expires_at_ms:     CHAIN_T_MS - 2000,
  },
}
const leafGrant = buildChainGrant(leafBase, leafKp.priv, leafKp.mlPriv, 'leaf-2026')

function remintLeaf(bodyOverride: Record<string, unknown>): Record<string, unknown> {
  const content: Record<string, unknown> = {
    ...leafBase,
    body: { ...(leafBase.body as Record<string, unknown>), ...bodyOverride },
  }
  return buildChainGrant(content, leafKp.priv, leafKp.mlPriv, 'leaf-2026')
}

const leafWidened      = remintLeaf({ capability_scopes: [{ capability: 'email.*' }] })
const leafExpiredChild = remintLeaf({ expires_at_ms: CHAIN_T_MS + 1000 })
const leafBrokenLink   = remintLeaf({ granted_by: 'sha256:' + '00'.repeat(32) })
const leafEmptyScope   = remintLeaf({ capability_scopes: [] })

const chainBaseLinks = [
  { ed25519_b64: b64(leafKp.pub), ml_dsa_b64: b64(leafKp.mlPub) },
  { ed25519_b64: b64(intKp.pub),  ml_dsa_b64: b64(intKp.mlPub)  },
  { ed25519_b64: b64(rootKp.pub), ml_dsa_b64: b64(rootKp.mlPub) },
]
const chainRootPubs = { ed25519_b64: b64(rootKp.pub), ml_dsa_b64: b64(rootKp.mlPub) }

const rogueKp = mintKp()

const chainVectors = [
  {
    name: 'chain: valid 3-link delegation authorizes',
    kind: 'chain',
    leaf: leafGrant, ancestors: [intGrant, rootGrant],
    link_pubkeys_b64: chainBaseLinks, root_pubkeys_b64: chainRootPubs,
    expected_authorized: true,
  },
  {
    name: 'chain: attenuation-widening child broadens parent scope (FAIL)',
    kind: 'chain',
    leaf: leafWidened, ancestors: [intGrant, rootGrant],
    link_pubkeys_b64: chainBaseLinks, root_pubkeys_b64: chainRootPubs,
    expected_authorized: false,
    expected_reason: 'widens parent (not attenuated)',
  },
  {
    name: 'chain: expired child outlives parent expiry (FAIL)',
    kind: 'chain',
    leaf: leafExpiredChild, ancestors: [intGrant, rootGrant],
    link_pubkeys_b64: chainBaseLinks, root_pubkeys_b64: chainRootPubs,
    expected_authorized: false,
    expected_reason: 'is later than parent',
  },
  {
    name: 'chain: broken linkage child granted_by != parent grantee (FAIL)',
    kind: 'chain',
    leaf: leafBrokenLink, ancestors: [intGrant, rootGrant],
    link_pubkeys_b64: chainBaseLinks, root_pubkeys_b64: chainRootPubs,
    expected_authorized: false,
    expected_reason: 'does not equal parent.grantee.actor_oid (broken signer link)',
  },
  {
    name: 'chain: root-mismatch terminal key != rootPubkeys (FAIL)',
    kind: 'chain',
    leaf: leafGrant, ancestors: [intGrant, rootGrant],
    link_pubkeys_b64: chainBaseLinks,
    root_pubkeys_b64: { ed25519_b64: b64(rogueKp.pub), ml_dsa_b64: b64(rogueKp.mlPub) },
    expected_authorized: false,
    expected_reason: 'does not equal rootPubkeys (forged/unknown root)',
  },
  {
    name: 'chain: empty leaf scope grants nothing (FAIL)',
    kind: 'chain',
    leaf: leafEmptyScope, ancestors: [intGrant, rootGrant],
    link_pubkeys_b64: chainBaseLinks, root_pubkeys_b64: chainRootPubs,
    expected_authorized: false,
    expected_reason: 'has no capability scopes (rejected)',
  },
  {
    name: 'chain: action not covered by leaf (FAIL)',
    kind: 'chain',
    leaf: leafGrant, ancestors: [intGrant, rootGrant],
    link_pubkeys_b64: chainBaseLinks, root_pubkeys_b64: chainRootPubs,
    action: 'fs.delete_all',
    expected_authorized: false,
    expected_reason: 'not covered by leaf grant',
  },
]

writeFileSync(
  join(sraidDir, 'delegation-chain.json'),
  JSON.stringify(chainVectors, null, 2) + '\n',
)

process.stdout.write(`Wrote SRAID vectors:\n`)
process.stdout.write(`  canonicalize.json      ${canonicalizeVectors.length} vectors\n`)
process.stdout.write(`  oid.json               ${oidVectors.length + 1} vectors (incl. 1 oid_determinism)\n`)
process.stdout.write(`  signatures.json        5 vectors (legacy bare-bytes envelope, incl. ml-dsa-only tamper)\n`)
process.stdout.write(`  attestation.json       ${attestationVectors.length} vectors (DSSE/PAE)\n`)
process.stdout.write(`  authority.json         ${authorityVectors.length} vectors\n`)
process.stdout.write(`  cdro-roundtrip.json    ${cdroRoundtripVectors.length} vectors\n`)
process.stdout.write(`  delegation-chain.json  ${chainVectors.length} vectors (K2, recovered from origin/line/f13)\n`)
process.stdout.write(`  lineage.json           (hand-maintained, no keys needed, not generated here)\n`)
process.stdout.write(`  sensitivity.json       (hand-maintained, no keys needed, not generated here)\n`)
