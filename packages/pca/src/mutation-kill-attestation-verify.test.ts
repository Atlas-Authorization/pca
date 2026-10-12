/**
 * Mutation-kill tests for attestation.ts (part 2): verifyAttestation (every refusal reason and time boundary), the
 * createAttestationVerifier hook, the multi-root verifier, evidence digest and anchoring.
 */
import { describe, expect, it } from 'vitest';
import {
  anchorAttestationEvidence,
  ATTEST_ANCHOR_DOMAIN,
  attestationBindingB64u,
  attestationEvidenceDigest,
  createAttestationVerifier,
  createDevAttestor,
  createMultiRootVerifier,
  MAX_ATTESTATION_AGE_MS,
  verifyAttestation,
  type AttestationDocument,
  type ExpectedAttestationBinding,
  type HardwareAttestationResult,
  type HardwareAttestationVerifier,
  type MeasuredIdentity,
} from './attestation';
import { enforced } from './attestation.test-util';
import type { AgentBinding } from './envelope';
import { mintGrant } from './envelope';
import { b64u, canonicalBytes, hashCanonical, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import { TransparencyLedger, verifyTreeHead } from './ledger';
import { DEFAULT_RISK_POLICY } from './risk';

const T = 5_000_000;
const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
const HOLDER = 'holder-key';
const GREF = 'grant-ref-1';
const att = generateKeyPair();
const ATT_PUB = encodeKey(att.publicKey);
const EXPECTED: ExpectedAttestationBinding = { holderPub: HOLDER, grantRef: GREF, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 };
const BOUND = attestationBindingB64u(EXPECTED);

const principal = generateKeyPair();
const grantWith = (binding: AgentBinding = {}) =>
  mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: HOLDER,
    goal: 'g',
    envelope: { predicates: [{ verb: 'read', resource: '*' }], caveats: [], agent_binding: binding, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;

const mkCtx = (over: Record<string, unknown> = {}, binding: AgentBinding = {}) =>
  ({ pcactn: { grant_ref: GREF, attestation: { epoch: 1, quote_digest: NONCE }, cap_chain: [{ holder: HOLDER }], ...over }, grant: grantWith(binding) }) as never;

/** A software document signed by `att` with full control of every field. */
const body = (o: Record<string, unknown> = {}) => ({
  model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 1000,
  attestor: ATT_PUB, mode: 'software', binding: BOUND, ...o,
});
const signDoc = (b: Record<string, unknown>): AttestationDocument => {
  const m = canonicalBytes(b);
  const p = utf8('atlas-pca/attest/v1\0');
  const msg = new Uint8Array(p.length + m.length);
  msg.set(p);
  msg.set(m, p.length);
  return { ...b, sig: b64u(sign(att.secretKey, msg)) } as never;
};
const doc = (o: Record<string, unknown> = {}) => signDoc(Object.fromEntries(Object.entries(body(o)).filter(([, v]) => v !== undefined)));

const run = (over: { document?: unknown; ctx?: unknown; expected?: unknown; nowMs?: number; keys?: string[]; hw?: HardwareAttestationVerifier; maxNonceAgeMs?: number; clockSkewMs?: number } = {}) =>
  verifyAttestation({
    document: ('document' in over ? over.document : doc()) as never,
    ctx: ('ctx' in over ? over.ctx : mkCtx()) as never,
    expected: ('expected' in over ? over.expected : EXPECTED) as never,
    nowMs: over.nowMs ?? T,
    trustedAttestorKeys: over.keys ?? [ATT_PUB],
    ...(over.hw ? { hardwareVerifier: over.hw } : {}),
    ...(over.maxNonceAgeMs !== undefined ? { maxNonceAgeMs: over.maxNonceAgeMs } : {}),
    ...(over.clockSkewMs !== undefined ? { clockSkewMs: over.clockSkewMs } : {}),
  });
const reason = async (over: Parameters<typeof run>[0]) => {
  const v = await run(over);
  expect(v.ok).toBe(false);
  expect(v.bound).toBe(false);
  return v.reason;
};

const MEASURED: MeasuredIdentity = { model_id: 'hm', weights_digest: 'hw', runtime_measurement: 'hr', operator: 'ho' };
const hwOk = (over: Partial<HardwareAttestationResult> = {}): HardwareAttestationVerifier => ({ verify: async () => ({ ok: true, bound: true, measured: MEASURED, ...over }) });

describe('verifyAttestation: software documents', () => {
  it('a bound, fresh document verifies and yields exactly the signed identity', async () => {
    const v = await run();
    expect(v).toEqual({ ok: true, present: true, bound: true, identity: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o' } });
    expect(Object.keys(v.identity!)).toEqual(['model_id', 'weights_digest', 'runtime_measurement', 'operator']);
  });
  it('prompt / tool digests are carried only when the signed document has them as strings', async () => {
    const v = await run({ document: doc({ system_prompt_digest: 'sp', tool_manifest_digest: 'tm' }) });
    expect(v.identity).toEqual({ model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', system_prompt_digest: 'sp', tool_manifest_digest: 'tm' });
    const only = await run({ document: doc({ system_prompt_digest: 'sp' }) });
    expect(Object.keys(only.identity!)).toContain('system_prompt_digest');
    expect(Object.keys(only.identity!)).not.toContain('tool_manifest_digest');
    const numeric = await run({ document: doc({ system_prompt_digest: 5, tool_manifest_digest: 6 }) });
    expect(Object.keys(numeric.identity!)).not.toContain('system_prompt_digest');
    expect(Object.keys(numeric.identity!)).not.toContain('tool_manifest_digest');
  });
  it('no document: present is false, and non-object documents do not count as present', async () => {
    for (const d of [undefined, null, 5, 'x', false]) {
      expect(await run({ document: d })).toEqual({ ok: false, present: false, bound: false, reason: 'no attestation document for this action' });
    }
    const v = await run({ document: {} });
    expect(v.present).toBe(true);
  });
  it('an unconstructible expected binding is refused with the binding error', async () => {
    expect(await reason({ expected: { ...EXPECTED, holderPub: '' } })).toBe('attestation binding not constructible: binding: holderPub required');
    expect(await reason({ expected: { ...EXPECTED, epoch: -1 } })).toBe('attestation binding not constructible: binding: epoch must be a non-negative safe integer');
  });
  it('the PCActn must commit to the expected grant, epoch and nonce (missing pcactn / attestation is just a mismatch)', async () => {
    expect(await reason({ ctx: mkCtx({ grant_ref: 'other' }) })).toBe('attestation binding: PCActn grant_ref differs from expected grant');
    expect(await reason({ ctx: { grant: grantWith() } })).toBe('attestation binding: PCActn grant_ref differs from expected grant');
    expect(await reason({ ctx: mkCtx({ attestation: { epoch: 2, quote_digest: NONCE } }) })).toBe('attestation binding: PCActn attestation epoch differs from expected epoch');
    expect(await reason({ ctx: mkCtx({ attestation: undefined }) })).toBe('attestation binding: PCActn attestation epoch differs from expected epoch');
    expect(await reason({ ctx: mkCtx({ attestation: { epoch: 1, quote_digest: 'other' } }) })).toBe('attestation nonce does not bind to this PCActn');
    expect(await reason({ ctx: mkCtx({ attestation: { epoch: 1 } }) })).toBe('attestation nonce does not bind to this PCActn');
  });
  it('the document nonce must equal the server-issued nonce', async () => {
    expect(await reason({ document: doc({ nonce: 'other' }) })).toBe('attestation nonce does not match the server-issued nonce');
  });
  it('mode, attestor, alg, signature, binding', async () => {
    expect(await reason({ document: doc({ mode: 'hardware' }) })).toBe('document mode hardware needs a hardwareVerifier');
    expect(await reason({ document: doc({ mode: undefined }) })).toBe('document mode undefined needs a hardwareVerifier');
    expect(await reason({ keys: ['someone-else'] })).toBe('attestor key is not trusted');
    expect(await reason({ document: doc({ attestor: 5 }) })).toBe('attestor key is not trusted');
    expect(await reason({ document: doc({ alg: 'bogus' }) })).toBe('attestation declares an unknown signature alg');
    expect(await reason({ document: { ...doc(), model_id: 'tampered' } })).toBe('attestation signature does not verify');
    expect(await reason({ document: { ...doc(), sig: undefined } })).toBe('attestation signature does not verify');
    expect(await reason({ document: { ...doc(), sig: 5 } })).toBe('attestation signature does not verify');
    expect(await reason({ document: doc({ binding: undefined }) })).toBe('attestation is not bound (binding absent)');
    expect(await reason({ document: doc({ binding: '' }) })).toBe('attestation is not bound (binding absent)');
    expect(await reason({ document: doc({ binding: 5 }) })).toBe('attestation is not bound (binding absent)');
    expect(await reason({ document: doc({ binding: attestationBindingB64u({ ...EXPECTED, epoch: 9 }) }) })).toBe('attestation binding mismatch (holder/grant/epoch/nonce)');
  });
  it('the validity window must be well formed: both ends finite numbers and expires >= issued', async () => {
    const MAL = 'malformed attestation validity window';
    expect(await reason({ document: doc({ issued_at: '5' }) })).toBe(MAL);
    expect(await reason({ document: doc({ expires_at: '9' }) })).toBe(MAL);
    expect(await reason({ document: doc({ issued_at: '5', expires_at: '9' }) })).toBe(MAL);
    expect(await reason({ document: doc({ issued_at: T, expires_at: T - 1 }) })).toBe(MAL);
    expect((await run({ document: doc({ issued_at: T, expires_at: T }) })).ok).toBe(true); // a zero-length window is still well formed
  });
  it('not-yet-valid and expired boundaries honour the clock skew in the right direction', async () => {
    expect((await run({ document: doc({ issued_at: T }) })).ok).toBe(true);
    expect(await reason({ document: doc({ issued_at: T + 1 }) })).toBe('attestation not yet valid');
    expect((await run({ document: doc({ issued_at: T + 10 }), clockSkewMs: 10 })).ok).toBe(true);
    expect(await reason({ document: doc({ issued_at: T + 11 }), clockSkewMs: 10 })).toBe('attestation not yet valid');
    expect((await run({ document: doc({ expires_at: T }) })).ok).toBe(true);
    expect(await reason({ document: doc({ expires_at: T - 1 }) })).toBe('attestation expired');
    expect((await run({ document: doc({ expires_at: T - 10 }), clockSkewMs: 10 })).ok).toBe(true);
    expect(await reason({ document: doc({ expires_at: T - 11 }), clockSkewMs: 10 })).toBe('attestation expired');
  });
  it('the server nonce age is checked when nonceIssuedAt is supplied, with skew and an explicit / clamped maximum', async () => {
    const at = (issued: unknown, o: Parameters<typeof run>[0] = {}) => run({ expected: { ...EXPECTED, nonceIssuedAt: issued }, ...o });
    expect((await at(T)).ok).toBe(true);
    expect((await at(T - MAX_ATTESTATION_AGE_MS)).ok).toBe(true);
    expect((await at(T - MAX_ATTESTATION_AGE_MS - 1)).reason).toBe('attestation nonce expired (stale quote)');
    expect((await at(T + 1)).reason).toBe('nonce issued in the future');
    // skew widens both sides by exactly `skew`
    expect((await at(T + 10, { clockSkewMs: 10 })).ok).toBe(true);
    expect((await at(T + 11, { clockSkewMs: 10 })).reason).toBe('nonce issued in the future');
    expect((await at(T - MAX_ATTESTATION_AGE_MS - 10, { clockSkewMs: 10 })).ok).toBe(true);
    expect((await at(T - MAX_ATTESTATION_AGE_MS - 11, { clockSkewMs: 10 })).reason).toBe('attestation nonce expired (stale quote)');
    // an explicit tighter maximum is honoured; zero / negative / NaN / infinite fall back to the default; a larger one is clamped
    expect((await at(T - 1000, { maxNonceAgeMs: 1000 })).ok).toBe(true);
    expect((await at(T - 1001, { maxNonceAgeMs: 1000 })).reason).toBe('attestation nonce expired (stale quote)');
    for (const m of [0, -5, Number.NaN, Number.POSITIVE_INFINITY]) expect((await at(T - 100_000, { maxNonceAgeMs: m })).ok).toBe(true);
    expect((await at(T - MAX_ATTESTATION_AGE_MS - 1, { maxNonceAgeMs: 10 * MAX_ATTESTATION_AGE_MS })).reason).toBe('attestation nonce expired (stale quote)');
    // a negative / non-finite skew counts as zero
    expect((await at(T, { clockSkewMs: -5 })).ok).toBe(true);
    expect((await at(T + 1, { clockSkewMs: -5 })).reason).toBe('nonce issued in the future');
    expect((await at(T + 1, { clockSkewMs: Number.NaN })).reason).toBe('nonce issued in the future');
    // a non-numeric nonceIssuedAt is ignored by the software path (the signed window governs)
    expect((await at('soon')).ok).toBe(true);
    expect((await at(undefined)).ok).toBe(true);
  });
  it('the agent_binding of the grant is matched against the established identity', async () => {
    expect(await reason({ ctx: mkCtx({}, { operator: 'someone-else' }) })).toBe('operator o is not the bound operator');
    expect((await run({ ctx: mkCtx({}, { operator: 'o', model_allowlist: ['m'] }) })).ok).toBe(true);
  });
  it('an internal error fails closed with its message (or "unknown")', async () => {
    const throwing = { ...EXPECTED, get nonceIssuedAt(): number { throw new Error('clock-broke'); } };
    expect(await reason({ expected: throwing })).toBe('attestation verification error (fail closed): clock-broke');
    const weird = { ...EXPECTED, get nonceIssuedAt(): number { throw 'str'; } };
    expect(await reason({ expected: weird })).toBe('attestation verification error (fail closed): unknown');
  });
});

describe('verifyAttestation: hardware', () => {
  it('require_hardware demands a hardware verifier and a hardware-mode document', async () => {
    const ctx = mkCtx({}, { require_hardware: true });
    expect(await reason({ ctx })).toBe('agent_binding.require_hardware: no hardware verifier is configured (fail closed)');
    expect(await reason({ ctx, hw: hwOk() })).toBe('agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)');
    const hwDoc = doc({ mode: 'hardware' });
    expect((await run({ ctx, hw: hwOk(), document: hwDoc })).ok).toBe(true);
    // not requiring it: a software-mode document under a hardware verifier is allowed to be delegated
    expect((await run({ hw: hwOk() })).ok).toBe(true);
  });
  it('the hardware verifier result is checked: ok, bound, measured; identity is the MEASURED one', async () => {
    expect(await reason({ hw: hwOk({ ok: false }) })).toBe('hardware attestation rejected: invalid');
    expect(await reason({ hw: hwOk({ ok: false, reason: 'bad chain' }) })).toBe('hardware attestation rejected: bad chain');
    expect(await reason({ hw: hwOk({ bound: false }) })).toBe('hardware verifier did not confirm report_data binding');
    expect(await reason({ hw: hwOk({ bound: undefined }) })).toBe('hardware verifier did not confirm report_data binding');
    expect(await reason({ hw: hwOk({ measured: undefined }) })).toBe('hardware verifier returned no measured identity');
    const v = await run({ hw: hwOk() });
    expect(v).toEqual({ ok: true, present: true, bound: true, identity: MEASURED });
  });
  it('the hardware verifier receives the document, ctx, clock and expected binding', async () => {
    let seen: Record<string, unknown> | undefined;
    const ctx = mkCtx();
    const document = doc();
    await run({ ctx, document, hw: { verify: async (i) => { seen = i as never; return { ok: true, bound: true, measured: MEASURED }; } } });
    expect(seen).toMatchObject({ document, ctx, nowMs: T, expected: EXPECTED });
  });
  it('hardware mode REQUIRES the server nonce issue time and checks its age', async () => {
    const hw = hwOk();
    expect(await reason({ hw, expected: { ...EXPECTED, nonceIssuedAt: undefined } })).toBe('server nonce issue time unknown (cannot establish freshness)');
    expect(await reason({ hw, expected: { ...EXPECTED, nonceIssuedAt: Number.NaN } })).toBe('server nonce issue time unknown (cannot establish freshness)');
    expect(await reason({ hw, expected: { ...EXPECTED, nonceIssuedAt: Number.POSITIVE_INFINITY } })).toBe('server nonce issue time unknown (cannot establish freshness)');
    expect(await reason({ hw, expected: { ...EXPECTED, nonceIssuedAt: '5' } })).toBe('server nonce issue time unknown (cannot establish freshness)');
    expect(await reason({ hw, expected: { ...EXPECTED, nonceIssuedAt: T + 1 } })).toBe('nonce issued in the future');
    expect(await reason({ hw, expected: { ...EXPECTED, nonceIssuedAt: T - MAX_ATTESTATION_AGE_MS - 1 } })).toBe('attestation nonce expired (stale quote)');
    expect((await run({ hw, expected: { ...EXPECTED, nonceIssuedAt: T - MAX_ATTESTATION_AGE_MS } })).ok).toBe(true);
    expect((await run({ hw, expected: { ...EXPECTED, nonceIssuedAt: T + 10 }, clockSkewMs: 10 })).ok).toBe(true);
    // the document's own dates are irrelevant in hardware mode
    expect((await run({ hw, document: doc({ issued_at: T + 99999, expires_at: 1 }) })).ok).toBe(true);
  });
  it('a hardware verifier that throws fails closed with its message', async () => {
    expect(await reason({ hw: { verify: async () => { throw new Error('hsm-down'); } } })).toBe('attestation verification error (fail closed): hsm-down');
    expect(await reason({ hw: { verify: async () => { throw 'x'; } } })).toBe('attestation verification error (fail closed): unknown');
  });
});

describe('createAttestationVerifier hook', () => {
  const a = createDevAttestor(att.secretKey);
  const GOOD_NONCE = 'AbCdEfGhIjKlMnOpQrStUv'; // 22 base64url chars, 22 distinct
  const bound = (nonce = GOOD_NONCE) => attestationBindingB64u({ ...EXPECTED, nonce });
  const mkDoc = (nonce = GOOD_NONCE, o: Record<string, unknown> = {}): AttestationDocument =>
    a.attest({ model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', nonce, issued_at: T - 1000, expires_at: T + 1000, holder_pub: HOLDER, grant_ref: GREF, epoch: 1, ...o });
  const ctxN = (nonce = GOOD_NONCE) => mkCtx({ attestation: { epoch: 1, quote_digest: nonce } });
  const base = (extra: object = {}, nonce = GOOD_NONCE) => ({
    trustedAttestorKeys: [ATT_PUB],
    resolveDocument: () => mkDoc(nonce),
    expectedBinding: () => ({ ...EXPECTED, nonce }),
    now: () => T,
    ...extra,
  });
  it('a success carries no `reason` key', async () => {
    const r = await createAttestationVerifier(base())(ctxN());
    expect(r).toStrictEqual({ enforced: true, ok: true, present: true, bound: true });
    expect(bound()).toBe(mkDoc().binding);
  });
  it('without an expected binding it fails closed, reporting whether a document was present', async () => {
    const msg = 'no server-issued attestation nonce/binding available (fail closed)';
    expect(await createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => mkDoc(), now: () => T })(ctxN())).toStrictEqual({ enforced: true, ok: false, reason: msg, present: true, bound: false });
    expect(await createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], now: () => T })(ctxN())).toStrictEqual({ enforced: true, ok: false, reason: msg, present: false, bound: false });
    expect(await createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => mkDoc(), expectedBinding: () => undefined, now: () => T })(ctxN())).toMatchObject({ ok: false, reason: msg });
  });
  it('a low-entropy server nonce is refused (present reflects the document) unless the insecure opt-out is set', async () => {
    const weak = 'weak-nonce-1234567890a';
    const msg = 'attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)';
    const withDoc = await createAttestationVerifier(base({ expectedBinding: () => ({ ...EXPECTED, nonce: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa' }) }))(ctxN());
    expect(withDoc).toStrictEqual({ enforced: true, ok: false, reason: msg, present: true, bound: false });
    const noDoc = await createAttestationVerifier(base({ resolveDocument: () => undefined, expectedBinding: () => ({ ...EXPECTED, nonce: weak.replace(/./g, 'a') }) }))(ctxN());
    expect(noDoc).toStrictEqual({ enforced: true, ok: false, reason: msg, present: false, bound: false });
    const minBytes = enforced(await createAttestationVerifier(base({ minNonceBytes: 20 }))(ctxN())); // 22 chars => 16 bytes < 20
    expect(minBytes.reason).toBe(msg);
  });
  it('insecure_selfDeclaredNonce derives the expected binding from the PCActn (leaf holder, else the grant holder)', async () => {
    const nonce = 'self-declared';
    const insecure = (ctx: unknown, hd = HOLDER) =>
      createAttestationVerifier({
        trustedAttestorKeys: [ATT_PUB], insecure_selfDeclaredNonce: true, now: () => T,
        resolveDocument: () => a.attest({ model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', nonce, issued_at: T - 1, expires_at: T + 1, holder_pub: hd, grant_ref: GREF, epoch: 1 }),
      })(ctx as never);
    const withLeaf = mkCtx({ attestation: { epoch: 1, quote_digest: nonce }, cap_chain: [{ holder: 'root' }, { holder: 'leaf-key' }] });
    expect(enforced(await insecure(withLeaf, 'leaf-key')).ok).toBe(true);
    expect(enforced(await insecure(withLeaf, HOLDER)).ok).toBe(false);
    const noChain = mkCtx({ attestation: { epoch: 1, quote_digest: nonce }, cap_chain: undefined });
    expect(enforced(await insecure(noChain)).ok).toBe(true); // falls back to the grant holder
    const emptyChain = mkCtx({ attestation: { epoch: 1, quote_digest: nonce }, cap_chain: [] });
    expect(enforced(await insecure(emptyChain)).ok).toBe(true);
    const noHolder = mkCtx({ attestation: { epoch: 1, quote_digest: nonce }, cap_chain: [{}] });
    expect(enforced(await insecure(noHolder)).reason).toBe('attestation binding not constructible: binding: holderPub required');
    // an absent ctx is a clean denial, not an internal error
    expect(await insecure(undefined)).toStrictEqual({ enforced: true, ok: false, reason: 'attestation binding not constructible: binding: holderPub required', present: true, bound: false });
  });
  it('the nonce store consumes the nonce only after a successful verification; a replay is refused', async () => {
    const consumed: string[] = [];
    const store = { consume: (n: string) => { const fresh = !consumed.includes(n); consumed.push(n); return fresh; } };
    const v = createAttestationVerifier(base({ nonceStore: store }));
    expect(enforced(await v(ctxN())).ok).toBe(true);
    expect(await v(ctxN())).toStrictEqual({ enforced: true, ok: false, reason: 'attestation nonce already consumed (replay)', present: true, bound: false });
    const failing = createAttestationVerifier(base({ nonceStore: store, trustedAttestorKeys: ['nobody'] }));
    const before = consumed.length;
    expect(enforced(await failing(ctxN())).ok).toBe(false);
    expect(consumed.length).toBe(before); // a failed verification burns nothing
    // an async store is awaited
    const asyncStore = { consume: async () => false };
    expect(enforced(await createAttestationVerifier(base({ nonceStore: asyncStore }))(ctxN())).reason).toBe('attestation nonce already consumed (replay)');
  });
  it('a throwing resolver / expectedBinding fails closed (present false, bound false)', async () => {
    const r1 = await createAttestationVerifier(base({ resolveDocument: () => { throw new Error('db'); } }))(ctxN());
    expect(r1).toStrictEqual({ enforced: true, ok: false, reason: 'attestation verification error (fail closed): db', present: false, bound: false });
    const r2 = enforced(await createAttestationVerifier(base({ expectedBinding: () => { throw 'x'; } }))(ctxN()));
    expect(r2.reason).toBe('attestation verification error (fail closed): unknown');
    expect(r2.present).toBe(false);
  });
  it('options are forwarded to the verifier: max nonce age, skew, hardware verifier', async () => {
    const stale = base({ maxNonceAgeMs: 500 }); // nonce issued 1000 ms ago
    expect(enforced(await createAttestationVerifier(stale)(ctxN())).reason).toBe('attestation nonce expired (stale quote)');
    const skewed = base({ maxNonceAgeMs: 500, clockSkewMs: 600 });
    expect(enforced(await createAttestationVerifier(skewed)(ctxN())).ok).toBe(true);
    const hw = createAttestationVerifier(base({ hardwareVerifier: hwOk(), trustedAttestorKeys: 5 as never }))(ctxN());
    expect(enforced(await hw).ok).toBe(true);
  });
});

describe('createMultiRootVerifier', () => {
  const input = { document: doc(), ctx: mkCtx(), nowMs: T, expected: EXPECTED };
  const id = (o: Partial<MeasuredIdentity> = {}): MeasuredIdentity => ({ ...MEASURED, ...o });
  const root = (rid: string, res: HardwareAttestationResult | (() => never), extra: object = {}) => ({ id: rid, verifier: { verify: async () => (typeof res === 'function' ? res() : res) } as HardwareAttestationVerifier, ...extra });
  const good = (m: Partial<MeasuredIdentity> = {}, extra: Partial<HardwareAttestationResult> = {}): HardwareAttestationResult => ({ ok: true, bound: true, measured: id(m), ...extra });

  it('construction errors name the problem', () => {
    expect(() => createMultiRootVerifier(undefined as never)).toThrow('createMultiRootVerifier: at least one attestation root is required');
    expect(() => createMultiRootVerifier({ roots: 'x' as never, threshold: 1 })).toThrow('createMultiRootVerifier: at least one attestation root is required');
    expect(() => createMultiRootVerifier({ roots: [], threshold: 1 })).toThrow('createMultiRootVerifier: at least one attestation root is required');
    const r = root('a', good());
    for (const t of [0, -1, 1.5, 2, Number.NaN, '1' as never]) expect(() => createMultiRootVerifier({ roots: [r], threshold: t })).toThrow('createMultiRootVerifier: threshold must be an integer in [1, roots.length]');
    expect(() => createMultiRootVerifier({ roots: [r], threshold: 1 })).not.toThrow();
    for (const bad of [null, { verifier: r.verifier }, { id: 5, verifier: r.verifier }, { id: '', verifier: r.verifier }]) {
      expect(() => createMultiRootVerifier({ roots: [bad as never], threshold: 1 })).toThrow('createMultiRootVerifier: each root needs a non-empty id');
    }
    expect(() => createMultiRootVerifier({ roots: [r, root('a', good())], threshold: 1 })).toThrow("createMultiRootVerifier: duplicate root id 'a'");
  });
  it('a corroborated set merges the identity, and weights_measured is true only if the digest came from a measuring root', async () => {
    const v = createMultiRootVerifier({ roots: [root('a', good({ weights_measured: false })), root('b', good({ weights_measured: true }))], threshold: 2 });
    expect(await v.verify(input as never)).toStrictEqual({ ok: true, bound: true, measured: { model_id: 'hm', weights_digest: 'hw', weights_measured: true, runtime_measurement: 'hr', operator: 'ho' } });
    const none = createMultiRootVerifier({ roots: [root('a', good()), root('b', good())], threshold: 2 });
    expect((await none.verify(input as never)).measured!.weights_measured).toBe(false);
    // a measuring root that vouches for a DIFFERENT digest does not upgrade the chosen one
    const dig = createMultiRootVerifier({ roots: [root('a', good({ weights_digest: 'W1', weights_measured: false })), root('b', good({ weights_digest: '', weights_measured: true }))], threshold: 2 });
    expect((await dig.verify(input as never)).measured!.weights_measured).toBe(false);
    const noWeights = createMultiRootVerifier({ roots: [root('a', good({ weights_digest: '', weights_measured: true }))], threshold: 1 });
    expect((await noWeights.verify(input as never)).measured!.weights_measured).toBe(false);
  });
  it('empty identity fields are taken from whichever root has them; prompt / tool digests appear only when non-empty', async () => {
    const v = createMultiRootVerifier({
      roots: [root('a', good({ operator: '', model_id: 'M' })), root('b', good({ operator: 'OP', model_id: '', system_prompt_digest: 'SP', tool_manifest_digest: 'TM' }))],
      threshold: 2,
    });
    const r = await v.verify(input as never);
    expect(r.measured).toMatchObject({ model_id: 'M', operator: 'OP', system_prompt_digest: 'SP', tool_manifest_digest: 'TM' });
    const plain = await createMultiRootVerifier({ roots: [root('a', good())], threshold: 1 }).verify(input as never);
    expect(Object.keys(plain.measured!)).not.toContain('system_prompt_digest');
    expect(Object.keys(plain.measured!)).not.toContain('tool_manifest_digest');
    const spOnly = await createMultiRootVerifier({ roots: [root('a', good({ system_prompt_digest: 'SP' }))], threshold: 1 }).verify(input as never);
    expect(Object.keys(spOnly.measured!)).toContain('system_prompt_digest');
    expect(Object.keys(spOnly.measured!)).not.toContain('tool_manifest_digest');
    const tmOnly = await createMultiRootVerifier({ roots: [root('a', good({ tool_manifest_digest: 'TM' }))], threshold: 1 }).verify(input as never);
    expect(Object.keys(tmOnly.measured!)).toContain('tool_manifest_digest');
    expect(Object.keys(tmOnly.measured!)).not.toContain('system_prompt_digest');
  });
  it('contradictory roots deny, naming the field and both roots', async () => {
    for (const field of ['model_id', 'weights_digest', 'runtime_measurement', 'operator', 'system_prompt_digest', 'tool_manifest_digest'] as const) {
      const v = createMultiRootVerifier({ roots: [root('a', good({ [field]: 'X' })), root('b', good({ [field]: 'Y' }))], threshold: 2 });
      expect(await v.verify(input as never)).toStrictEqual({ ok: false, reason: `multi-root attestation identity conflict: roots 'a' and 'b' disagree on ${field}` });
    }
    const same = createMultiRootVerifier({ roots: [root('a', good({ operator: 'X' })), root('b', good({ operator: 'X' }))], threshold: 2 });
    expect((await same.verify(input as never)).ok).toBe(true);
  });
  it('a root counts only with ok === true AND bound === true AND a measured identity', async () => {
    const variants: HardwareAttestationResult[] = [
      { ok: false, bound: true, measured: id() },
      { ok: true, bound: false, measured: id() },
      { ok: true, bound: undefined, measured: id() },
      { ok: true, bound: true },
      { ok: 1 as never, bound: true, measured: id() },
      { ok: true, bound: 1 as never, measured: id() },
    ];
    for (const res of variants) {
      const v = createMultiRootVerifier({ roots: [root('a', res)], threshold: 1 });
      expect(await v.verify(input as never)).toStrictEqual({ ok: false, reason: 'multi-root attestation below threshold (0/1 independent roots corroborated)' });
    }
  });
  it('threshold counting and required roots', async () => {
    const bad = { ok: false, reason: 'chain broken' } as HardwareAttestationResult;
    const optional = createMultiRootVerifier({ roots: [root('a', good()), root('b', bad)], threshold: 1 });
    expect((await optional.verify(input as never)).ok).toBe(true);
    const below = createMultiRootVerifier({ roots: [root('a', good()), root('b', bad)], threshold: 2 });
    expect(await below.verify(input as never)).toStrictEqual({ ok: false, reason: 'multi-root attestation below threshold (1/2 independent roots corroborated)' });
    const req = createMultiRootVerifier({ roots: [root('a', good()), root('b', bad, { required: true })], threshold: 1 });
    expect(await req.verify(input as never)).toStrictEqual({ ok: false, reason: "required attestation root 'b' failed: chain broken" });
    const reqNoReason = createMultiRootVerifier({ roots: [root('b', { ok: false } as never, { required: true })], threshold: 1 });
    expect(await reqNoReason.verify(input as never)).toStrictEqual({ ok: false, reason: "required attestation root 'b' failed: invalid" });
    const notStrict = createMultiRootVerifier({ roots: [root('a', good()), root('b', bad, { required: 1 as never })], threshold: 1 });
    expect((await notStrict.verify(input as never)).ok).toBe(true); // only `required: true` makes a root mandatory
  });
  it('a throwing root is a failure of that root (named), not of the verifier', async () => {
    const boom = root('x', () => { throw new Error('kaboom'); }, { required: true });
    expect(await createMultiRootVerifier({ roots: [boom], threshold: 1 }).verify(input as never)).toStrictEqual({ ok: false, reason: "required attestation root 'x' failed: root 'x' threw (fail closed): kaboom" });
    const weird = root('x', () => { throw 'str'; }, { required: true });
    expect((await createMultiRootVerifier({ roots: [weird], threshold: 1 }).verify(input as never)).reason).toBe("required attestation root 'x' failed: root 'x' threw (fail closed): unknown");
    const ok = createMultiRootVerifier({ roots: [root('a', good()), root('x', () => { throw new Error('k'); })], threshold: 1 });
    expect((await ok.verify(input as never)).ok).toBe(true);
  });
  it('host-asserted fields are namespaced by root id and omitted when there are none', async () => {
    const v = createMultiRootVerifier({ roots: [root('a', good({}, { hostAsserted: { host_data: 'h1' } })), root('b', good({}, { hostAsserted: { host_data: 'h2', x: 'y' } })), root('c', good())], threshold: 3 });
    expect((await v.verify(input as never)).hostAsserted).toEqual({ 'a.host_data': 'h1', 'b.host_data': 'h2', 'b.x': 'y' });
    const none = await createMultiRootVerifier({ roots: [root('a', good())], threshold: 1 }).verify(input as never);
    expect(Object.keys(none)).not.toContain('hostAsserted');
    // a failed root's host-asserted fields are not merged in
    const failed = createMultiRootVerifier({ roots: [root('a', good()), root('b', { ok: false, hostAsserted: { z: '1' } } as never)], threshold: 1 });
    expect(Object.keys(await failed.verify(input as never))).not.toContain('hostAsserted');
  });
  it('a verifier returning a hostile object fails closed (null/undefined = a failed root; a throwing getter aborts)', async () => {
    const undef = createMultiRootVerifier({ roots: [{ id: 'a', verifier: { verify: async () => undefined as never } }], threshold: 1 });
    expect((await undef.verify(input as never)).reason).toMatch(/^multi-root attestation below threshold \(0\/1/);
    const getter = createMultiRootVerifier({ roots: [{ id: 'a', verifier: { verify: async () => ({ get ok(): boolean { throw 'str'; } }) as never } }], threshold: 1 });
    expect(await getter.verify(input as never)).toStrictEqual({ ok: false, reason: 'multi-root attestation error (fail closed): unknown' });
    const getter2 = createMultiRootVerifier({ roots: [{ id: 'a', verifier: { verify: async () => ({ get ok(): boolean { throw new Error('bad-getter'); } }) as never } }], threshold: 1 });
    expect((await getter2.verify(input as never)).reason).toBe('multi-root attestation error (fail closed): bad-getter');
  });
});

describe('attestation evidence digest and anchoring', () => {
  const ev = (o: Record<string, unknown> = {}) => ({
    identity: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', ...(o.identity as object) },
    binding: { holderPub: 'h', grantRef: 'g', epoch: 2, nonce: 'n', ...(o.binding as object) },
    verifiedAt: 1234,
    ...Object.fromEntries(Object.entries(o).filter(([k]) => k !== 'identity' && k !== 'binding')),
  }) as never;
  it('the digest is the canonical hash of the named fields', () => {
    expect(attestationEvidenceDigest(ev({ rootIds: ['b', 'a'], suite: 's', identity: { weights_measured: true, system_prompt_digest: 'sp', tool_manifest_digest: 'tm' } }))).toBe(
      hashCanonical({
        domain: ATTEST_ANCHOR_DOMAIN, holder: 'h', grant: 'g', epoch: 2, nonce: 'n', model_id: 'm', weights_digest: 'w', weights_measured: true,
        runtime_measurement: 'r', operator: 'o', system_prompt_digest: 'sp', tool_manifest_digest: 'tm', roots: ['a', 'b'], suite: 's', verified_at: 1234,
      }),
    );
    expect(attestationEvidenceDigest(ev())).toBe(
      hashCanonical({ domain: ATTEST_ANCHOR_DOMAIN, holder: 'h', grant: 'g', epoch: 2, nonce: 'n', model_id: 'm', weights_digest: 'w', weights_measured: false, runtime_measurement: 'r', operator: 'o', system_prompt_digest: '', tool_manifest_digest: '', roots: [], suite: '', verified_at: 1234 }),
    );
  });
  it('every field moves the digest; absent == empty/false; root order is irrelevant', () => {
    const base = attestationEvidenceDigest(ev());
    const variants: Array<Record<string, unknown>> = [
      { binding: { holderPub: 'h2' } }, { binding: { grantRef: 'g2' } }, { binding: { epoch: 3 } }, { binding: { nonce: 'n2' } },
      { identity: { model_id: 'm2' } }, { identity: { weights_digest: 'w2' } }, { identity: { weights_measured: true } }, { identity: { runtime_measurement: 'r2' } },
      { identity: { operator: 'o2' } }, { identity: { system_prompt_digest: 'x' } }, { identity: { tool_manifest_digest: 'x' } }, { rootIds: ['a'] }, { suite: 'x' }, { verifiedAt: 1235 },
    ];
    for (const v of variants) expect(attestationEvidenceDigest(ev(v))).not.toBe(base);
    expect(attestationEvidenceDigest(ev({ identity: { weights_measured: false, system_prompt_digest: undefined } }))).toBe(base);
    expect(attestationEvidenceDigest(ev({ rootIds: [] }))).toBe(base);
    expect(attestationEvidenceDigest(ev({ rootIds: ['a', 'b'] }))).toBe(attestationEvidenceDigest(ev({ rootIds: ['b', 'a'] })));
    expect(attestationEvidenceDigest(ev({ identity: { weights_measured: 1 } }))).toBe(base); // only `true` counts
  });
  it('anchoring needs a TransparencyLedger and, when required, a guardian secret', () => {
    const e = ev();
    const NOLEDGER = 'attestation anchoring (fail closed): no transparency ledger available';
    expect(() => anchorAttestationEvidence(e, undefined as never)).toThrow(NOLEDGER);
    expect(() => anchorAttestationEvidence(e, {} as never)).toThrow(NOLEDGER);
    expect(() => anchorAttestationEvidence(e, { ledger: {} as never })).toThrow(NOLEDGER);
    const l = new TransparencyLedger('g');
    expect(() => anchorAttestationEvidence(e, { ledger: l, required: true })).toThrow('attestation anchoring (fail closed): required anchoring needs a guardian secret to sign the tree head');
    expect(l.head().size).toBe(0); // a refused anchor appends nothing
    expect(() => anchorAttestationEvidence(e, { ledger: l, required: true, guardianSecret: 'no' as never })).toThrow('needs a guardian secret');
  });
  it('without a guardian secret (not required) the commitment is appended and no STH is produced', () => {
    const l = new TransparencyLedger('g');
    const e = ev();
    for (const required of [undefined, false, 1 as never]) {
      const a = anchorAttestationEvidence(e, { ledger: l, required });
      expect(a).toStrictEqual({ index: l.head().size - 1, commit: attestationEvidenceDigest(e) });
    }
    expect(l.head().size).toBe(3);
  });
  it('with a guardian secret the tree head is signed over the post-append head', () => {
    const l = new TransparencyLedger('principal-1');
    const g = generateKeyPair();
    const e = ev();
    const first = anchorAttestationEvidence(e, { ledger: l, guardianSecret: g.secretKey, instanceId: 'ins', now: () => 777 });
    expect(first.index).toBe(0);
    expect(first.commit).toBe(attestationEvidenceDigest(e));
    expect(first.sth).toMatchObject({ instance_id: 'ins', principal: 'principal-1', size: 1, root: l.head().root, prev_root: new TransparencyLedger('x').head().root, timestamp: 777, guardian: encodeKey(g.publicKey) });
    expect(verifyTreeHead(first.sth!, encodeKey(g.publicKey))).toBe(true);
    const rootAfterFirst = l.head().root;
    const second = anchorAttestationEvidence(ev({ verifiedAt: 5 }), { ledger: l, guardianSecret: g.secretKey });
    expect(second.index).toBe(1);
    expect(second.sth!.prev_root).toBe(rootAfterFirst);
    expect(second.sth!.size).toBe(2);
    expect(second.sth!.instance_id).toBe('');
    expect(Math.abs(second.sth!.timestamp - Date.now())).toBeLessThan(5000);
  });
  it('a failed STH signature is tolerated unless anchoring is required', () => {
    const e = ev();
    const g = generateKeyPair();
    const badSuite = { alg: 'bogus' as never };
    const tolerant = anchorAttestationEvidence(e, { ledger: new TransparencyLedger('g'), guardianSecret: g.secretKey, suite: badSuite });
    expect(Object.keys(tolerant)).toEqual(['index', 'commit']);
    expect(() => anchorAttestationEvidence(e, { ledger: new TransparencyLedger('g'), guardianSecret: g.secretKey, suite: badSuite, required: true })).toThrow(/^attestation anchoring \(fail closed\): tree-head signing failed: .+/);
  });
});
