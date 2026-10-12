/**
 * Mutation-kill tests for agent-native.ts (part 1): caution claims, rationale binding, argument-schema validation and the
 * tool-schema firewall. Exact reason strings, every boundary, each guard reached on its own.
 */
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytes, hashCanonical } from './hash';
import { generateKeyPair, sign, verifyB64u } from './keys';
import {
  ABSOLUTE_MAX_ARRAY_ITEMS,
  ABSOLUTE_MAX_STRING_LEN,
  DEFAULT_MAX_ARRAY_ITEMS,
  DEFAULT_MAX_STRING_LEN,
  MAX_CAUTION_REASON_LEN,
  MAX_ENUM_VALUES,
  MAX_OBJECT_PROPS,
  MAX_RATIONALE_LEN,
  MAX_SCHEMA_DEPTH,
  MAX_SCHEMA_NODES,
  MAX_VALUE_NODES,
  MIN_SALT_BYTES,
  MIN_SALT_DISTINCT_BYTES,
  agentNativeCaveatEvaluator,
  auditRationale,
  bindRationale,
  checkCautionMonotone,
  combineCaution,
  combineSignedCaution,
  evaluateToolSchema,
  isStrongSalt,
  predicatesCaveat,
  signCaution,
  toolSchemaCaveat,
  toolSchemaEvaluator,
  validateArgSchema,
  verifyCaution,
  verifyRationale,
  type CautionClaim,
  type RationaleCommitment,
} from './agent-native';

const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pk: b64u(k.publicKey) };
};
const H = kp();
const OTHER = kp();
const AD = hashCanonical({ verb: 'x' });
const bytesSalt = (n: number, distinct: number) => b64u(Uint8Array.from({ length: n }, (_, i) => (i % distinct) * 7 + 1));
const SALT = bytesSalt(16, 16);
const throwingGetter = (o: Record<string, unknown>, key: string, thrown: unknown = new Error('getter')) =>
  Object.defineProperty({ ...o }, key, { enumerable: true, get() { throw thrown; } });

// =============================================================================================
describe('signCaution / cautionBodyError', () => {
  const body = (o: Record<string, unknown> = {}) => ({ action_digest: AD, caution: 0.5, holder: H.pk, ...o }) as never;
  const msg = (m: string) => new RangeError(`signCaution: ${m}`);
  it('rejects non-plain bodies', () => {
    expect(() => signCaution(null as never, H.sk)).toThrow(msg('not an object'));
    expect(() => signCaution([] as never, H.sk)).toThrow(msg('not an object'));
    expect(() => signCaution('x' as never, H.sk)).toThrow(msg('not an object'));
    class C { action_digest = AD; caution = 0.5; holder = H.pk; }
    expect(() => signCaution(new C() as never, H.sk)).toThrow(msg('not an object'));
  });
  it('accepts a null-prototype body', () => {
    const b = Object.assign(Object.create(null), { action_digest: AD, caution: 0.5, holder: H.pk });
    expect(signCaution(b, H.sk).caution).toBe(0.5);
  });
  it('requires non-empty string action_digest and holder, each with its own message', () => {
    for (const bad of ['', undefined, 5, null]) expect(() => signCaution(body({ action_digest: bad }), H.sk)).toThrow(msg('action_digest required'));
    for (const bad of ['', undefined, 5, null]) expect(() => signCaution(body({ holder: bad }), H.sk)).toThrow(msg('holder required'));
  });
  it('caution must be a finite number in [0,1], inclusive', () => {
    const m = msg('caution must be a finite number in [0,1]');
    for (const bad of [NaN, Infinity, -Infinity, -0.0001, 1.0001, 2, -1, '0.5', undefined, null]) expect(() => signCaution(body({ caution: bad }), H.sk)).toThrow(m);
    expect(signCaution(body({ caution: 0 }), H.sk).caution).toBe(0);
    expect(signCaution(body({ caution: 1 }), H.sk).caution).toBe(1);
  });
  it('reason: string of [A-Za-z0-9_.:-], 1..64 chars', () => {
    const m = msg('invalid reason');
    for (const bad of [5, '', 'has space', 'bad/char', 'x'.repeat(MAX_CAUTION_REASON_LEN + 1), null, {}]) expect(() => signCaution(body({ reason: bad }), H.sk)).toThrow(m);
    expect(signCaution(body({ reason: 'x'.repeat(MAX_CAUTION_REASON_LEN) }), H.sk).reason).toHaveLength(MAX_CAUTION_REASON_LEN);
    expect(signCaution(body({ reason: 'a.b:c_d-E9' }), H.sk).reason).toBe('a.b:c_d-E9');
  });
  it('signature covers exactly the domain-separated clean body (reason included only when present)', () => {
    const c = signCaution(body({ reason: 'ood', ignored: 'dropped' }), H.sk);
    expect(Object.keys(c).sort()).toEqual(['action_digest', 'caution', 'holder', 'reason', 'sig']);
    expect(verifyB64u(H.pk, canonicalBytes({ d: 'atlas-pca/caution/v1', b: { action_digest: AD, caution: 0.5, holder: H.pk, reason: 'ood' } }), c.sig)).toBe(true);
    const n = signCaution(body(), H.sk);
    expect(Object.keys(n).sort()).toEqual(['action_digest', 'caution', 'holder', 'sig']);
    expect('reason' in n).toBe(false);
    expect(verifyB64u(H.pk, canonicalBytes({ d: 'atlas-pca/caution/v1', b: { action_digest: AD, caution: 0.5, holder: H.pk } }), n.sig)).toBe(true);
    expect(verifyB64u(H.pk, canonicalBytes({ d: 'other', b: { action_digest: AD, caution: 0.5, holder: H.pk } }), n.sig)).toBe(false);
  });
});

describe('verifyCaution', () => {
  const claim = (o: Record<string, unknown> = {}): CautionClaim => signCaution({ action_digest: AD, caution: 0.5, holder: H.pk, ...o } as never, H.sk);
  const forge = (b: Record<string, unknown>, domain = 'atlas-pca/caution/v1') => ({ ...b, sig: b64u(sign(H.sk, canonicalBytes({ d: domain, b }))) }) as unknown as CautionClaim;
  it('accepts a valid claim with and without expectations', () => {
    const c = claim();
    expect(verifyCaution(c)).toBe(true);
    expect(verifyCaution(c, AD)).toBe(true);
    expect(verifyCaution(c, undefined, H.pk)).toBe(true);
    expect(verifyCaution(c, AD, H.pk)).toBe(true);
    expect(verifyCaution(claim({ reason: 'ood' }))).toBe(true);
  });
  it('binds action digest and holder', () => {
    const c = claim();
    expect(verifyCaution(c, hashCanonical({ verb: 'y' }))).toBe(false);
    expect(verifyCaution(c, AD, OTHER.pk)).toBe(false);
    expect(verifyCaution(c, 'x', H.pk)).toBe(false);
  });
  it('rejects non-plain / non-object claims', () => {
    expect(verifyCaution(null as never)).toBe(false);
    expect(verifyCaution(undefined as never)).toBe(false);
    expect(verifyCaution('x' as never)).toBe(false);
    class C {}
    expect(verifyCaution(Object.assign(new C(), claim()) as never)).toBe(false);
  });
  it('rejects a missing / non-string sig and smuggled fields', () => {
    const c = claim();
    expect(verifyCaution({ ...c, sig: 5 } as never)).toBe(false);
    const { sig: _s, ...nosig } = c;
    void _s;
    expect(verifyCaution(nosig as never)).toBe(false);
    expect(verifyCaution({ ...c, extra: 1 } as never)).toBe(false);
  });
  it('rejects a validly signed but structurally invalid body (each rule)', () => {
    expect(verifyCaution(forge({ action_digest: AD, caution: 2, holder: H.pk }))).toBe(false);
    expect(verifyCaution(forge({ action_digest: AD, caution: -1, holder: H.pk }))).toBe(false);
    expect(verifyCaution(forge({ action_digest: '', caution: 0.5, holder: H.pk }))).toBe(false);
    expect(verifyCaution(forge({ action_digest: AD, caution: 0.5, holder: H.pk, reason: 'has space' }))).toBe(false);
    expect(verifyCaution(forge({ action_digest: AD, caution: 0.5, holder: H.pk }))).toBe(true); // control
  });
  it('rejects a validly signed claim that smuggles an extra field into the signed body', () => {
    expect(verifyCaution(forge({ action_digest: AD, caution: 0.5, holder: H.pk, extra: 'x' }))).toBe(false);
    expect(verifyCaution(forge({ action_digest: AD, caution: 0.5, holder: H.pk, reason: 'ok', extra: 1 }))).toBe(false);
    expect(verifyCaution(forge({ action_digest: AD, caution: 0.5, holder: H.pk, reason: 'ok' }))).toBe(true);
  });
  it('rejects wrong domain, tampering and a different signer', () => {
    expect(verifyCaution(forge({ action_digest: AD, caution: 0.5, holder: H.pk }, 'other-domain'))).toBe(false);
    expect(verifyCaution({ ...claim(), caution: 0.6 })).toBe(false);
    const impostor = signCaution({ action_digest: AD, caution: 0.5, holder: H.pk }, OTHER.sk);
    expect(verifyCaution(impostor)).toBe(false);
  });
  it('is total: a throwing accessor yields false', () => {
    expect(verifyCaution(throwingGetter({ ...claim() }, 'sig') as never)).toBe(false);
    expect(verifyCaution(throwingGetter({ ...claim() }, 'caution', 'string thrown') as never)).toBe(false);
  });
});

describe('combineSignedCaution', () => {
  const claim = (caution: number, holder = H) => signCaution({ action_digest: AD, caution, holder: holder.pk }, holder.sk);
  it('no claim => server risk, not honoured', () => {
    expect(combineSignedCaution(undefined, AD, 0.4)).toEqual({ effectiveRisk: 0.4, honoured: false, escalated: false });
  });
  it('valid claim above server risk escalates', () => {
    expect(combineSignedCaution(claim(0.9), AD, 0.4)).toEqual({ effectiveRisk: 0.9, honoured: true, escalated: true });
  });
  it('valid claim below / equal to server risk is honoured but never lowers; escalated requires strictly greater', () => {
    expect(combineSignedCaution(claim(0.2), AD, 0.4)).toEqual({ effectiveRisk: 0.4, honoured: true, escalated: false });
    expect(combineSignedCaution(claim(0.4), AD, 0.4)).toEqual({ effectiveRisk: 0.4, honoured: true, escalated: false });
  });
  it('misbound / forged / wrong-holder claims degrade to server risk', () => {
    expect(combineSignedCaution(claim(0.9), hashCanonical({ verb: 'z' }), 0.4)).toEqual({ effectiveRisk: 0.4, honoured: false, escalated: false });
    expect(combineSignedCaution(claim(0.9), AD, 0.4, OTHER.pk)).toEqual({ effectiveRisk: 0.4, honoured: false, escalated: false });
    expect(combineSignedCaution(claim(0.9), AD, 0.4, H.pk)).toEqual({ effectiveRisk: 0.9, honoured: true, escalated: true });
    expect(combineSignedCaution({ ...claim(0.9), caution: 1 }, AD, 0.4)).toEqual({ effectiveRisk: 0.4, honoured: false, escalated: false });
  });
  it('unusable server risk fails closed to 1 (clamped otherwise)', () => {
    expect(combineSignedCaution(claim(0.1), AD, NaN)).toEqual({ effectiveRisk: 1, honoured: true, escalated: false });
    expect(combineSignedCaution(undefined, AD, 7).effectiveRisk).toBe(1);
    expect(combineSignedCaution(undefined, AD, -3).effectiveRisk).toBe(0);
    expect(combineSignedCaution(claim(0), AD, -3)).toEqual({ effectiveRisk: 0, honoured: true, escalated: false });
  });
});

describe('combineCaution / checkCautionMonotone', () => {
  it('exact values and clamping', () => {
    expect(combineCaution(0.3, 0.6)).toBe(0.6);
    expect(combineCaution(0.8, 0.6)).toBe(0.8);
    expect(combineCaution(5, 0.6)).toBe(1);
    expect(combineCaution(0.2, 9)).toBe(1);
    expect(combineCaution(0.2, -9)).toBe(0.2);
    expect(combineCaution(-2, -9)).toBe(0);
  });
  it('unusable declarations (NaN / Infinity / undefined) are ignored in the grid check, so it stays ok', () => {
    expect(checkCautionMonotone([0.5, Infinity, NaN, 0.2, -Infinity])).toEqual({ ok: true });
    expect(checkCautionMonotone([])).toEqual({ ok: true });
    expect(checkCautionMonotone([0, 0.5, 1])).toEqual({ ok: true });
  });
});

// =============================================================================================
describe('isStrongSalt', () => {
  it('constants', () => {
    expect(MIN_SALT_BYTES).toBe(16);
    expect(MIN_SALT_DISTINCT_BYTES).toBe(8);
    expect(MAX_RATIONALE_LEN).toBe(8192);
  });
  it('non-strings and bad alphabets', () => {
    for (const bad of [undefined, null, 5, {}, [], '', 'not base64!', 'has space', '+/==']) expect(isStrongSalt(bad)).toBe(false);
  });
  it('anchored alphabet: junk before OR after a strong salt is rejected', () => {
    expect(isStrongSalt(SALT)).toBe(true);
    expect(isStrongSalt(`!!${SALT}`)).toBe(false);
    expect(isStrongSalt(`${SALT}!!`)).toBe(false);
    expect(isStrongSalt(`${SALT}\n`)).toBe(false);
    expect(isStrongSalt(`\n${SALT}`)).toBe(false);
  });
  it('length cap is 256 chars inclusive', () => {
    const s256 = b64u(Uint8Array.from({ length: 192 }, (_, i) => (i * 5) % 251));
    expect(s256).toHaveLength(256);
    expect(isStrongSalt(s256)).toBe(true);
    const s257 = `${s256}A`;
    expect(isStrongSalt(s257)).toBe(false);
    const s260 = b64u(Uint8Array.from({ length: 195 }, (_, i) => (i * 5) % 251)); // valid base64url, strong, but over the cap
    expect(s260).toHaveLength(260);
    expect(isStrongSalt(s260)).toBe(false);
  });
  it('needs >= 16 bytes and >= 8 distinct byte values (both inclusive)', () => {
    expect(isStrongSalt(bytesSalt(15, 15))).toBe(false); // too short
    expect(isStrongSalt(bytesSalt(16, 16))).toBe(true);
    expect(isStrongSalt(bytesSalt(12, 12))).toBe(false); // short but many distinct
    expect(isStrongSalt(bytesSalt(16, 8))).toBe(true); // exactly 8 distinct
    expect(isStrongSalt(bytesSalt(16, 7))).toBe(false);
    expect(isStrongSalt(bytesSalt(64, 1))).toBe(false);
    expect(isStrongSalt(bytesSalt(8, 8))).toBe(false); // 8 distinct but only 8 bytes
  });
});

describe('bindRationale / verifyRationale', () => {
  const action = { verb: 'send', to: 'a@b.c' };
  it('exact commitment shape and reveal', () => {
    const { commitment, reveal } = bindRationale(action, 'because', SALT);
    const ad = hashCanonical(action);
    expect(commitment).toEqual({ v: 1, action_digest: ad, commitment: hashCanonical({ d: 'atlas-pca/rationale/v1', a: ad, s: SALT, r: 'because' }) });
    expect(reveal).toEqual({ rationale: 'because', salt: SALT });
  });
  it('default salt is random and strong', () => {
    const a = bindRationale(action, 'r');
    const b = bindRationale(action, 'r');
    expect(a.reveal.salt).not.toBe(b.reveal.salt);
    expect(isStrongSalt(a.reveal.salt)).toBe(true);
    expect(a.commitment.commitment).not.toBe(b.commitment.commitment);
    expect(verifyRationale(a.commitment, a.reveal, action)).toBe(true);
  });
  it('authoring errors carry exact types and messages', () => {
    expect(() => bindRationale(action, 5 as never, SALT)).toThrow(new TypeError('bindRationale: rationale must be a string'));
    expect(() => bindRationale(action, 'x'.repeat(MAX_RATIONALE_LEN + 1), SALT)).toThrow(new RangeError('bindRationale: rationale too long'));
    expect(() => bindRationale(action, 'x'.repeat(MAX_RATIONALE_LEN), SALT)).not.toThrow();
    expect(() => bindRationale(action, '', SALT)).not.toThrow();
    expect(() => bindRationale(action, 'r', 'weak')).toThrow(new RangeError('bindRationale: salt must be b64u of >=16 bytes with >=8 distinct values'));
    expect(() => bindRationale({ x: undefined }, 'r', SALT)).toThrow();
  });
  const good = () => bindRationale(action, 'because', SALT);
  it('verifyRationale: accepts the opening, with and without the action', () => {
    const { commitment, reveal } = good();
    expect(verifyRationale(commitment, reveal)).toBe(true);
    expect(verifyRationale(commitment, reveal, action)).toBe(true);
    expect(verifyRationale(commitment, reveal, { ...action, to: 'x' })).toBe(false);
  });
  it('verifyRationale: rejects wrong rationale / salt / commitment', () => {
    const { commitment, reveal } = good();
    expect(verifyRationale(commitment, { ...reveal, rationale: 'other' })).toBe(false);
    expect(verifyRationale(commitment, { ...reveal, salt: bytesSalt(16, 12) })).toBe(false);
    expect(verifyRationale({ ...commitment, commitment: 'zzz' }, reveal)).toBe(false);
  });
  it('verifyRationale: structural guards, each alone', () => {
    const { commitment, reveal } = good();
    class C {}
    expect(verifyRationale(null as never, reveal)).toBe(false);
    expect(verifyRationale(commitment, null as never)).toBe(false);
    expect(verifyRationale(Object.assign(new C(), commitment) as never, reveal)).toBe(false);
    expect(verifyRationale(commitment, Object.assign(new C(), reveal) as never)).toBe(false);
    expect(verifyRationale({ ...commitment, v: 2 } as never, reveal)).toBe(false);
    expect(verifyRationale({ ...commitment, action_digest: '' }, reveal)).toBe(false);
    expect(verifyRationale({ ...commitment, action_digest: 5 } as never, reveal)).toBe(false);
    expect(verifyRationale({ ...commitment, commitment: '' }, reveal)).toBe(false);
    expect(verifyRationale({ ...commitment, commitment: 5 } as never, reveal)).toBe(false);
    expect(verifyRationale(commitment, { ...reveal, rationale: 5 } as never)).toBe(false);
  });
  it('verifyRationale: a weak salt or an over-long rationale is rejected even if it hashes correctly', () => {
    const weak = 'AAAAAAAAAAAAAAAAAAAAAA';
    const ad = hashCanonical(action);
    const c1: RationaleCommitment = { v: 1, action_digest: ad, commitment: hashCanonical({ d: 'atlas-pca/rationale/v1', a: ad, s: weak, r: 'r' }) };
    expect(verifyRationale(c1, { rationale: 'r', salt: weak })).toBe(false);
    const edge = 'x'.repeat(MAX_RATIONALE_LEN);
    expect(verifyRationale(bindRationale(action, edge, SALT).commitment, { rationale: edge, salt: SALT })).toBe(true);
    const long = 'x'.repeat(MAX_RATIONALE_LEN + 1);
    const c2: RationaleCommitment = { v: 1, action_digest: ad, commitment: hashCanonical({ d: 'atlas-pca/rationale/v1', a: ad, s: SALT, r: long }) };
    expect(verifyRationale(c2, { rationale: long, salt: SALT })).toBe(false);
  });
  it('verifyRationale is total (throwing accessor => false)', () => {
    const { commitment, reveal } = good();
    expect(verifyRationale(commitment, throwingGetter({ ...reveal }, 'rationale') as never)).toBe(false);
    expect(verifyRationale(commitment, reveal, { x: undefined })).toBe(false);
  });
});

describe('auditRationale', () => {
  const action = { verb: 'send', n: 1 };
  const { commitment, reveal } = bindRationale(action, 'reason', SALT);
  const ev = { commitment: commitment.commitment, action_digest: commitment.action_digest };
  const yes = () => true;
  it('consistent / false_rationale carry the rationale in evidence; slashable only when false', () => {
    expect(auditRationale(commitment, action, reveal, yes)).toEqual({ verdict: 'consistent', slashable: false, evidence: { ...ev, rationale: 'reason' } });
    expect(auditRationale(commitment, action, reveal, () => false)).toEqual({ verdict: 'false_rationale', slashable: true, evidence: { ...ev, rationale: 'reason' } });
  });
  it('only a literal `true` from the judge is consistent', () => {
    expect(auditRationale(commitment, action, reveal, (() => 1) as never).verdict).toBe('false_rationale');
    expect(auditRationale(commitment, action, reveal, (() => 'yes') as never).verdict).toBe('false_rationale');
    expect(auditRationale(commitment, action, reveal, (() => undefined) as never).verdict).toBe('false_rationale');
  });
  it('the judge receives (rationale, action)', () => {
    const seen: unknown[] = [];
    auditRationale(commitment, action, reveal, (r, a) => (seen.push(r, a), true));
    expect(seen).toEqual(['reason', action]);
  });
  it('a throwing judge => judge_error, not slashable, evidence has the rationale', () => {
    expect(auditRationale(commitment, action, reveal, () => { throw new Error('x'); })).toEqual({
      verdict: 'judge_error',
      slashable: false,
      evidence: { ...ev, rationale: 'reason' },
    });
  });
  it('unopened (missing / wrong / weak reveal) is slashable, evidence without rationale', () => {
    const exp = { verdict: 'unopened', slashable: true, evidence: ev };
    expect(auditRationale(commitment, action, undefined, yes)).toEqual(exp);
    expect(auditRationale(commitment, action, { ...reveal, rationale: 'other' }, yes)).toEqual(exp);
    expect(auditRationale(commitment, action, { ...reveal, salt: bytesSalt(16, 10) }, yes)).toEqual(exp);
    expect('rationale' in auditRationale(commitment, action, undefined, yes).evidence).toBe(false);
  });
  it('wrong_action is not slashable and is reported before opening is checked', () => {
    expect(auditRationale(commitment, { verb: 'other' }, reveal, yes)).toEqual({ verdict: 'wrong_action', slashable: false, evidence: ev });
    expect(auditRationale(commitment, { verb: 'other' }, undefined, yes).verdict).toBe('wrong_action');
  });
  it('malformed commitments (each field alone) keep whatever evidence strings they carry', () => {
    const empty = { commitment: '', action_digest: '' };
    expect(auditRationale(null as never, action, reveal, yes)).toEqual({ verdict: 'malformed', slashable: false, evidence: empty });
    expect(auditRationale('x' as never, action, reveal, yes)).toEqual({ verdict: 'malformed', slashable: false, evidence: empty });
    class C {}
    const nonPlain = Object.assign(new C(), commitment);
    expect(auditRationale(nonPlain as never, action, reveal, yes)).toEqual({ verdict: 'malformed', slashable: false, evidence: empty });
    expect(auditRationale({ ...commitment, v: 2 } as never, action, reveal, yes)).toEqual({ verdict: 'malformed', slashable: false, evidence: ev });
    expect(auditRationale({ ...commitment, action_digest: '' }, action, reveal, yes)).toEqual({
      verdict: 'malformed',
      slashable: false,
      evidence: { commitment: commitment.commitment, action_digest: '' },
    });
    expect(auditRationale({ ...commitment, commitment: '' }, action, reveal, yes)).toEqual({
      verdict: 'malformed',
      slashable: false,
      evidence: { commitment: '', action_digest: commitment.action_digest },
    });
    expect(auditRationale({ ...commitment, commitment: 5 } as never, action, reveal, yes).evidence).toEqual({ commitment: '', action_digest: commitment.action_digest });
    expect(auditRationale({ ...commitment, action_digest: 5 } as never, action, reveal, yes).evidence).toEqual({ commitment: commitment.commitment, action_digest: '' });
  });
  it('is total: an un-hashable action => malformed', () => {
    expect(auditRationale(commitment, { x: undefined }, reveal, yes)).toEqual({ verdict: 'malformed', slashable: false, evidence: ev });
  });
});

// =============================================================================================
describe('validateArgSchema', () => {
  const v = (s: unknown) => validateArgSchema(s);
  const props = (n: number, spec: unknown = { type: 'boolean' }) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`p${i}`, spec]));
  const objSpec = (inner: Record<string, unknown>) => ({ type: 'object', props: inner });
  const nestObjs = (m: number, leaf?: unknown) => {
    let spec: unknown = objSpec(leaf ? { x: leaf } : {});
    for (let i = 1; i < m; i++) spec = objSpec({ a: spec });
    return { props: { a: spec } };
  };
  const nestArrs = (m: number, leaf: unknown = { type: 'boolean' }) => {
    let spec: unknown = leaf;
    for (let i = 0; i < m; i++) spec = { type: 'array', items: spec };
    return { props: { a: spec } };
  };
  it('constants', () => {
    expect([MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES, MAX_OBJECT_PROPS, MAX_ENUM_VALUES, DEFAULT_MAX_ARRAY_ITEMS, ABSOLUTE_MAX_ARRAY_ITEMS, DEFAULT_MAX_STRING_LEN, ABSOLUTE_MAX_STRING_LEN, MAX_VALUE_NODES]).toEqual([
      8, 256, 64, 256, 256, 4096, 65536, 1048576, 10000,
    ]);
  });
  it('top-level shape', () => {
    class C {}
    for (const bad of [null, undefined, [], 'x', 5, Object.assign(new C(), { props: {} })]) expect(v(bad)).toBe('schema must be an object');
    expect(v({ props: {}, extra: 1 })).toBe('unknown schema key');
    expect(v({})).toBe('props must be an object');
    expect(v({ props: [] })).toBe('props must be an object');
    expect(v({ props: null })).toBe('props must be an object');
    expect(v({ props: {} })).toBeNull();
    expect(v({ props: {}, required: [] })).toBeNull();
  });
  it('property names', () => {
    expect(v({ props: { 'bad-name': { type: 'boolean' } } })).toBe("invalid property name 'bad-name'");
    expect(v({ props: { '': { type: 'boolean' } } })).toBe("invalid property name ''");
    expect(v({ props: { ['a'.repeat(65)]: { type: 'boolean' } } })).toBe(`invalid property name '${'a'.repeat(32)}'`);
    expect(v({ props: { ['a'.repeat(64)]: { type: 'boolean' } } })).toBeNull();
    expect(v({ props: { aZ_09: { type: 'boolean' } } })).toBeNull();
  });
  it('property count: 64 ok, 65 too many', () => {
    expect(v({ props: props(64) })).toBeNull();
    expect(v({ props: props(65) })).toBe('too many props');
  });
  it('required: array of declared names, at most 64', () => {
    const p = props(64);
    expect(v({ props: p, required: Object.keys(p) })).toBeNull();
    expect(v({ props: p, required: [...Object.keys(p), 'p0'] })).toBe('required must be a short array');
    expect(v({ props: p, required: 'p0' })).toBe('required must be a short array');
    expect(v({ props: p, required: { length: 1, 0: 'p0' } })).toBe('required must be a short array');
    expect(v({ props: { a: { type: 'boolean' } }, required: ['zz'] })).toBe('required names an undeclared property');
    expect(v({ props: { a: { type: 'boolean' } }, required: [5] })).toBe('required names an undeclared property');
    expect(v({ props: { a: { type: 'boolean' } }, required: ['toString'] })).toBe('required names an undeclared property');
    expect(v({ props: { a: { type: 'boolean' } }, required: ['a'] })).toBeNull();
  });
  it('nested errors are prefixed with the property path', () => {
    expect(v({ props: { a: { type: 'bogus' } } })).toBe('a: unknown type');
    expect(v({ props: { a: objSpec({ b: { type: 'bogus' } }) } })).toBe('a: b: unknown type');
    expect(v({ props: { a: { type: 'array', items: { type: 'bogus' } } } })).toBe('a: unknown type');
  });
  it('object nesting depth: objects above the limit are refused (empty innermost: 7 ok / 8 not)', () => {
    expect(v(nestObjs(7))).toBeNull();
    expect(v(nestObjs(8))).toMatch(/schema too deep$/);
    expect(v(nestObjs(8))).toBe(`${'a: '.repeat(8)}schema too deep`);
  });
  it('object nesting depth with a leaf: 6 ok / 7 not', () => {
    expect(v(nestObjs(6, { type: 'boolean' }))).toBeNull();
    expect(v(nestObjs(7, { type: 'boolean' }))).toBe(`${'a: '.repeat(7)}x: schema too deep`);
  });
  it('array nesting depth: 6 ok / 7 not', () => {
    expect(v(nestArrs(6))).toBeNull();
    expect(v(nestArrs(7))).toBe('a: schema too deep');
  });
  it('node budget: 256 nodes ok, 257 too large (leaf overflow and object overflow)', () => {
    const leaves = (n: number) => props(n);
    const withObjs = (topLeaves: number, objs: number[]) => {
      const p: Record<string, unknown> = { ...Object.fromEntries(Object.entries(leaves(topLeaves)).map(([k, s]) => [`l${k}`, s])) };
      objs.forEach((n, i) => (p[`o${i}`] = objSpec(leaves(n))));
      return { props: p };
    };
    // 1 (top) + topLeaves + sum(1 + n_i)
    expect(v(withObjs(59, [64, 64, 64, 0]))).toBeNull(); // 1 + 59 + 3*65 + 1 = 256
    expect(v(withObjs(60, [64, 64, 64, 0]))).toBe('o3: schema too large'); // 257th node is the empty object
    expect(v(withObjs(59, [64, 64, 64, 1]))).toBe('o3: p0: schema too large'); // 257th node is a leaf
    expect(v(withObjs(0, [40, 40, 40, 40, 40]))).toBeNull(); // 1 + 5*41 = 206
    expect(v(withObjs(50, [40, 40, 40, 40, 40]))).toBeNull(); // 256
    expect(v(withObjs(51, [40, 40, 40, 40, 40]))).toMatch(/schema too large$/); // 257
  });
  it('spec must be a plain object with a known own `type`', () => {
    class C {}
    for (const bad of [null, 5, 'x', [], Object.assign(new C(), { type: 'boolean' }), {}, { type: 5 }, { type: 'toString' }, { type: 'constructor' }, { type: '__proto__' }]) {
      expect(v({ props: { a: bad } })).toBe('a: unknown type');
    }
  });
  it('unknown spec keys per type', () => {
    expect(v({ props: { a: { type: 'string', foo: 1 } } })).toBe('a: unknown spec key');
    expect(v({ props: { a: { type: 'string', min: 1 } } })).toBe('a: unknown spec key');
    expect(v({ props: { a: { type: 'number', minLength: 1 } } })).toBe('a: unknown spec key');
    expect(v({ props: { a: { type: 'boolean', min: 1 } } })).toBe('a: unknown spec key');
    expect(v({ props: { a: { type: 'object', props: {}, enum: [] } } })).toBe('a: unknown spec key');
    expect(v({ props: { a: { type: 'array', items: { type: 'boolean' }, props: {} } } })).toBe('a: unknown spec key');
    expect(v({ props: { a: { type: 'integer', prefix: 'x' } } })).toBe('a: unknown spec key');
  });
  it('object specs: props required, required checked', () => {
    expect(v({ props: { a: { type: 'object' } } })).toBe('a: props must be an object');
    expect(v({ props: { a: { type: 'object', props: {}, required: ['q'] } } })).toBe('a: required names an undeclared property');
    expect(v({ props: { a: { type: 'object', props: { q: { type: 'string' } }, required: ['q'] } } })).toBeNull();
  });
  it('arrays: items required; minItems / maxItems bounds', () => {
    const arr = (o: Record<string, unknown>) => v({ props: { a: { type: 'array', items: { type: 'boolean' }, ...o } } });
    expect(v({ props: { a: { type: 'array' } } })).toBe('a: unknown type');
    for (const bad of [-1, 4097, 1.5, NaN, '1', null]) {
      expect(arr({ minItems: bad })).toBe('a: bad minItems');
      expect(arr({ maxItems: bad })).toBe('a: bad maxItems');
    }
    expect(arr({ minItems: 0 })).toBeNull();
    expect(arr({ minItems: 4096, maxItems: 4096 })).toBeNull();
    expect(arr({ maxItems: 0 })).toBeNull();
    expect(arr({ minItems: 3, maxItems: 2 })).toBe('a: minItems > maxItems');
    expect(arr({ minItems: 2, maxItems: 2 })).toBeNull();
    expect(arr({ minItems: 2, maxItems: 3 })).toBeNull();
    expect(arr({ minItems: 5 })).toBeNull();
  });
  it('const / enum validity per scalar type', () => {
    const s = (spec: Record<string, unknown>) => v({ props: { a: spec } });
    expect(s({ type: 'string', const: 5 })).toBe('a: bad const');
    expect(s({ type: 'string', const: undefined })).toBe('a: bad const');
    expect(s({ type: 'string', const: 'x'.repeat(1024) })).toBeNull();
    expect(s({ type: 'string', const: 'x'.repeat(1025) })).toBe('a: bad const');
    expect(s({ type: 'number', const: '1' })).toBe('a: bad const');
    expect(s({ type: 'number', const: NaN })).toBe('a: bad const');
    expect(s({ type: 'number', const: Infinity })).toBe('a: bad const');
    expect(s({ type: 'number', const: 1.5 })).toBeNull();
    expect(s({ type: 'integer', const: 1.5 })).toBe('a: bad const');
    expect(s({ type: 'integer', const: 2 })).toBeNull();
    expect(s({ type: 'boolean', const: 'true' })).toBe('a: bad const');
    expect(s({ type: 'boolean', const: 1 })).toBe('a: bad const');
    expect(s({ type: 'boolean', const: false })).toBeNull();
    expect(s({ type: 'string', enum: [] })).toBe('a: bad enum');
    expect(s({ type: 'string', enum: 'abc' })).toBe('a: bad enum');
    expect(s({ type: 'string', enum: ['a', 5] })).toBe('a: bad enum');
    expect(s({ type: 'string', enum: [5, 'a'] })).toBe('a: bad enum');
    expect(s({ type: 'string', enum: ['a', 'b'] })).toBeNull();
    expect(s({ type: 'string', enum: ['x'.repeat(1025)] })).toBe('a: bad enum');
    expect(s({ type: 'string', enum: Array.from({ length: 256 }, (_, i) => `v${i}`) })).toBeNull();
    expect(s({ type: 'string', enum: Array.from({ length: 257 }, (_, i) => `v${i}`) })).toBe('a: bad enum');
    expect(s({ type: 'integer', enum: [1, 2.5] })).toBe('a: bad enum');
    expect(s({ type: 'number', enum: [1.5, 2] })).toBeNull();
    expect(s({ type: 'number', enum: [NaN] })).toBe('a: bad enum');
    expect(s({ type: 'boolean', enum: [true, 'x'] })).toBe('a: bad enum');
    expect(s({ type: 'boolean', enum: [true, false] })).toBeNull();
  });
  it('string bounds: minLength / maxLength / prefix', () => {
    const s = (o: Record<string, unknown>) => v({ props: { a: { type: 'string', ...o } } });
    for (const bad of [-1, 1_048_577, 1.5, '1', NaN]) {
      expect(s({ minLength: bad })).toBe('a: bad minLength');
      expect(s({ maxLength: bad })).toBe('a: bad maxLength');
    }
    expect(s({ minLength: 0, maxLength: 1_048_576 })).toBeNull();
    expect(s({ minLength: 3, maxLength: 2 })).toBe('a: minLength > maxLength');
    expect(s({ minLength: 2, maxLength: 2 })).toBeNull();
    expect(s({ minLength: 9 })).toBeNull();
    expect(s({ prefix: 5 })).toBe('a: bad prefix');
    expect(s({ prefix: 'x'.repeat(513) })).toBe('a: bad prefix');
    expect(s({ prefix: 'x'.repeat(512) })).toBeNull();
    expect(s({ prefix: '' })).toBeNull();
  });
  it('number / integer bounds: min / max', () => {
    for (const type of ['number', 'integer']) {
      const s = (o: Record<string, unknown>) => v({ props: { a: { type, ...o } } });
      for (const bad of [NaN, Infinity, '1', null]) {
        expect(s({ min: bad })).toBe('a: bad min');
        expect(s({ max: bad })).toBe('a: bad max');
      }
      expect(s({ min: -5, max: 5 })).toBeNull();
      expect(s({ min: 6, max: 5 })).toBe('a: min > max');
      expect(s({ min: 5, max: 5 })).toBeNull();
      expect(s({ min: 1 })).toBeNull();
    }
  });
  it('a rich valid schema passes', () => {
    expect(
      v({
        props: {
          to: { type: 'string', prefix: 'ops@', minLength: 5, maxLength: 50, enum: ['ops@a.com'] },
          n: { type: 'integer', min: 0, max: 10, const: 3 },
          f: { type: 'number', min: -1.5, max: 1.5 },
          b: { type: 'boolean', enum: [true] },
          list: { type: 'array', minItems: 1, maxItems: 3, items: { type: 'string' } },
          obj: { type: 'object', props: { x: { type: 'boolean' } }, required: ['x'] },
        },
        required: ['to', 'n'],
      }),
    ).toBeNull();
  });
});

describe('toolSchemaCaveat / predicatesCaveat', () => {
  const schema = { props: { to: { type: 'string' as const, prefix: 'ops@' } }, required: ['to'] };
  it('builds the documented digests', () => {
    const sig = { name: 'send', params: { to: 'string' } };
    const c = toolSchemaCaveat(sig, schema);
    const sd = hashCanonical(sig);
    expect(c).toEqual({
      type: 'tool_schema',
      tool: 'send',
      signature_digest: sd,
      schema,
      schema_digest: hashCanonical(schema),
      binding_digest: hashCanonical({ tool: 'send', signature_digest: sd, schema }),
    });
    expect(toolSchemaCaveat('send', schema).tool).toBe('send');
    expect(toolSchemaCaveat('send', schema).signature_digest).toBe(hashCanonical('send'));
  });
  it('tool name required (string, or object with a string name)', () => {
    const m = new TypeError('toolSchemaCaveat: tool name required');
    for (const bad of ['', {}, { name: '' }, { name: 5 }, { name: null }, 5, null, undefined, [], ['x']]) expect(() => toolSchemaCaveat(bad, schema)).toThrow(m);
  });
  it('an invalid schema is refused with its reason', () => {
    expect(() => toolSchemaCaveat('t', { props: { a: { type: 'bogus' } } } as never)).toThrow(new TypeError('toolSchemaCaveat: a: unknown type'));
    expect(() => toolSchemaCaveat('t', null as never)).toThrow(new TypeError('toolSchemaCaveat: schema must be an object'));
  });
  it('the schema is deep-cloned in canonical form', () => {
    const live = { props: { b: { type: 'string' as const }, a: { type: 'string' as const } } };
    const c = toolSchemaCaveat('t', live);
    live.props.a = { type: 'number' } as never;
    expect((c.schema.props.a as { type: string }).type).toBe('string');
    expect(Object.keys(c.schema.props)).toEqual(['a', 'b']);
  });
  it('predicatesCaveat deep-clones canonically', () => {
    const allow = [{ verb: ['b', 'a'], resource: '/x/*' }];
    const c = predicatesCaveat(allow as never);
    expect(c).toEqual({ type: 'predicates', allow });
    allow[0]!.resource = '/changed';
    expect((c.allow[0] as { resource: string }).resource).toBe('/x/*');
  });
});

// =============================================================================================
describe('evaluateToolSchema: caveat / call validation', () => {
  const sig = { name: 'send', params: { to: 'string' } };
  const schema = { props: { to: { type: 'string' as const } }, required: ['to'] };
  const cav = () => toolSchemaCaveat(sig, schema);
  const call = (o: Record<string, unknown> = {}) => ({ tool: 'send', args: { to: 'a' }, ...o }) as never;
  const bad = (reason: string) => ({ ok: false, reason });
  it('ok result is exactly { ok: true }', () => {
    expect(evaluateToolSchema(cav(), call())).toEqual({ ok: true });
    expect('reason' in evaluateToolSchema(cav(), call())).toBe(false);
    expect(evaluateToolSchema(cav(), call({ toolSignature: sig }))).toEqual({ ok: true });
    expect(evaluateToolSchema(cav(), call({ toolSignatureDigest: hashCanonical(sig) }))).toEqual({ ok: true });
  });
  it('malformed caveat shapes', () => {
    const m = bad('malformed tool_schema caveat');
    expect(evaluateToolSchema(null as never, call())).toEqual(m);
    expect(evaluateToolSchema([] as never, call())).toEqual(m);
    expect(evaluateToolSchema({ ...cav(), type: 'other' } as never, call())).toEqual(m);
    expect(evaluateToolSchema({ ...cav(), tool: '' }, call())).toEqual(m);
    expect(evaluateToolSchema({ ...cav(), tool: 5 } as never, call())).toEqual(m);
    const { tool: _t, ...notool } = cav();
    void _t;
    expect(evaluateToolSchema(notool as never, call())).toEqual(m);
  });
  it('an invalid embedded schema is reported with the validation reason', () => {
    expect(evaluateToolSchema({ ...cav(), schema: { props: { a: { type: 'bogus' } } } } as never, call())).toEqual(bad('malformed tool_schema caveat: a: unknown type'));
    expect(evaluateToolSchema({ ...cav(), schema: null } as never, call())).toEqual(bad('malformed tool_schema caveat: schema must be an object'));
  });
  it('digest consistency', () => {
    expect(evaluateToolSchema({ ...cav(), schema_digest: 'x' }, call())).toEqual(bad('schema digest mismatch'));
    expect(evaluateToolSchema({ ...cav(), binding_digest: 'x' }, call())).toEqual(bad('binding digest mismatch'));
    expect(evaluateToolSchema({ ...cav(), signature_digest: 'x' }, call())).toEqual(bad('binding digest mismatch'));
    expect(evaluateToolSchema({ ...cav(), tool: 'other' }, call())).toEqual(bad('binding digest mismatch'));
  });
  it('malformed call', () => {
    const m = bad('malformed call');
    expect(evaluateToolSchema(cav(), null as never)).toEqual(m);
    expect(evaluateToolSchema(cav(), [] as never)).toEqual(m);
    expect(evaluateToolSchema(cav(), call({ tool: 5 }))).toEqual(m);
    expect(evaluateToolSchema(cav(), call({ args: null }))).toEqual(m);
    expect(evaluateToolSchema(cav(), call({ args: [] }))).toEqual(m);
    expect(evaluateToolSchema(cav(), call({ args: 'x' }))).toEqual(m);
    class C {}
    expect(evaluateToolSchema(cav(), call({ args: Object.assign(new C(), { to: 'a' }) }))).toEqual(m);
  });
  it('tool name, signature and signed binding must match (in that order)', () => {
    expect(evaluateToolSchema(cav(), call({ tool: 'drop' }))).toEqual(bad('tool "drop" not authorized'));
    expect(evaluateToolSchema(cav(), call({ tool: 'x'.repeat(60) }))).toEqual(bad(`tool "${'x'.repeat(48)}…" not authorized`));
    expect(evaluateToolSchema(cav(), call({ tool: 'x'.repeat(48) }))).toEqual(bad(`tool "${'x'.repeat(48)}" not authorized`));
    expect(evaluateToolSchema(cav(), call({ tool: 'x'.repeat(49) }))).toEqual(bad(`tool "${'x'.repeat(48)}…" not authorized`));
    expect(evaluateToolSchema(cav(), call({ toolSignature: { name: 'send', params: { to: 'number' } } }))).toEqual(bad('tool signature differs from the authorized signature'));
    expect(evaluateToolSchema(cav(), call({ toolSignatureDigest: 'nope' }))).toEqual(bad('signed tool_binding differs from the authorized tool signature'));
    // signature checked before digest, tool name before both
    expect(evaluateToolSchema(cav(), call({ toolSignature: 'zzz', toolSignatureDigest: 'nope' }))).toEqual(bad('tool signature differs from the authorized signature'));
    expect(evaluateToolSchema(cav(), call({ tool: 'drop', toolSignature: 'zzz' }))).toEqual(bad('tool "drop" not authorized'));
  });
  it('is total: unexpected throws are fail-closed with a fixed reason', () => {
    expect(evaluateToolSchema(throwingGetter({ ...cav() }, 'schema') as never, call())).toEqual(bad('evaluation error (fail closed)'));
    expect(evaluateToolSchema(cav(), call({ toolSignature: { x: undefined } }))).toEqual(bad('evaluation error (fail closed)'));
    expect(evaluateToolSchema(cav(), throwingGetter({ tool: 'send', args: { to: 'a' } }, 'args') as never)).toEqual(bad('evaluation error (fail closed)'));
  });
  it('toolSchemaEvaluator: needs ctx.toolCall as an object and defers to evaluateToolSchema', () => {
    const c = cav();
    expect(toolSchemaEvaluator(c, { toolCall: call() })).toBe(true);
    expect(toolSchemaEvaluator(c, { toolCall: call({ args: { to: 5 } }) })).toBe(false);
    expect(toolSchemaEvaluator(c, null)).toBe(false);
    expect(toolSchemaEvaluator(c, undefined)).toBe(false);
    expect(toolSchemaEvaluator(c, {})).toBe(false);
    expect(toolSchemaEvaluator(c, { toolCall: 'x' })).toBe(false);
    expect(toolSchemaEvaluator(c, { toolCall: [] })).toBe(false);
  });
});

describe('evaluateToolSchema: argument checking', () => {
  const run = (props: Record<string, unknown>, args: Record<string, unknown>, required?: string[]) => {
    const c = toolSchemaCaveat('t', { props, ...(required ? { required } : {}) } as never);
    return evaluateToolSchema(c, { tool: 't', args });
  };
  const ok = { ok: true };
  const no = (reason: string) => ({ ok: false, reason });
  it('closed top level: unexpected arguments rejected, names quoted and truncated at 48', () => {
    expect(run({}, {})).toEqual(ok);
    expect(run({ a: { type: 'boolean' } }, { b: true })).toEqual(no('args: unexpected argument "b"'));
    expect(run({}, { ['k'.repeat(48)]: 1 })).toEqual(no(`args: unexpected argument "${'k'.repeat(48)}"`));
    expect(run({}, { ['k'.repeat(49)]: 1 })).toEqual(no(`args: unexpected argument "${'k'.repeat(48)}…"`));
    expect(run({ a: { type: 'boolean' } }, { a: true, __proto__x: 1 } as never)).toEqual(no('args: unexpected argument "__proto__x"'));
    expect(run({ a: { type: 'boolean' } }, JSON.parse('{"a":true,"toString":1}'))).toEqual(no('args: unexpected argument "toString"'));
  });
  it('required properties', () => {
    expect(run({ a: { type: 'boolean' } }, {}, ['a'])).toEqual(no("args: missing required argument 'a'"));
    expect(run({ a: { type: 'boolean' } }, { a: true }, ['a'])).toEqual(ok);
    expect(run({ a: { type: 'boolean' }, b: { type: 'boolean' } }, { a: true }, ['a', 'b'])).toEqual(no("args: missing required argument 'b'"));
    expect(run({ a: { type: 'boolean' } }, {})).toEqual(ok);
  });
  it('unexpected is reported before missing-required, missing before value errors', () => {
    expect(run({ a: { type: 'boolean' }, b: { type: 'boolean' } }, { zz: 1 }, ['a'])).toEqual(no('args: unexpected argument "zz"'));
    expect(run({ a: { type: 'boolean' }, b: { type: 'boolean' } }, { b: 5 }, ['a'])).toEqual(no("args: missing required argument 'a'"));
  });
  it('strings: type, length bounds (inclusive), prefix, const, enum', () => {
    expect(run({ s: { type: 'string' } }, { s: 5 })).toEqual(no('args.s: wrong type (expected string)'));
    expect(run({ s: { type: 'string' } }, { s: null })).toEqual(no('args.s: wrong type (expected string)'));
    expect(run({ s: { type: 'string' } }, { s: 'x'.repeat(DEFAULT_MAX_STRING_LEN) })).toEqual(ok);
    expect(run({ s: { type: 'string' } }, { s: 'x'.repeat(DEFAULT_MAX_STRING_LEN + 1) })).toEqual(no('args.s: exceeds maxLength'));
    expect(run({ s: { type: 'string', maxLength: 3 } }, { s: 'abc' })).toEqual(ok);
    expect(run({ s: { type: 'string', maxLength: 3 } }, { s: 'abcd' })).toEqual(no('args.s: exceeds maxLength'));
    expect(run({ s: { type: 'string', minLength: 3 } }, { s: 'abc' })).toEqual(ok);
    expect(run({ s: { type: 'string', minLength: 3 } }, { s: 'ab' })).toEqual(no('args.s: below minLength'));
    expect(run({ s: { type: 'string', minLength: 0 } }, { s: '' })).toEqual(ok);
    expect(run({ s: { type: 'string', prefix: 'ops@' } }, { s: 'ops@x' })).toEqual(ok);
    expect(run({ s: { type: 'string', prefix: 'ops@' } }, { s: 'ops' })).toEqual(no('args.s: violates prefix'));
    expect(run({ s: { type: 'string', prefix: 'ops@' } }, { s: 'xops@' })).toEqual(no('args.s: violates prefix'));
    expect(run({ s: { type: 'string', prefix: '' } }, { s: 'anything' })).toEqual(ok);
    expect(run({ s: { type: 'string', const: 'a' } }, { s: 'a' })).toEqual(ok);
    expect(run({ s: { type: 'string', const: 'a' } }, { s: 'b' })).toEqual(no('args.s: violates const'));
    expect(run({ s: { type: 'string', const: '' } }, { s: 'b' })).toEqual(no('args.s: violates const'));
    expect(run({ s: { type: 'string', enum: ['a', 'b'] } }, { s: 'b' })).toEqual(ok);
    expect(run({ s: { type: 'string', enum: ['a', 'b'] } }, { s: 'c' })).toEqual(no('args.s: violates enum'));
  });
  it('numbers and integers', () => {
    expect(run({ n: { type: 'number' } }, { n: 1.5 })).toEqual(ok);
    expect(run({ n: { type: 'number' } }, { n: '1' })).toEqual(no('args.n: wrong type (expected number)'));
    expect(run({ n: { type: 'number' } }, { n: NaN })).toEqual(no('args.n: wrong type (expected number)'));
    expect(run({ n: { type: 'number' } }, { n: Infinity })).toEqual(no('args.n: wrong type (expected number)'));
    expect(run({ n: { type: 'integer' } }, { n: 2 })).toEqual(ok);
    expect(run({ n: { type: 'integer' } }, { n: 1.5 })).toEqual(no('args.n: wrong type (expected integer)'));
    expect(run({ n: { type: 'integer' } }, { n: null })).toEqual(no('args.n: wrong type (expected integer)'));
    for (const type of ['number', 'integer']) {
      expect(run({ n: { type, min: 1, max: 3 } }, { n: 1 })).toEqual(ok);
      expect(run({ n: { type, min: 1, max: 3 } }, { n: 3 })).toEqual(ok);
      expect(run({ n: { type, min: 1, max: 3 } }, { n: 0 })).toEqual(no('args.n: below min'));
      expect(run({ n: { type, min: 1, max: 3 } }, { n: 4 })).toEqual(no('args.n: above max'));
      expect(run({ n: { type, min: 0 } }, { n: 0 })).toEqual(ok);
      expect(run({ n: { type, max: 0 } }, { n: 0 })).toEqual(ok);
      expect(run({ n: { type, const: 2 } }, { n: 3 })).toEqual(no('args.n: violates const'));
      expect(run({ n: { type, const: 0 } }, { n: 1 })).toEqual(no('args.n: violates const'));
      expect(run({ n: { type, enum: [1, 2] } }, { n: 2 })).toEqual(ok);
      expect(run({ n: { type, enum: [1, 2] } }, { n: 3 })).toEqual(no('args.n: violates enum'));
    }
    expect(run({ n: { type: 'number', min: -5, max: 5 } }, { n: -5 })).toEqual(ok);
  });
  it('booleans', () => {
    expect(run({ b: { type: 'boolean' } }, { b: false })).toEqual(ok);
    expect(run({ b: { type: 'boolean' } }, { b: 0 })).toEqual(no('args.b: wrong type (expected boolean)'));
    expect(run({ b: { type: 'boolean' } }, { b: 'true' })).toEqual(no('args.b: wrong type (expected boolean)'));
    expect(run({ b: { type: 'boolean', const: true } }, { b: false })).toEqual(no('args.b: violates const'));
    expect(run({ b: { type: 'boolean', const: false } }, { b: false })).toEqual(ok);
    expect(run({ b: { type: 'boolean', enum: [true] } }, { b: false })).toEqual(no('args.b: violates enum'));
    expect(run({ b: { type: 'boolean', enum: [true] } }, { b: true })).toEqual(ok);
  });
  it('null / undefined are never accepted', () => {
    for (const type of ['string', 'number', 'integer', 'boolean']) {
      expect(run({ x: { type } }, { x: null }).ok).toBe(false);
      expect(run({ x: { type } }, { x: undefined }).ok).toBe(false);
    }
    expect(run({ x: { type: 'object', props: {} } }, { x: null })).toEqual(no('args.x: expected object'));
    expect(run({ x: { type: 'array', items: { type: 'boolean' } } }, { x: null })).toEqual(no('args.x: expected array'));
  });
  it('objects: nested path, plain-object requirement, closedness, required', () => {
    const spec = { o: { type: 'object', props: { x: { type: 'boolean' }, y: { type: 'string' } }, required: ['x'] } };
    expect(run(spec, { o: { x: true } })).toEqual(ok);
    expect(run(spec, { o: [] })).toEqual(no('args.o: expected object'));
    expect(run(spec, { o: 'x' })).toEqual(no('args.o: expected object'));
    class C {}
    expect(run(spec, { o: Object.assign(new C(), { x: true }) })).toEqual(no('args.o: expected object'));
    expect(run(spec, { o: Object.assign(Object.create(null), { x: true }) })).toEqual(ok);
    expect(run(spec, { o: { x: true, z: 1 } })).toEqual(no('args.o: unexpected argument "z"'));
    expect(run(spec, { o: {} })).toEqual(no("args.o: missing required argument 'x'"));
    expect(run(spec, { o: { x: true, y: 1 } })).toEqual(no('args.o.y: wrong type (expected string)'));
  });
  it('arrays: type, length bounds, holes, per-element path', () => {
    const arr = (o: Record<string, unknown> = {}) => ({ a: { type: 'array', items: { type: 'string' }, ...o } });
    expect(run(arr(), { a: ['x', 'y'] })).toEqual(ok);
    expect(run(arr(), { a: 'x' })).toEqual(no('args.a: expected array'));
    expect(run(arr(), { a: {} })).toEqual(no('args.a: expected array'));
    expect(run(arr(), { a: Array.from({ length: DEFAULT_MAX_ARRAY_ITEMS }, () => 'x') })).toEqual(ok);
    expect(run(arr(), { a: Array.from({ length: DEFAULT_MAX_ARRAY_ITEMS + 1 }, () => 'x') })).toEqual(no('args.a: exceeds maxItems'));
    expect(run(arr({ maxItems: 2 }), { a: ['x', 'y'] })).toEqual(ok);
    expect(run(arr({ maxItems: 2 }), { a: ['x', 'y', 'z'] })).toEqual(no('args.a: exceeds maxItems'));
    expect(run(arr({ maxItems: 0 }), { a: [] })).toEqual(ok);
    expect(run(arr({ maxItems: ABSOLUTE_MAX_ARRAY_ITEMS }), { a: Array.from({ length: 300 }, () => 'x') })).toEqual(ok);
    expect(run(arr({ minItems: 2 }), { a: ['x', 'y'] })).toEqual(ok);
    expect(run(arr({ minItems: 2 }), { a: ['x'] })).toEqual(no('args.a: below minItems'));
    expect(run(arr({ minItems: 0 }), { a: [] })).toEqual(ok);
    expect(run(arr(), { a: ['x', 5] })).toEqual(no('args.a[1]: wrong type (expected string)'));
    expect(run(arr(), { a: [5] })).toEqual(no('args.a[0]: wrong type (expected string)'));
    // eslint-disable-next-line no-sparse-arrays
    expect(run(arr(), { a: ['x', , 'z'] })).toEqual(no('args.a[1]: hole in array'));
    expect(run({ a: { type: 'array', items: { type: 'array', items: { type: 'integer' } } } }, { a: [[1], [2, 'x']] })).toEqual(no('args.a[1][1]: wrong type (expected integer)'));
  });
  it('the deepest schema-legal value nesting is accepted', () => {
    // 6 nested object levels + a leaf: the leaf spec sits at the maximum schema depth (8)
    let spec: unknown = { type: 'object', props: { x: { type: 'boolean' } } };
    let val: unknown = { x: true };
    for (let i = 1; i < 6; i++) {
      spec = { type: 'object', props: { a: spec } };
      val = { a: val };
    }
    expect(run({ a: spec } as never, { a: val } as never)).toEqual(ok);
    // and the same for arrays
    let aspec: unknown = { type: 'boolean' };
    let aval: unknown = true;
    for (let i = 0; i < 6; i++) {
      aspec = { type: 'array', items: aspec };
      aval = [aval];
    }
    expect(run({ a: aspec } as never, { a: aval } as never)).toEqual(ok);
  });
  it('value-node budget: exactly 10000 nodes ok, 10001 refused', () => {
    const props = { a: { type: 'array', maxItems: 100, items: { type: 'array', maxItems: 100, items: { type: 'boolean' } } } };
    const mk = (outer: number, inner: number) => ({ a: Array.from({ length: outer }, () => Array.from({ length: inner }, () => true)) });
    expect(run(props, mk(99, 100))).toEqual(ok); // 1 + 99 + 9900 = 10000
    const r = run(props, mk(100, 99)); // 1 + 100 + 9900 = 10001
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/: too many values$/);
  });
});

// =============================================================================================
describe('agentNativeCaveatEvaluator', () => {
  const sig = { name: 't' };
  const tc = toolSchemaCaveat(sig, { props: { a: { type: 'boolean' } } });
  const action = { action: { verb: 'read', resource: '/docs/x' } };
  it('tool_schema caveats use ctx.toolCall', () => {
    expect(agentNativeCaveatEvaluator(tc, { toolCall: { tool: 't', args: { a: true } } })).toBe(true);
    expect(agentNativeCaveatEvaluator(tc, { toolCall: { tool: 't', args: { a: 1 } } })).toBe(false);
    expect(agentNativeCaveatEvaluator(tc, { now: 1 })).toBe(false);
  });
  it('predicates caveats need ctx.action and an allow array; any matching predicate suffices', () => {
    const p = (allow: unknown) => ({ type: 'predicates', allow }) as never;
    expect(agentNativeCaveatEvaluator(p([{ verb: 'read', resource: '/docs/*' }]), { action })).toBe(true);
    expect(agentNativeCaveatEvaluator(p([{ verb: 'write' }, { verb: 'read', resource: '/docs/*' }]), { action })).toBe(true);
    expect(agentNativeCaveatEvaluator(p([{ verb: 'write' }, { verb: 'read', resource: '/other/*' }]), { action })).toBe(false);
    expect(agentNativeCaveatEvaluator(p([]), { action })).toBe(false);
    expect(agentNativeCaveatEvaluator(p([{ verb: '*' }]), {})).toBe(false);
    expect(agentNativeCaveatEvaluator(p([{ verb: '*' }]), { action: [] })).toBe(false);
    expect(agentNativeCaveatEvaluator(p([{ verb: '*' }]), { action: 'x' })).toBe(false);
    expect(agentNativeCaveatEvaluator(p('nope'), { action })).toBe(false);
    expect(agentNativeCaveatEvaluator(p({ some: () => true }), { action })).toBe(false); // array-like impostor
    expect(agentNativeCaveatEvaluator(p([{ verb: '*' }]), { action: { some: true } })).toBe(false);
  });
  it('anything else defers to the stock envelope evaluator (fails closed on unknown types)', () => {
    expect(agentNativeCaveatEvaluator({ type: 'expires', at: 100 }, { now: 50 })).toBe(true);
    expect(agentNativeCaveatEvaluator({ type: 'expires', at: 100 }, { now: 150 })).toBe(false);
    expect(agentNativeCaveatEvaluator({ type: 'mystery' }, { now: 1 })).toBe(false);
  });
  it('is total and returns exactly false for non-objects / throwing accessors', () => {
    expect(agentNativeCaveatEvaluator(null as never, { now: 1 })).toBe(false);
    expect(agentNativeCaveatEvaluator([] as never, { now: 1 })).toBe(false);
    expect(agentNativeCaveatEvaluator({ type: 'expires', at: 100 }, null)).toBe(false);
    expect(agentNativeCaveatEvaluator({ type: 'expires', at: 100 }, 'x')).toBe(false);
    expect(agentNativeCaveatEvaluator({ type: 'expires', at: 100 }, [])).toBe(false);
    expect(agentNativeCaveatEvaluator({ type: 'predicates', allow: [{ verb: '*' }] }, throwingGetter({ now: 1 }, 'action'))).toBe(false);
    expect(agentNativeCaveatEvaluator({ type: 'predicates', allow: [{ verb: '*' }] }, throwingGetter({ now: 1 }, 'action', 'str'))).toBe(false);
  });
});
