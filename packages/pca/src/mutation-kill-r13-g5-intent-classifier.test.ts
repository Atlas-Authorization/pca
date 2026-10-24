/**
 * 0.4.2 r13 mutation kills (g5): intent-classifier.ts. Exact reasons for every verdict wire / classifier policy /
 * rule-18 refusal, inclusive bounds (32 labels, 8 committed digests, k = 1 and k = |keys|), non-string names that
 * stringify to valid ones, the pinned PQ key path (a hybrid verdict verifies only under its pq_keys pin), two-classifier
 * selection, the exact vote tally, and both catches (decideClassifierDimensions, verifyClassifierAttestation).
 */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { artifactSuiteError } from './intent-artifacts';
import {
  classifierCheckActive,
  classifierContentDigest,
  classifierVerdictRef,
  decideClassifierDimensions,
  INTENT_CLASSIFIER_REF_DOMAIN,
  signClassifierVerdict,
  validateClassifierPolicy,
  validateClassifierVerdictWire,
  verifyClassifierAttestation,
  type ClassifierPolicy,
  type ClassifierVerdict,
} from './intent-classifier';

const seed = (l: string) => sha256(utf8(`atlas-pca-test/r13-g5-cls/${l}`));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const J1 = key('j1');
const J2 = key('j2');
const J3 = key('j3');
const SESSION = b64u(seed('session'));
const MSG = 'we are sorry';
const verdict = (j: { sk: Uint8Array }, label = 'apologetic', over: Partial<ClassifierVerdict> = {}) =>
  signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: classifierContentDigest(MSG), label, measurement: 'm1', ...over } as never, j.sk);
const cls = (over: Record<string, unknown> = {}): ClassifierPolicy =>
  ({ id: 'tone', param: 'action.params.text', labels: ['neutral', 'apologetic', 'hostile'], keys: [J1.pk, J2.pk, J3.pk], k: 2, ...over }) as ClassifierPolicy;
const decide = (vs: unknown[], over: Record<string, unknown> = {}, classifiers: unknown[] = [cls()]) =>
  decideClassifierDimensions({ session: SESSION, action: { params: { text: MSG } }, committed: vs.map((v) => classifierVerdictRef(v as ClassifierVerdict)), verdicts: vs, policy: { classifiers }, ...over } as never);
const why = (r: ReturnType<typeof decideClassifierDimensions>) => (r.ok ? 'OK' : r.reason);
const wire = (over: Record<string, unknown> = {}) => ({ ...verdict(J1), ...over });

describe('validateClassifierVerdictWire: exact reasons', () => {
  it('well-formed', () => {
    expect(validateClassifierVerdictWire(verdict(J1))).toBeNull();
    expect(validateClassifierVerdictWire(wire({ label: 'x'.repeat(64), measurement: 'm'.repeat(256) }))).toBeNull();
  });
  it('each member', () => {
    expect(validateClassifierVerdictWire(null)).toBe('verdict must be an object');
    expect(validateClassifierVerdictWire([])).toBe('verdict must be an object');
    expect(validateClassifierVerdictWire(wire({ extra: 1 }))).toBe("unknown member 'verdict.extra'");
    const k = 'verdict must be {v: 1, kind: "pca-intent-classification"}';
    expect(validateClassifierVerdictWire(wire({ v: 2 }))).toBe(k);
    expect(validateClassifierVerdictWire(wire({ kind: 'pca-fact' }))).toBe(k);
    const c = "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$";
    expect(validateClassifierVerdictWire(wire({ classifier: ['tone'] }))).toBe(c);
    expect(validateClassifierVerdictWire(wire({ classifier: 'Tone' }))).toBe(c);
    expect(validateClassifierVerdictWire(wire({ session: 'x' }))).toBe("'verdict.session' must be canonical base64url (32 bytes)");
    expect(validateClassifierVerdictWire(wire({ content_digest: 'x' }))).toBe("'verdict.content_digest' must be canonical base64url (32 bytes)");
    expect(validateClassifierVerdictWire(wire({ label: '' }))).toBe("'verdict.label' must be a non-empty string (<= 64 bytes)");
    const m = "'verdict.measurement' must be a non-empty string (<= 256 bytes)";
    expect(validateClassifierVerdictWire(wire({ measurement: '' }))).toBe(m);
    expect(validateClassifierVerdictWire(wire({ measurement: 5 }))).toBe(m);
    expect(validateClassifierVerdictWire(wire({ judge: 'x' }))).toBe("'verdict.judge' must be canonical base64url (32 bytes)");
    expect(validateClassifierVerdictWire(wire({ sig: 1 }))).toBe("'verdict.sig' must be a string");
  });
  it('classifierVerdictRef is hashCanonical over {d, c}', () => {
    const v = verdict(J1);
    expect(classifierVerdictRef(v)).toBe(hashCanonical({ d: INTENT_CLASSIFIER_REF_DOMAIN, c: v }));
  });
});

describe('validateClassifierPolicy: exact reasons', () => {
  const p = (c: unknown[]) => validateClassifierPolicy({ classifiers: c } as never);
  it('container', () => {
    expect(validateClassifierPolicy({ classifiers: [] })).toBeNull();
    expect(validateClassifierPolicy(null as never)).toBe('classifier policy needs a classifiers list');
    expect(validateClassifierPolicy({ classifiers: 'x' } as never)).toBe('classifier policy needs a classifiers list');
    expect(validateClassifierPolicy({ classifiers: [], extra: 1 } as never)).toBe("unknown member 'policy.extra'");
    expect(validateClassifierPolicy({ classifiers: [], 'Stryker was here': 1 } as never)).toBe("unknown member 'policy.Stryker was here'");
  });
  it('classifier entry, id', () => {
    const ex = 'every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}';
    expect(p([cls()])).toBeNull();
    expect(p([null])).toBe(ex);
    expect(p([[]])).toBe(ex);
    expect(p([{ ...cls(), extra: 1 }])).toBe(ex);
    const { k: _k, ...noK } = cls();
    expect(p([noK])).toBe(ex);
    const id = 'every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$';
    expect(p([cls({ id: ['tone'] })])).toBe(id);
    expect(p([cls({ id: 'Tone' })])).toBe(id);
    expect(p([cls(), cls()])).toBe(id);
    expect(p([cls(), cls({ id: 'data' })])).toBeNull();
  });
  it('param, labels', () => {
    expect(p([cls({ param: 'text' })])).toBe("classifier 'tone': param must be an action.params path");
    const lm = "classifier 'tone': labels must hold 1..32 strings";
    expect(p([cls({ labels: [] })])).toBe(lm);
    expect(p([cls({ labels: 'abc' })])).toBe(lm);
    expect(p([cls({ labels: Array.from({ length: 33 }, (_, i) => `l${i}`) })])).toBe(lm);
    expect(p([cls({ labels: Array.from({ length: 32 }, (_, i) => `l${i}`) })])).toBeNull();
    const ld = "classifier 'tone': labels must be distinct non-empty strings";
    expect(p([cls({ labels: ['a', ''] })])).toBe(ld);
    expect(p([cls({ labels: ['a', 5] })])).toBe(ld);
    expect(p([cls({ labels: ['a', 'a'] })])).toBe(ld);
  });
  it('keys, k', () => {
    const km = "classifier 'tone': keys must be distinct 32-byte keys";
    expect(p([cls({ keys: [] })])).toBe(km);
    expect(p([cls({ keys: 'abc' })])).toBe(km);
    expect(p([cls({ keys: [J1.pk, 'short'], k: 1 })])).toBe(km);
    expect(p([cls({ keys: [J1.pk, J1.pk], k: 1 })])).toBe(km);
    const kk = (n: number) => `classifier 'tone': k must be an integer in [1, ${n}]`;
    expect(p([cls({ k: 0 })])).toBe(kk(3));
    expect(p([cls({ k: 1.5 })])).toBe(kk(3));
    expect(p([cls({ k: 4 })])).toBe(kk(3));
    expect(p([cls({ k: 1 })])).toBeNull();
    expect(p([cls({ k: 3 })])).toBeNull();
  });
  it('measurements', () => {
    const mm = "classifier 'tone': measurements must be a list of strings";
    expect(p([cls({ measurements: [] })])).toBeNull();
    expect(p([cls({ measurements: ['m1', 'm2'] })])).toBeNull();
    expect(p([cls({ measurements: 'm1' })])).toBe(mm);
    expect(p([cls({ measurements: [1] })])).toBe(mm);
    expect(p([cls({ measurements: ['m1', 1] })])).toBe(mm);
  });
  it('pq_keys', () => {
    const pm = "classifier 'tone': pq_keys must map allowlisted keys to PQ keys";
    expect(p([cls({ pq_keys: {} })])).toBeNull();
    expect(p([cls({ pq_keys: { [J1.pk]: 'PQ', [J2.pk]: 'PQ2' } })])).toBeNull();
    expect(p([cls({ pq_keys: [] })])).toBe(pm);
    expect(p([cls({ pq_keys: null })])).toBe(pm);
    expect(p([cls({ pq_keys: { [key('off').pk]: 'PQ' } })])).toBe(pm);
    expect(p([cls({ pq_keys: { [J1.pk]: 'PQ', [key('off').pk]: 'PQ' } })])).toBe(pm);
    expect(p([cls({ pq_keys: { [J1.pk]: 5 } })])).toBe(pm);
    expect(p([cls({ pq_keys: { [J1.pk]: '' } })])).toBe(pm);
  });
});

describe('classifierCheckActive', () => {
  it('strict', () => {
    expect(classifierCheckActive(null as never)).toBe(false);
    expect(classifierCheckActive({ committed: [], policy: { classifiers: [] } })).toBe(false);
    expect(classifierCheckActive({ committed: ['x'], policy: { classifiers: [] } })).toBe(true);
    expect(classifierCheckActive({ policy: { classifiers: [cls()] } })).toBe(true);
  });
});

describe('decideClassifierDimensions: exact reasons', () => {
  const two = () => [verdict(J1), verdict(J2)];
  it('success with the exact tally', () => {
    const r = decide([...two(), verdict(J3, 'neutral')]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect({ ...r.classes }).toEqual({ tone: 'apologetic' });
    expect(JSON.parse(JSON.stringify(r.votes))).toEqual({ tone: { apologetic: 2, neutral: 1 } });
  });
  it('absent committed / verdicts / params are empty', () => {
    const r = decideClassifierDimensions({ session: SESSION, action: {}, policy: { classifiers: [] } });
    expect(r.ok).toBe(true);
    expect(r.ok && JSON.parse(JSON.stringify(r))).toEqual({ ok: true, classes: {}, votes: {} });
    expect(decideClassifierDimensions({ session: SESSION, action: { params: {} }, committed: [], policy: { classifiers: [] } }).ok).toBe(true);
  });
  it('input, policy', () => {
    expect(why(decideClassifierDimensions(null as never))).toBe('classes: input must be an object');
    expect(why(decide(two(), { policy: { classifiers: [cls({ k: 0 })] } }))).toBe("classes: policy misconfigured (fail closed): classifier 'tone': k must be an integer in [1, 3]");
  });
  it('committed', () => {
    const cm = 'classes: committed verdicts must be a list of at most 8 digests';
    const ds = (n: number) => Array.from({ length: n }, (_, i) => b64u(seed(`d${i}`)));
    expect(why(decide([], { committed: ds(9) }))).toBe(cm);
    expect(why(decide([], { committed: 'abc' }))).toBe(cm);
    expect(why(decide([], { committed: ds(8) }))).toBe('classes: a committed verdict was not supplied (or is malformed)');
    const dm = 'classes: committed verdicts must be distinct canonical 32-byte digests';
    expect(why(decide([], { committed: ['x'] }))).toBe(dm);
    expect(why(decide([], { committed: [ds(1)[0], ds(1)[0]] }))).toBe(dm);
  });
  it('verdicts, action, params', () => {
    expect(why(decide([], { committed: [], verdicts: {} }))).toBe('classes: verdicts must be an array');
    expect(why(decide([], { action: null }))).toBe('classes: action must be an object');
    expect(why(decide([], { action: { params: null } }))).toBe('classes: action.params must be an object');
  });
  it('a malformed supplied verdict is skipped even when committed and otherwise valid', () => {
    const extra = signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: classifierContentDigest(MSG), label: 'apologetic', measurement: 'm1', extra: 1 } as never, J1.sk);
    expect(why(decide([extra, verdict(J2)]))).toBe('classes: a committed verdict was not supplied (or is malformed)');
  });
  it('per verdict: suite, classifier, allowlist, signature, session, content, label, measurement, pair', () => {
    const alg = { ...verdict(J1), alg: 'no-such-suite' };
    expect(why(decide([alg]))).toBe(`classes: verdict signature suite: ${artifactSuiteError(alg)}`);
    expect(why(decide([verdict(J1, 'a', { classifier: 'data' })]))).toBe("classes: verdict for undeclared classifier 'data'");
    expect(why(decide([verdict(key('off'))]))).toBe("classes: classifier 'tone': judge key is not on the allowlist");
    expect(why(decide([{ ...verdict(J1), label: 'hostile' }]))).toBe("classes: classifier 'tone': bad verdict signature");
    expect(why(decide([verdict(J1, 'apologetic', { session: b64u(seed('s2')) })]))).toBe("classes: classifier 'tone': verdict bound to another session");
    expect(why(decide(two(), { action: { params: {} } }))).toBe("classes: classifier 'tone': the action carries no 'action.params.text'");
    expect(why(decide(two(), { action: { params: { text: 'other' } } }))).toBe("classes: classifier 'tone': verdict is about other content");
    expect(why(decide([verdict(J1, 'weird'), verdict(J2, 'weird')]))).toBe("classes: classifier 'tone': label 'weird' is not in its label set");
    expect(why(decide(two(), {}, [cls({ measurements: ['m2'] })]))).toBe("classes: classifier 'tone': measurement is not pinned");
    expect(decide(two(), {}, [cls({ measurements: ['m2', 'm1'] })]).ok).toBe(true);
    expect(why(decide([verdict(J1), verdict(J1, 'neutral')]))).toBe("classes: classifier 'tone': two verdicts from one judge");
  });
  it('quorum: none, ambiguous', () => {
    expect(why(decide([verdict(J1)]))).toBe("classes: classifier 'tone': no label reaches the quorum 2");
    expect(why(decide([verdict(J1), verdict(J2, 'neutral')], {}, [cls({ k: 1 })]))).toBe("classes: classifier 'tone': ambiguous, 2 labels reach the quorum");
  });
  it('two classifiers: each verdict goes to its own classifier', () => {
    const data = cls({ id: 'data', labels: ['public', 'pii'], keys: [J3.pk], k: 1 });
    const vs = [verdict(J1), verdict(J2), verdict(J3, 'pii', { classifier: 'data' })];
    const r = decide(vs, {}, [cls(), data]);
    expect(r.ok && { ...r.classes }).toEqual({ tone: 'apologetic', data: 'pii' });
  });
  it('a hybrid verdict verifies only under its pinned PQ key', () => {
    const k = mlDsa65Keygen(seed('pq'));
    const pqpk = encodeMlDsaPublicKey(k.publicKey);
    const hv = signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: classifierContentDigest(MSG), label: 'apologetic', measurement: 'm1' }, J1.sk, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: k });
    const vs = [hv, verdict(J2)];
    expect(decide(vs, {}, [cls({ pq_keys: { [J1.pk]: pqpk } })])).toMatchObject({ ok: true, classes: { tone: 'apologetic' } });
    expect(why(decide(vs))).toBe("classes: classifier 'tone': bad verdict signature");
    expect(why(decide(vs, {}, [cls({ pq_keys: { [J2.pk]: pqpk } })]))).toBe("classes: classifier 'tone': bad verdict signature");
    // an ed25519 verdict next to an unrelated pin still verifies
    expect(decide(two(), {}, [cls({ pq_keys: { [J3.pk]: pqpk } })]).ok).toBe(true);
  });
  it('an internal throw is an evaluation error', () => {
    const i = { session: SESSION, action: { params: {} } } as Record<string, unknown>;
    Object.defineProperty(i, 'policy', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(why(decideClassifierDimensions(i as never))).toBe('classes: evaluation error (fail closed): boom');
  });
});

describe('verifyClassifierAttestation', () => {
  const v = verdict(J1);
  it('non-object verdict, missing / matching attestation', () => {
    expect(verifyClassifierAttestation(null as never, undefined)).toEqual({ ok: false, reason: 'verdict must be an object' });
    expect(verifyClassifierAttestation([] as never, undefined)).toEqual({ ok: false, reason: 'verdict must be an object' });
    expect(verifyClassifierAttestation(v, undefined)).toEqual({ ok: false, reason: 'no verified attestation for this judge (fail-closed)' });
    const measured = { runtime_measurement: 'm1' };
    expect(verifyClassifierAttestation(v, { ok: true, bound: true, measured } as never)).toEqual({ ok: true, measured });
  });
  it('a throw inside is an attestation check error (Error message, else unknown)', () => {
    const boom = {} as Record<string, unknown>;
    Object.defineProperty(boom, 'ok', { get: () => { throw new Error('boom'); } });
    expect(verifyClassifierAttestation(v, boom as never)).toEqual({ ok: false, reason: 'attestation check error (fail closed): boom' });
    const raw = {} as Record<string, unknown>;
    Object.defineProperty(raw, 'ok', { get: () => { throw 'raw'; } });
    expect(verifyClassifierAttestation(v, raw as never)).toEqual({ ok: false, reason: 'attestation check error (fail closed): unknown' });
  });
});
