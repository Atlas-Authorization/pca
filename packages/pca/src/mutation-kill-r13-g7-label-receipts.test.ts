/**
 * r13 mutation kills for label-receipts.ts: exact outcomes of isLabelKey, validateLabelsWire (every refusal message and
 * every boundary), verifyLabels (key lookup, suite and signature refusals), flowRuleFor / flowAllowed /
 * validateFlowRules and decideReadPurpose (malformed inputs, coverage patterns, minimisation and ordering).
 */
import { describe, expect, it } from 'vitest';
import { b64u, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  decideReadPurpose,
  flowAllowed,
  flowRuleFor,
  isLabelKey,
  LABELS_DOMAIN,
  LABELS_REF_DOMAIN,
  labelsRef,
  MAX_LABEL_FIELDS,
  PUBLIC_CLASS,
  signLabels,
  validateFlowRules,
  validateLabelsWire,
  verifyLabels,
  type PcaLabels,
} from './label-receipts';
import { artifactRef } from './intent-artifacts';

/** Run f, capturing its value or its error (name + message), so a mutant that throws fails an assertion, not an error. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
/** Async form of settle. */
const settleAsync = async <T>(f: () => Promise<T>) => {
  try {
    return { ok: true as const, value: await f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

const seed = (l: string) => sha256(utf8(`atlas-pca-test/r13-g7-labels/${l}`));
const SK = seed('site');
const PK = b64u(publicKeyOf(SK));
const OTHER_PK = b64u(publicKeyOf(seed('other')));
const D = (l: string) => b64u(seed(l));
const SITE = 'shop.example';

const body = (over: Record<string, unknown> = {}) => ({
  site: SITE,
  session: D('session'),
  response_digest: D('resp'),
  fields: { 'a.b': { class: 'pii.contact', value_digest: D('v') } },
  issued_at: 5,
  kid: 'k1',
  ...over,
});
const signed = (over: Record<string, unknown> = {}) => signLabels(body(over) as never, SK);
const wire = (over: Record<string, unknown> = {}) => ({ v: 1, kind: 'pca-labels', ...body(), sig: 'x', ...over });
const KEYS = [{ site: SITE, kid: 'k1', pk: PK }];

describe('constants', () => {
  it('pins the domains and limits', () => {
    expect(LABELS_DOMAIN).toBe('atlas-pca/labels/v1\0');
    expect(LABELS_REF_DOMAIN).toBe('atlas-pca/labels-ref/v1');
    expect(MAX_LABEL_FIELDS).toBe(64);
    expect(PUBLIC_CLASS).toBe('public');
  });
  it('labelsRef is the artifact ref under the labels-ref domain, slot l', () => {
    const l = signed();
    expect(settle(() => labelsRef(l))).toEqual({ ok: true, value: artifactRef('atlas-pca/labels-ref/v1', 'l', l) });
  });
});

describe('isLabelKey', () => {
  it('accepts a well-formed key, with or without a pq_pk', () => {
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k1', pk: PK }))).toEqual({ ok: true, value: true });
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k1', pk: PK, pq_pk: 'x' }))).toEqual({ ok: true, value: true });
  });
  it('refuses every malformed key', () => {
    expect(settle(() => isLabelKey(null))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey([]))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k1', pk: PK, extra: 1 }))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k1' }))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey({ site: '', kid: 'k1', pk: PK }))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey({ site: 'a'.repeat(257), kid: 'k1', pk: PK }))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey({ site: 'a'.repeat(256), kid: 'k1', pk: PK }))).toEqual({ ok: true, value: true });
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k'.repeat(65), pk: PK }))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k'.repeat(64), pk: PK }))).toEqual({ ok: true, value: true });
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k1', pk: 'nope' }))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k1', pk: PK, pq_pk: '' }))).toEqual({ ok: true, value: false });
    expect(settle(() => isLabelKey({ site: SITE, kid: 'k1', pk: PK, pq_pk: null }))).toEqual({ ok: true, value: false });
  });
});

describe('validateLabelsWire', () => {
  it('accepts a well-formed receipt (signed or not yet verified)', () => {
    expect(settle(() => validateLabelsWire(wire()))).toEqual({ ok: true, value: null });
    expect(settle(() => validateLabelsWire(signed()))).toEqual({ ok: true, value: null });
    expect(settle(() => validateLabelsWire(wire({ alg: 'ed25519' })))).toEqual({ ok: true, value: null });
    expect(settle(() => validateLabelsWire(wire({ issued_at: 0 })))).toEqual({ ok: true, value: null });
  });
  it('refuses with the exact reason', () => {
    expect(settle(() => validateLabelsWire(null))).toEqual({ ok: true, value: 'label receipt must be an object' });
    expect(settle(() => validateLabelsWire([]))).toEqual({ ok: true, value: 'label receipt must be an object' });
    expect(settle(() => validateLabelsWire(wire({ extra: 1 })))).toEqual({ ok: true, value: "unknown member 'labels.extra'" });
    const { kid: _k, ...noKid } = wire();
    expect(settle(() => validateLabelsWire(noKid))).toEqual({ ok: true, value: "missing member 'labels.kid'" });
    const VK = 'label receipt must be {v: 1, kind: "pca-labels"}';
    expect(settle(() => validateLabelsWire(wire({ v: 2 })))).toEqual({ ok: true, value: VK });
    expect(settle(() => validateLabelsWire(wire({ kind: 'pca-label' })))).toEqual({ ok: true, value: VK });
    expect(settle(() => validateLabelsWire(wire({ v: 2, kind: 'x' })))).toEqual({ ok: true, value: VK });
    expect(settle(() => validateLabelsWire(wire({ site: '' })))).toEqual({ ok: true, value: "'labels.site' must be a non-empty string (<= 256 bytes)" });
    expect(settle(() => validateLabelsWire(wire({ site: 'a'.repeat(257) })))).toEqual({ ok: true, value: "'labels.site' must be a non-empty string (<= 256 bytes)" });
    expect(settle(() => validateLabelsWire(wire({ session: 'x' })))).toEqual({ ok: true, value: "'labels.session' must be canonical base64url (32 bytes)" });
    expect(settle(() => validateLabelsWire(wire({ response_digest: 'x' })))).toEqual({ ok: true, value: "'labels.response_digest' must be canonical base64url (32 bytes)" });
    expect(settle(() => validateLabelsWire(wire({ fields: [] })))).toEqual({ ok: true, value: "'labels.fields' must be an object" });
    expect(settle(() => validateLabelsWire(wire({ fields: {} })))).toEqual({ ok: true, value: "'labels.fields' must hold 1..64 fields" });
  });
  it('enforces 1..64 fields exactly', () => {
    const many = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, { class: 'public', value_digest: D('v') }]));
    expect(settle(() => validateLabelsWire(wire({ fields: many(1) })))).toEqual({ ok: true, value: null });
    expect(settle(() => validateLabelsWire(wire({ fields: many(64) })))).toEqual({ ok: true, value: null });
    expect(settle(() => validateLabelsWire(wire({ fields: many(65) })))).toEqual({ ok: true, value: "'labels.fields' must hold 1..64 fields" });
  });
  it('checks every field (not only the first)', () => {
    const ok = { class: 'public', value_digest: D('v') };
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, '': ok } })))).toEqual({ ok: true, value: 'label field paths must be non-empty strings (<= 256 bytes)' });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, ['p'.repeat(257)]: ok } })))).toEqual({ ok: true, value: 'label field paths must be non-empty strings (<= 256 bytes)' });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, ['p'.repeat(256)]: ok } })))).toEqual({ ok: true, value: null });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: null } })))).toEqual({ ok: true, value: "label field 'b' must be exactly {class, value_digest}" });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: { ...ok, x: 1 } } })))).toEqual({ ok: true, value: "label field 'b' must be exactly {class, value_digest}" });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: { class: 'public' } } })))).toEqual({ ok: true, value: "label field 'b' must be exactly {class, value_digest}" });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: { class: 7, value_digest: D('v') } } })))).toEqual({ ok: true, value: "label field 'b': invalid data class" });
    // an array whose string form is a valid class is still not a string
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: { class: ['public'], value_digest: D('v') } } })))).toEqual({ ok: true, value: "label field 'b': invalid data class" });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: { class: 'a'.repeat(129), value_digest: D('v') } } })))).toEqual({ ok: true, value: "label field 'b': invalid data class" });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: { class: 'a'.repeat(128), value_digest: D('v') } } })))).toEqual({ ok: true, value: null });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: { class: 'Bad', value_digest: D('v') } } })))).toEqual({ ok: true, value: "label field 'b': invalid data class" });
    expect(settle(() => validateLabelsWire(wire({ fields: { a: ok, b: { class: 'public', value_digest: 'x' } } })))).toEqual({ ok: true, value: "label field 'b': value_digest must be canonical base64url (32 bytes)" });
  });
  it('checks issued_at, kid and sig', () => {
    const IA = "'labels.issued_at' must be a non-negative safe integer";
    expect(settle(() => validateLabelsWire(wire({ issued_at: -1 })))).toEqual({ ok: true, value: IA });
    expect(settle(() => validateLabelsWire(wire({ issued_at: 1.5 })))).toEqual({ ok: true, value: IA });
    expect(settle(() => validateLabelsWire(wire({ issued_at: '1' })))).toEqual({ ok: true, value: IA });
    const KID = "'labels.kid' must be a non-empty string (<= 64 bytes)";
    expect(settle(() => validateLabelsWire(wire({ kid: '' })))).toEqual({ ok: true, value: KID });
    expect(settle(() => validateLabelsWire(wire({ kid: 'k'.repeat(65) })))).toEqual({ ok: true, value: KID });
    expect(settle(() => validateLabelsWire(wire({ kid: 'k'.repeat(64) })))).toEqual({ ok: true, value: null });
    expect(settle(() => validateLabelsWire(wire({ sig: 7 })))).toEqual({ ok: true, value: "'labels.sig' must be a string" });
  });
});

describe('verifyLabels', () => {
  it('verifies a signed receipt under the pinned key', () => {
    const l = signed();
    expect(l.v).toBe(1);
    expect(l.kind).toBe('pca-labels');
    expect(settle(() => verifyLabels(l, KEYS))).toEqual({ ok: true, value: null });
    // a non-object entry ahead of the real key is skipped, never dereferenced
    expect(settle(() => verifyLabels(l, [null as never, 7 as never, ...KEYS]))).toEqual({ ok: true, value: null });
  });
  it('returns the wire reason first', () => {
    expect(settle(() => verifyLabels({ ...signed(), v: 2 }, KEYS))).toEqual({ ok: true, value: 'label receipt must be {v: 1, kind: "pca-labels"}' });
  });
  it('refuses non-array keys', () => {
    expect(settle(() => verifyLabels(signed(), null as never))).toEqual({ ok: true, value: 'label keys must be an array' });
    expect(settle(() => verifyLabels(signed(), {} as never))).toEqual({ ok: true, value: 'label keys must be an array' });
  });
  it('refuses a malformed suite', () => {
    expect(settle(() => verifyLabels({ ...signed(), pq_sig: 'x' }, KEYS))).toEqual({ ok: true, value: 'signature suite: an ed25519 artifact must not carry pq_pk / pq_sig' });
  });
  it('refuses an unpinned site or kid', () => {
    expect(settle(() => verifyLabels(signed(), [{ site: 'other', kid: 'k1', pk: PK }]))).toEqual({ ok: true, value: `no pinned label key for site '${SITE}' kid 'k1'` });
    expect(settle(() => verifyLabels(signed(), [{ site: SITE, kid: 'k2', pk: PK }]))).toEqual({ ok: true, value: `no pinned label key for site '${SITE}' kid 'k1'` });
    expect(settle(() => verifyLabels(signed(), []))).toEqual({ ok: true, value: `no pinned label key for site '${SITE}' kid 'k1'` });
  });
  it('refuses a bad signature or a wrong pinned key', () => {
    expect(settle(() => verifyLabels(signed(), [{ site: SITE, kid: 'k1', pk: OTHER_PK }]))).toEqual({ ok: true, value: 'bad label receipt signature' });
    const l = signed() as PcaLabels;
    expect(settle(() => verifyLabels({ ...l, issued_at: 6 }, KEYS))).toEqual({ ok: true, value: 'bad label receipt signature' });
    // the first matching key decides
    expect(settle(() => verifyLabels(l, [{ site: SITE, kid: 'k1', pk: OTHER_PK }, ...KEYS]))).toEqual({ ok: true, value: 'bad label receipt signature' });
  });
});

describe('flowRuleFor', () => {
  const rules = { 'pii.contact': ['a'], 'pii.*': ['b'], 'pii.contact.*': ['c'], '*': ['d'] };
  it('exact beats prefix beats *', () => {
    expect(settle(() => flowRuleFor(rules, 'pii.contact'))).toEqual({ ok: true, value: 'pii.contact' });
    expect(settle(() => flowRuleFor(rules, 'pii.contact.email'))).toEqual({ ok: true, value: 'pii.contact.*' });
    expect(settle(() => flowRuleFor({ 'pii.contact.*': ['c'], 'pii.*': ['b'] }, 'pii.contact.email'))).toEqual({ ok: true, value: 'pii.contact.*' });
    expect(settle(() => flowRuleFor({ 'pii.*': ['b'], 'pii.contact.*': ['c'] }, 'pii.contact.email'))).toEqual({ ok: true, value: 'pii.contact.*' });
    expect(settle(() => flowRuleFor(rules, 'pii.ssn'))).toEqual({ ok: true, value: 'pii.*' });
    expect(settle(() => flowRuleFor(rules, 'piix'))).toEqual({ ok: true, value: '*' });
    expect(settle(() => flowRuleFor({ 'pii.*': ['b'] }, 'piix'))).toEqual({ ok: true, value: undefined });
    expect(settle(() => flowRuleFor({ 'pii.*': ['b'] }, 'pii'))).toEqual({ ok: true, value: undefined });
    expect(settle(() => flowRuleFor({ 'pii.*': ['b'], 'pii.contact': ['a'] }, 'pii.x'))).toEqual({ ok: true, value: 'pii.*' });
    expect(settle(() => flowRuleFor({ pii: ['b'] }, 'pii.x'))).toEqual({ ok: true, value: undefined });
    expect(settle(() => flowRuleFor({}, 'x'))).toEqual({ ok: true, value: undefined });
  });
  it('is undefined on malformed input', () => {
    expect(settle(() => flowRuleFor(null as never, 'x'))).toEqual({ ok: true, value: undefined });
    expect(settle(() => flowRuleFor({ '*': ['d'] }, 7 as never))).toEqual({ ok: true, value: undefined });
  });
  it('uses own members only', () => {
    expect(settle(() => flowRuleFor({}, 'toString'))).toEqual({ ok: true, value: undefined });
    expect(settle(() => flowRuleFor({}, '*'))).toEqual({ ok: true, value: undefined });
  });
});

describe('flowAllowed', () => {
  const rules = { 'pii.*': ['crm'], secret: [] as string[], weird: 'crm' as unknown as string[] };
  it('origin and public always flow', () => {
    expect(settle(() => flowAllowed({}, 'secret', 'site', 'site'))).toEqual({ ok: true, value: true });
    expect(settle(() => flowAllowed({}, 'public', 'site', 'other'))).toEqual({ ok: true, value: true });
  });
  it('the most specific rule must list the sink', () => {
    expect(settle(() => flowAllowed(rules, 'pii.x', 'site', 'crm'))).toEqual({ ok: true, value: true });
    expect(settle(() => flowAllowed(rules, 'pii.x', 'site', 'ads'))).toEqual({ ok: true, value: false });
    expect(settle(() => flowAllowed(rules, 'secret', 'site', 'crm'))).toEqual({ ok: true, value: false });
    expect(settle(() => flowAllowed(rules, 'other', 'site', 'crm'))).toEqual({ ok: true, value: false });
    expect(settle(() => flowAllowed(rules, 'weird', 'site', 'crm'))).toEqual({ ok: true, value: false });
    // no matching rule is a deny even when a member is literally named 'undefined'
    expect(settle(() => flowAllowed({ undefined: ['crm'] }, 'x', 'site', 'crm'))).toEqual({ ok: true, value: false });
  });
  it('is false on non-string arguments', () => {
    expect(settle(() => flowAllowed(rules, 7 as never, 'site', 'site'))).toEqual({ ok: true, value: false });
    expect(settle(() => flowAllowed(rules, 'public', 7 as never, 'x'))).toEqual({ ok: true, value: false });
    expect(settle(() => flowAllowed(rules, 'public', 'x', 7 as never))).toEqual({ ok: true, value: false });
  });
});

describe('validateFlowRules', () => {
  it('accepts classes, prefixes and *', () => {
    expect(settle(() => validateFlowRules({ 'pii.contact': ['a'], 'pii.*': ['b'], '*': [] }))).toEqual({ ok: true, value: null });
    expect(settle(() => validateFlowRules({}))).toEqual({ ok: true, value: null });
  });
  it('refuses with the exact reason', () => {
    expect(settle(() => validateFlowRules(null))).toEqual({ ok: true, value: 'flows must be an object' });
    expect(settle(() => validateFlowRules([]))).toEqual({ ok: true, value: 'flows must be an object' });
    expect(settle(() => validateFlowRules({ Bad: [] }))).toEqual({ ok: true, value: "flow pattern 'Bad' is not a class, a 'prefix.*' or '*'" });
    expect(settle(() => validateFlowRules({ '.*': [] }))).toEqual({ ok: true, value: "flow pattern '.*' is not a class, a 'prefix.*' or '*'" });
    expect(settle(() => validateFlowRules({ 'a*': [] }))).toEqual({ ok: true, value: "flow pattern 'a*' is not a class, a 'prefix.*' or '*'" });
    expect(settle(() => validateFlowRules({ '**': [] }))).toEqual({ ok: true, value: "flow pattern '**' is not a class, a 'prefix.*' or '*'" });
    expect(settle(() => validateFlowRules({ ok: [], 'a.*': 'x' }))).toEqual({ ok: true, value: "flow pattern 'a.*' needs a list of audiences" });
    expect(settle(() => validateFlowRules({ a: ['x', ''] }))).toEqual({ ok: true, value: "flow pattern 'a' needs a list of audiences" });
    expect(settle(() => validateFlowRules({ a: ['x', 'y'.repeat(257)] }))).toEqual({ ok: true, value: "flow pattern 'a' needs a list of audiences" });
    expect(settle(() => validateFlowRules({ a: ['y'.repeat(256)] }))).toEqual({ ok: true, value: null });
  });
});

describe('decideReadPurpose', () => {
  const MAL = { outcome: 'deny', minimise: [], uncovered: [] };
  const cov = { booking: ['pii.*', 'payment.card'], support: ['*'], none: [] as string[] };
  it('allows when every class is covered', () => {
    const fields = [{ path: 'a', class: 'pii.contact' }, { path: 'b', class: 'payment.card' }, { path: 'c', class: 'public' }];
    expect(settle(() => decideReadPurpose(fields, 'booking', cov))).toEqual({ ok: true, value: { outcome: 'allow', minimise: [], uncovered: [] } });
    expect(settle(() => decideReadPurpose([{ path: 'x', class: 'anything' }], 'support', cov))).toEqual({ ok: true, value: { outcome: 'allow', minimise: [], uncovered: [] } });
    expect(settle(() => decideReadPurpose([], 'nope', cov))).toEqual({ ok: true, value: { outcome: 'allow', minimise: [], uncovered: [] } });
  });
  it('minimises optional and questions or denies required uncovered fields', () => {
    const fields = [
      { path: 'z', class: 'health', optional: true },
      { path: 'y', class: 'pii.contact' },
      { path: 'é', class: 'health' },
      { path: '\u{1F600}', class: 'health' },
      { path: '～', class: 'health' },
      { path: 'b', class: 'payment.cardx' },
      { path: 'b', class: 'payment.cardx' },
      { path: 'm', class: 'piix', optional: false },
      { path: 'o', class: 'pii', optional: true },
    ];
    const out = decideReadPurpose(fields, 'booking', cov);
    expect(out).toEqual({ outcome: 'question', minimise: ['o', 'z'], uncovered: ['b', 'm', 'é', '～', '\u{1F600}'] });
    expect(settle(() => decideReadPurpose(fields, 'booking', cov, 'deny').outcome)).toEqual({ ok: true, value: 'deny' });
    expect(settle(() => decideReadPurpose(fields, 'booking', cov, 'question').outcome)).toEqual({ ok: true, value: 'question' });
  });
  it('an unknown or inherited purpose covers only public', () => {
    const fields = [{ path: 'a', class: 'public' }, { path: 'b', class: 'x' }];
    expect(settle(() => decideReadPurpose(fields, 'unknown', cov))).toEqual({ ok: true, value: { outcome: 'question', minimise: [], uncovered: ['b'] } });
    expect(settle(() => decideReadPurpose(fields, 'toString', cov))).toEqual({ ok: true, value: { outcome: 'question', minimise: [], uncovered: ['b'] } });
    expect(settle(() => decideReadPurpose(fields, 'none', cov))).toEqual({ ok: true, value: { outcome: 'question', minimise: [], uncovered: ['b'] } });
    expect(settle(() => decideReadPurpose([{ path: 'c', class: 'Stryker was here' }], 'unknown', cov))).toEqual({ ok: true, value: { outcome: 'question', minimise: [], uncovered: ['c'] } });
  });
  it('a prefix pattern matches only past its dot', () => {
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'pii.x' }], 'p', { p: ['pii.*'] }).outcome)).toEqual({ ok: true, value: 'allow' });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'piix' }], 'p', { p: ['pii.*'] }).outcome)).toEqual({ ok: true, value: 'question' });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'piix' }], 'p', { p: ['pii.'] }).outcome)).toEqual({ ok: true, value: 'question' });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'pii.x' }], 'p', { p: ['pii'] }).outcome)).toEqual({ ok: true, value: 'question' });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'x.*' }], 'p', { p: ['x.*'] }).outcome)).toEqual({ ok: true, value: 'allow' });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: '' }], 'p', { p: ['.*'] }).outcome)).toEqual({ ok: true, value: 'question' });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: '*' }], 'p', { p: [] }).outcome)).toEqual({ ok: true, value: 'question' });
  });
  it('refuses malformed input as deny with empty lists', () => {
    const f = [{ path: 'a', class: 'x' }];
    expect(settle(() => decideReadPurpose(null as never, 'p', cov))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose(f, 7 as never, cov))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose(f, 'p', null as never))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose(f, 'p', [] as never))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose(f, 'p', cov, 'maybe' as never))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose(f, 'p', { q: 'x' } as never))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose(f, 'p', { q: ['a', 7] } as never))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose([null] as never, 'p', cov))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose([{ class: 'x' }] as never, 'p', cov))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose([{ path: 'a' }] as never, 'p', cov))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'x', optional: 'yes' }] as never, 'p', cov))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'x', optional: null }] as never, 'p', cov))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'public' }, { path: 'b', class: 7 }] as never, 'p', cov))).toEqual({ ok: true, value: MAL });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'public' }], 'p', { a: [], b: ['x', 7] } as never))).toEqual({ ok: true, value: MAL });
  });
  it('accepts the deny and question policies explicitly and defaults to question', () => {
    const f = [{ path: 'a', class: 'x' }];
    expect(settle(() => decideReadPurpose(f, 'p', {}))).toEqual({ ok: true, value: { outcome: 'question', minimise: [], uncovered: ['a'] } });
    expect(settle(() => decideReadPurpose(f, 'p', {}, 'deny'))).toEqual({ ok: true, value: { outcome: 'deny', minimise: [], uncovered: ['a'] } });
    expect(settle(() => decideReadPurpose([{ path: 'a', class: 'x', optional: true }], 'p', {}, 'deny'))).toEqual({ ok: true, value: { outcome: 'allow', minimise: ['a'], uncovered: [] } });
  });
});
