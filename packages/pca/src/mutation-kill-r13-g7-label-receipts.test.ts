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
    expect(labelsRef(l)).toBe(artifactRef('atlas-pca/labels-ref/v1', 'l', l));
  });
});

describe('isLabelKey', () => {
  it('accepts a well-formed key, with or without a pq_pk', () => {
    expect(isLabelKey({ site: SITE, kid: 'k1', pk: PK })).toBe(true);
    expect(isLabelKey({ site: SITE, kid: 'k1', pk: PK, pq_pk: 'x' })).toBe(true);
  });
  it('refuses every malformed key', () => {
    expect(isLabelKey(null)).toBe(false);
    expect(isLabelKey([])).toBe(false);
    expect(isLabelKey({ site: SITE, kid: 'k1', pk: PK, extra: 1 })).toBe(false);
    expect(isLabelKey({ site: SITE, kid: 'k1' })).toBe(false);
    expect(isLabelKey({ site: '', kid: 'k1', pk: PK })).toBe(false);
    expect(isLabelKey({ site: 'a'.repeat(257), kid: 'k1', pk: PK })).toBe(false);
    expect(isLabelKey({ site: 'a'.repeat(256), kid: 'k1', pk: PK })).toBe(true);
    expect(isLabelKey({ site: SITE, kid: 'k'.repeat(65), pk: PK })).toBe(false);
    expect(isLabelKey({ site: SITE, kid: 'k'.repeat(64), pk: PK })).toBe(true);
    expect(isLabelKey({ site: SITE, kid: 'k1', pk: 'nope' })).toBe(false);
    expect(isLabelKey({ site: SITE, kid: 'k1', pk: PK, pq_pk: '' })).toBe(false);
    expect(isLabelKey({ site: SITE, kid: 'k1', pk: PK, pq_pk: null })).toBe(false);
  });
});

describe('validateLabelsWire', () => {
  it('accepts a well-formed receipt (signed or not yet verified)', () => {
    expect(validateLabelsWire(wire())).toBeNull();
    expect(validateLabelsWire(signed())).toBeNull();
    expect(validateLabelsWire(wire({ alg: 'ed25519' }))).toBeNull();
    expect(validateLabelsWire(wire({ issued_at: 0 }))).toBeNull();
  });
  it('refuses with the exact reason', () => {
    expect(validateLabelsWire(null)).toBe('label receipt must be an object');
    expect(validateLabelsWire([])).toBe('label receipt must be an object');
    expect(validateLabelsWire(wire({ extra: 1 }))).toBe("unknown member 'labels.extra'");
    const { kid: _k, ...noKid } = wire();
    expect(validateLabelsWire(noKid)).toBe("missing member 'labels.kid'");
    const VK = 'label receipt must be {v: 1, kind: "pca-labels"}';
    expect(validateLabelsWire(wire({ v: 2 }))).toBe(VK);
    expect(validateLabelsWire(wire({ kind: 'pca-label' }))).toBe(VK);
    expect(validateLabelsWire(wire({ v: 2, kind: 'x' }))).toBe(VK);
    expect(validateLabelsWire(wire({ site: '' }))).toBe("'labels.site' must be a non-empty string (<= 256 bytes)");
    expect(validateLabelsWire(wire({ site: 'a'.repeat(257) }))).toBe("'labels.site' must be a non-empty string (<= 256 bytes)");
    expect(validateLabelsWire(wire({ session: 'x' }))).toBe("'labels.session' must be canonical base64url (32 bytes)");
    expect(validateLabelsWire(wire({ response_digest: 'x' }))).toBe("'labels.response_digest' must be canonical base64url (32 bytes)");
    expect(validateLabelsWire(wire({ fields: [] }))).toBe("'labels.fields' must be an object");
    expect(validateLabelsWire(wire({ fields: {} }))).toBe("'labels.fields' must hold 1..64 fields");
  });
  it('enforces 1..64 fields exactly', () => {
    const many = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, { class: 'public', value_digest: D('v') }]));
    expect(validateLabelsWire(wire({ fields: many(1) }))).toBeNull();
    expect(validateLabelsWire(wire({ fields: many(64) }))).toBeNull();
    expect(validateLabelsWire(wire({ fields: many(65) }))).toBe("'labels.fields' must hold 1..64 fields");
  });
  it('checks every field (not only the first)', () => {
    const ok = { class: 'public', value_digest: D('v') };
    expect(validateLabelsWire(wire({ fields: { a: ok, '': ok } }))).toBe('label field paths must be non-empty strings (<= 256 bytes)');
    expect(validateLabelsWire(wire({ fields: { a: ok, ['p'.repeat(257)]: ok } }))).toBe('label field paths must be non-empty strings (<= 256 bytes)');
    expect(validateLabelsWire(wire({ fields: { a: ok, ['p'.repeat(256)]: ok } }))).toBeNull();
    expect(validateLabelsWire(wire({ fields: { a: ok, b: null } }))).toBe("label field 'b' must be exactly {class, value_digest}");
    expect(validateLabelsWire(wire({ fields: { a: ok, b: { ...ok, x: 1 } } }))).toBe("label field 'b' must be exactly {class, value_digest}");
    expect(validateLabelsWire(wire({ fields: { a: ok, b: { class: 'public' } } }))).toBe("label field 'b' must be exactly {class, value_digest}");
    expect(validateLabelsWire(wire({ fields: { a: ok, b: { class: 7, value_digest: D('v') } } }))).toBe("label field 'b': invalid data class");
    // an array whose string form is a valid class is still not a string
    expect(validateLabelsWire(wire({ fields: { a: ok, b: { class: ['public'], value_digest: D('v') } } }))).toBe("label field 'b': invalid data class");
    expect(validateLabelsWire(wire({ fields: { a: ok, b: { class: 'a'.repeat(129), value_digest: D('v') } } }))).toBe("label field 'b': invalid data class");
    expect(validateLabelsWire(wire({ fields: { a: ok, b: { class: 'a'.repeat(128), value_digest: D('v') } } }))).toBeNull();
    expect(validateLabelsWire(wire({ fields: { a: ok, b: { class: 'Bad', value_digest: D('v') } } }))).toBe("label field 'b': invalid data class");
    expect(validateLabelsWire(wire({ fields: { a: ok, b: { class: 'public', value_digest: 'x' } } }))).toBe("label field 'b': value_digest must be canonical base64url (32 bytes)");
  });
  it('checks issued_at, kid and sig', () => {
    const IA = "'labels.issued_at' must be a non-negative safe integer";
    expect(validateLabelsWire(wire({ issued_at: -1 }))).toBe(IA);
    expect(validateLabelsWire(wire({ issued_at: 1.5 }))).toBe(IA);
    expect(validateLabelsWire(wire({ issued_at: '1' }))).toBe(IA);
    const KID = "'labels.kid' must be a non-empty string (<= 64 bytes)";
    expect(validateLabelsWire(wire({ kid: '' }))).toBe(KID);
    expect(validateLabelsWire(wire({ kid: 'k'.repeat(65) }))).toBe(KID);
    expect(validateLabelsWire(wire({ kid: 'k'.repeat(64) }))).toBeNull();
    expect(validateLabelsWire(wire({ sig: 7 }))).toBe("'labels.sig' must be a string");
  });
});

describe('verifyLabels', () => {
  it('verifies a signed receipt under the pinned key', () => {
    const l = signed();
    expect(l.v).toBe(1);
    expect(l.kind).toBe('pca-labels');
    expect(verifyLabels(l, KEYS)).toBeNull();
    // a non-object entry ahead of the real key is skipped, never dereferenced
    expect(verifyLabels(l, [null as never, 7 as never, ...KEYS])).toBeNull();
  });
  it('returns the wire reason first', () => {
    expect(verifyLabels({ ...signed(), v: 2 }, KEYS)).toBe('label receipt must be {v: 1, kind: "pca-labels"}');
  });
  it('refuses non-array keys', () => {
    expect(verifyLabels(signed(), null as never)).toBe('label keys must be an array');
    expect(verifyLabels(signed(), {} as never)).toBe('label keys must be an array');
  });
  it('refuses a malformed suite', () => {
    expect(verifyLabels({ ...signed(), pq_sig: 'x' }, KEYS)).toBe('signature suite: an ed25519 artifact must not carry pq_pk / pq_sig');
  });
  it('refuses an unpinned site or kid', () => {
    expect(verifyLabels(signed(), [{ site: 'other', kid: 'k1', pk: PK }])).toBe(`no pinned label key for site '${SITE}' kid 'k1'`);
    expect(verifyLabels(signed(), [{ site: SITE, kid: 'k2', pk: PK }])).toBe(`no pinned label key for site '${SITE}' kid 'k1'`);
    expect(verifyLabels(signed(), [])).toBe(`no pinned label key for site '${SITE}' kid 'k1'`);
  });
  it('refuses a bad signature or a wrong pinned key', () => {
    expect(verifyLabels(signed(), [{ site: SITE, kid: 'k1', pk: OTHER_PK }])).toBe('bad label receipt signature');
    const l = signed() as PcaLabels;
    expect(verifyLabels({ ...l, issued_at: 6 }, KEYS)).toBe('bad label receipt signature');
    // the first matching key decides
    expect(verifyLabels(l, [{ site: SITE, kid: 'k1', pk: OTHER_PK }, ...KEYS])).toBe('bad label receipt signature');
  });
});

describe('flowRuleFor', () => {
  const rules = { 'pii.contact': ['a'], 'pii.*': ['b'], 'pii.contact.*': ['c'], '*': ['d'] };
  it('exact beats prefix beats *', () => {
    expect(flowRuleFor(rules, 'pii.contact')).toBe('pii.contact');
    expect(flowRuleFor(rules, 'pii.contact.email')).toBe('pii.contact.*');
    expect(flowRuleFor({ 'pii.contact.*': ['c'], 'pii.*': ['b'] }, 'pii.contact.email')).toBe('pii.contact.*');
    expect(flowRuleFor({ 'pii.*': ['b'], 'pii.contact.*': ['c'] }, 'pii.contact.email')).toBe('pii.contact.*');
    expect(flowRuleFor(rules, 'pii.ssn')).toBe('pii.*');
    expect(flowRuleFor(rules, 'piix')).toBe('*');
    expect(flowRuleFor({ 'pii.*': ['b'] }, 'piix')).toBeUndefined();
    expect(flowRuleFor({ 'pii.*': ['b'] }, 'pii')).toBeUndefined();
    expect(flowRuleFor({ 'pii.*': ['b'], 'pii.contact': ['a'] }, 'pii.x')).toBe('pii.*');
    expect(flowRuleFor({ pii: ['b'] }, 'pii.x')).toBeUndefined();
    expect(flowRuleFor({}, 'x')).toBeUndefined();
  });
  it('is undefined on malformed input', () => {
    expect(flowRuleFor(null as never, 'x')).toBeUndefined();
    expect(flowRuleFor({ '*': ['d'] }, 7 as never)).toBeUndefined();
  });
  it('uses own members only', () => {
    expect(flowRuleFor({}, 'toString')).toBeUndefined();
    expect(flowRuleFor({}, '*')).toBeUndefined();
  });
});

describe('flowAllowed', () => {
  const rules = { 'pii.*': ['crm'], secret: [] as string[], weird: 'crm' as unknown as string[] };
  it('origin and public always flow', () => {
    expect(flowAllowed({}, 'secret', 'site', 'site')).toBe(true);
    expect(flowAllowed({}, 'public', 'site', 'other')).toBe(true);
  });
  it('the most specific rule must list the sink', () => {
    expect(flowAllowed(rules, 'pii.x', 'site', 'crm')).toBe(true);
    expect(flowAllowed(rules, 'pii.x', 'site', 'ads')).toBe(false);
    expect(flowAllowed(rules, 'secret', 'site', 'crm')).toBe(false);
    expect(flowAllowed(rules, 'other', 'site', 'crm')).toBe(false);
    expect(flowAllowed(rules, 'weird', 'site', 'crm')).toBe(false);
    // no matching rule is a deny even when a member is literally named 'undefined'
    expect(flowAllowed({ undefined: ['crm'] }, 'x', 'site', 'crm')).toBe(false);
  });
  it('is false on non-string arguments', () => {
    expect(flowAllowed(rules, 7 as never, 'site', 'site')).toBe(false);
    expect(flowAllowed(rules, 'public', 7 as never, 'x')).toBe(false);
    expect(flowAllowed(rules, 'public', 'x', 7 as never)).toBe(false);
  });
});

describe('validateFlowRules', () => {
  it('accepts classes, prefixes and *', () => {
    expect(validateFlowRules({ 'pii.contact': ['a'], 'pii.*': ['b'], '*': [] })).toBeNull();
    expect(validateFlowRules({})).toBeNull();
  });
  it('refuses with the exact reason', () => {
    expect(validateFlowRules(null)).toBe('flows must be an object');
    expect(validateFlowRules([])).toBe('flows must be an object');
    expect(validateFlowRules({ Bad: [] })).toBe("flow pattern 'Bad' is not a class, a 'prefix.*' or '*'");
    expect(validateFlowRules({ '.*': [] })).toBe("flow pattern '.*' is not a class, a 'prefix.*' or '*'");
    expect(validateFlowRules({ 'a*': [] })).toBe("flow pattern 'a*' is not a class, a 'prefix.*' or '*'");
    expect(validateFlowRules({ '**': [] })).toBe("flow pattern '**' is not a class, a 'prefix.*' or '*'");
    expect(validateFlowRules({ ok: [], 'a.*': 'x' })).toBe("flow pattern 'a.*' needs a list of audiences");
    expect(validateFlowRules({ a: ['x', ''] })).toBe("flow pattern 'a' needs a list of audiences");
    expect(validateFlowRules({ a: ['x', 'y'.repeat(257)] })).toBe("flow pattern 'a' needs a list of audiences");
    expect(validateFlowRules({ a: ['y'.repeat(256)] })).toBeNull();
  });
});

describe('decideReadPurpose', () => {
  const MAL = { outcome: 'deny', minimise: [], uncovered: [] };
  const cov = { booking: ['pii.*', 'payment.card'], support: ['*'], none: [] as string[] };
  it('allows when every class is covered', () => {
    const fields = [{ path: 'a', class: 'pii.contact' }, { path: 'b', class: 'payment.card' }, { path: 'c', class: 'public' }];
    expect(decideReadPurpose(fields, 'booking', cov)).toEqual({ outcome: 'allow', minimise: [], uncovered: [] });
    expect(decideReadPurpose([{ path: 'x', class: 'anything' }], 'support', cov)).toEqual({ outcome: 'allow', minimise: [], uncovered: [] });
    expect(decideReadPurpose([], 'nope', cov)).toEqual({ outcome: 'allow', minimise: [], uncovered: [] });
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
    expect(decideReadPurpose(fields, 'booking', cov, 'deny').outcome).toBe('deny');
    expect(decideReadPurpose(fields, 'booking', cov, 'question').outcome).toBe('question');
  });
  it('an unknown or inherited purpose covers only public', () => {
    const fields = [{ path: 'a', class: 'public' }, { path: 'b', class: 'x' }];
    expect(decideReadPurpose(fields, 'unknown', cov)).toEqual({ outcome: 'question', minimise: [], uncovered: ['b'] });
    expect(decideReadPurpose(fields, 'toString', cov)).toEqual({ outcome: 'question', minimise: [], uncovered: ['b'] });
    expect(decideReadPurpose(fields, 'none', cov)).toEqual({ outcome: 'question', minimise: [], uncovered: ['b'] });
    expect(decideReadPurpose([{ path: 'c', class: 'Stryker was here' }], 'unknown', cov)).toEqual({ outcome: 'question', minimise: [], uncovered: ['c'] });
  });
  it('a prefix pattern matches only past its dot', () => {
    expect(decideReadPurpose([{ path: 'a', class: 'pii.x' }], 'p', { p: ['pii.*'] }).outcome).toBe('allow');
    expect(decideReadPurpose([{ path: 'a', class: 'piix' }], 'p', { p: ['pii.*'] }).outcome).toBe('question');
    expect(decideReadPurpose([{ path: 'a', class: 'piix' }], 'p', { p: ['pii.'] }).outcome).toBe('question');
    expect(decideReadPurpose([{ path: 'a', class: 'pii.x' }], 'p', { p: ['pii'] }).outcome).toBe('question');
    expect(decideReadPurpose([{ path: 'a', class: 'x.*' }], 'p', { p: ['x.*'] }).outcome).toBe('allow');
    expect(decideReadPurpose([{ path: 'a', class: '' }], 'p', { p: ['.*'] }).outcome).toBe('question');
    expect(decideReadPurpose([{ path: 'a', class: '*' }], 'p', { p: [] }).outcome).toBe('question');
  });
  it('refuses malformed input as deny with empty lists', () => {
    const f = [{ path: 'a', class: 'x' }];
    expect(decideReadPurpose(null as never, 'p', cov)).toEqual(MAL);
    expect(decideReadPurpose(f, 7 as never, cov)).toEqual(MAL);
    expect(decideReadPurpose(f, 'p', null as never)).toEqual(MAL);
    expect(decideReadPurpose(f, 'p', [] as never)).toEqual(MAL);
    expect(decideReadPurpose(f, 'p', cov, 'maybe' as never)).toEqual(MAL);
    expect(decideReadPurpose(f, 'p', { q: 'x' } as never)).toEqual(MAL);
    expect(decideReadPurpose(f, 'p', { q: ['a', 7] } as never)).toEqual(MAL);
    expect(decideReadPurpose([null] as never, 'p', cov)).toEqual(MAL);
    expect(decideReadPurpose([{ class: 'x' }] as never, 'p', cov)).toEqual(MAL);
    expect(decideReadPurpose([{ path: 'a' }] as never, 'p', cov)).toEqual(MAL);
    expect(decideReadPurpose([{ path: 'a', class: 'x', optional: 'yes' }] as never, 'p', cov)).toEqual(MAL);
    expect(decideReadPurpose([{ path: 'a', class: 'x', optional: null }] as never, 'p', cov)).toEqual(MAL);
    expect(decideReadPurpose([{ path: 'a', class: 'public' }, { path: 'b', class: 7 }] as never, 'p', cov)).toEqual(MAL);
    expect(decideReadPurpose([{ path: 'a', class: 'public' }], 'p', { a: [], b: ['x', 7] } as never)).toEqual(MAL);
  });
  it('accepts the deny and question policies explicitly and defaults to question', () => {
    const f = [{ path: 'a', class: 'x' }];
    expect(decideReadPurpose(f, 'p', {})).toEqual({ outcome: 'question', minimise: [], uncovered: ['a'] });
    expect(decideReadPurpose(f, 'p', {}, 'deny')).toEqual({ outcome: 'deny', minimise: [], uncovered: ['a'] });
    expect(decideReadPurpose([{ path: 'a', class: 'x', optional: true }], 'p', {}, 'deny')).toEqual({ outcome: 'allow', minimise: ['a'], uncovered: [] });
  });
});
