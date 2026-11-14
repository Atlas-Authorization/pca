import { describe, expect, it } from 'vitest';
import {
  ACTION_PIN_ON_NEW, EVOLUTION_CLASSES, EVOLUTION_DIFF_DOMAIN, EVOLUTION_DOMAIN, EVOLUTION_RECORD_KIND, MAX_ESC_TIER, MAX_EVOLUTION_STEPS, REAPPROVAL_DOMAIN, REAPPROVAL_KIND,
  actionPinError, decidePin, evolutionDiffDigest, evolutionRecordError, reapprovalValid, registryKeyOf, signEvolutionRecord, signReapproval, signRegistryDoc, verifyEvolutionRecord, verifyRegistrySig,
  type EvolutionRecord, type UnsignedEvolutionRecord,
} from './action-pin';
import { canonicalBytesStrict, hashCanonical, utf8 } from './hash';
import { generateKeyPair } from './keys';
import { mlDsa65Keygen, signSuiteArtifact, suiteKeysOf, suitePqPublicKey } from './pq';

const reg = generateKeyPair();
const other = generateKeyPair();
const principal = generateKeyPair();
const KEY = registryKeyOf('r1', reg.secretKey);
const KEYS = [KEY];
const dg = (c: string) => c.repeat(43);
const A = dg('A'), B = dg('B'), C = dg('C'), D = dg('D');
const VERB = 'acme.thing.do';
const PIN = { pack: { ns: 'acme', root: dg('R') }, defs: { [VERB]: A }, on_new_action: 'deny' as const };
const rec = (from: string | null, to: string | null, cls: UnsignedEvolutionRecord['class'], over: Partial<UnsignedEvolutionRecord> = {}): EvolutionRecord =>
  signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'acme', verb: VERB, from, to, class: cls, reasons: [], ...over }, 'r1', reg.secretKey);
const grant = { id: dg('G'), issuer: Buffer.from(principal.publicKey).toString('base64url') };
const doc = (def: string | undefined, pack: unknown = { ns: 'acme', root: dg('R') }) => ({ pack: pack as never, verbs: [{ verb: VERB, def }] });
const decide = (def: string | undefined, records: unknown[] = [], reapprovals: unknown[] = [], pin: unknown = PIN, d = doc(def)) => decidePin({ pin, doc: d, verb: VERB, records, keys: KEYS, reapprovals, grant });
const cat = (a: Uint8Array, b: Uint8Array) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const unsigned = (r: EvolutionRecord): UnsignedEvolutionRecord => { const { sig: _s, ...u } = r; void _s; return u; };
const dd = (i: number) => `D${i}`.padEnd(43, 'x');

describe('constants', () => {
  it('are exact', () => {
    expect(EVOLUTION_RECORD_KIND).toBe('pca-evolution-record');
    expect(REAPPROVAL_KIND).toBe('pca-reapproval');
    expect(EVOLUTION_DOMAIN).toBe('atlas-pca/action-evolution/v1\0');
    expect(EVOLUTION_DIFF_DOMAIN).toBe('atlas-pca/action-evolution-diff/v1');
    expect(REAPPROVAL_DOMAIN).toBe('atlas-pca/action-reapproval/v1\0');
    expect(MAX_EVOLUTION_STEPS).toBe(32);
    expect(MAX_ESC_TIER).toBe(3);
    expect([...ACTION_PIN_ON_NEW]).toEqual(['deny', 'escalate']);
    expect([...EVOLUTION_CLASSES]).toEqual(['equal', 'narrow', 'widen', 'incomparable', 'added', 'removed']);
  });
  it('the diff digest and the signed messages are built from those domains', () => {
    const r = rec(A, B, 'widen', { reasons: ['x'] });
    expect(evolutionDiffDigest(r)).toBe(hashCanonical({ d: 'atlas-pca/action-evolution-diff/v1', ns: 'acme', verb: VERB, from: A, to: B, class: 'widen', reasons: ['x'] }));
    const body = unsigned(r);
    const expected = signSuiteArtifact(undefined, suiteKeysOf(reg.secretKey, undefined), cat(utf8('atlas-pca/action-evolution/v1\0'), canonicalBytesStrict(body))).sig;
    expect(r.sig.value).toBe(expected);
    const a = signReapproval({ grantId: grant.id, record: r, principalSecret: principal.secretKey });
    const { sig: _s, ...abody } = a;
    void _s;
    expect(a.sig.value).toBe(signSuiteArtifact(undefined, suiteKeysOf(principal.secretKey, undefined), cat(utf8('atlas-pca/action-reapproval/v1\0'), canonicalBytesStrict(abody))).sig);
    expect(abody).toEqual({ v: 1, kind: 'pca-reapproval', grant: grant.id, verb: VERB, diff: evolutionDiffDigest(r) });
  });
});

describe('actionPinError exact refusals', () => {
  const pinWith = (over: Record<string, unknown>) => ({ ...PIN, ...over });
  it('object, closed members and pack shape', () => {
    expect(actionPinError(null)).toBe('actions must be an object');
    expect(actionPinError(pinWith({ extra: 1 }))).toBe("actions: unknown member 'extra'");
    for (const p of [null, [], 'x', undefined, { ns: 'acme', root: dg('R'), extra: 1 }]) expect(actionPinError(pinWith({ pack: p }))).toBe('actions.pack must be {ns, root}');
    expect(actionPinError(pinWith({ pack: { ns: 'acme' } }))).toBe('actions.pack.root must be a base64url digest');
    expect(actionPinError(pinWith({ pack: { root: dg('R') } }))).toBe('actions.pack.ns is not a namespace');
  });
  it('namespace grammar', () => {
    const ns = (n: unknown) => actionPinError(pinWith({ pack: { ns: n, root: dg('R') } }));
    for (const ok of ['acme', 'a_1', 'a.bc', 'a.b.c.d.e.f', 'ab.cd']) expect(ns(ok), ok).toBeNull();
    for (const bad of ['Acme', 'acme!', '', 'a.b.c.d.e.f.g', 'a..b', '.a', 'a.', 'a.B', 5, ['acme']]) expect(ns(bad), String(bad)).toBe('actions.pack.ns is not a namespace');
  });
  it('root digest grammar', () => {
    const root = (r: unknown) => actionPinError(pinWith({ pack: { ns: 'acme', root: r } }));
    expect(root(dg('R'))).toBeNull();
    expect(root('a-_9'.repeat(10) + 'abc')).toBeNull();
    for (const bad of [dg('R') + 'R', '!' + dg('R'), dg('R') + '!', 'R'.repeat(42), 'R'.repeat(42) + '=', [dg('R')], 5]) expect(root(bad), String(bad)).toBe('actions.pack.root must be a base64url digest');
  });
  it('tiers: 0 and 3 are tiers, nothing else is', () => {
    expect(actionPinError(pinWith({ max_esc: 0 }))).toBeNull();
    expect(actionPinError(pinWith({ max_esc: 3, preauth_esc: 3 }))).toBeNull();
    expect(actionPinError(pinWith({ max_esc: 3, preauth_esc: 0 }))).toBeNull();
    expect(actionPinError(pinWith({ preauth_esc: 0 }))).toBeNull();
    expect(actionPinError(pinWith({ max_esc: 2, preauth_esc: 2 }))).toBeNull();
    for (const bad of [-1, 4, 1.5, '1', NaN, Infinity, -0, null, [1]]) {
      expect(actionPinError(pinWith({ max_esc: bad })), String(bad)).toBe('actions.max_esc must be an integer tier 0..3');
      expect(actionPinError(pinWith({ preauth_esc: bad })), String(bad)).toBe('actions.preauth_esc must be an integer tier 0..3');
    }
    expect(actionPinError(pinWith({ max_esc: 1, preauth_esc: 2 }))).toBe('actions.preauth_esc exceeds actions.max_esc');
    expect(actionPinError(pinWith({ max_esc: 0, preauth_esc: 1 }))).toBe('actions.preauth_esc exceeds actions.max_esc');
  });
  it('caveats', () => {
    const msg = 'actions.caveats must be distinct caveat kinds';
    expect(actionPinError(pinWith({ caveats: [] }))).toBeNull();
    expect(actionPinError(pinWith({ caveats: ['amount_cap', 'window'] }))).toBeNull();
    for (const bad of ['amount_cap', {}, ['amount_cap', 'nope'], ['nope', 'amount_cap'], [5], ['window', 'window'], [null]]) expect(actionPinError(pinWith({ caveats: bad })), JSON.stringify(bad)).toBe(msg);
  });
  it('defs', () => {
    expect(actionPinError(pinWith({ defs: 'x' }))).toBe('actions.defs must be an object');
    expect(actionPinError(pinWith({ defs: {} }))).toBeNull();
    expect(actionPinError(pinWith({ defs: { 'Bad Verb': A } }))).toBe("actions.defs: 'Bad Verb' is not a verb");
    expect(actionPinError(pinWith({ defs: { [VERB]: 'x' } }))).toBe(`actions.defs.${VERB} must be a base64url digest`);
    expect(actionPinError(pinWith({ defs: { [VERB]: [A] } }))).toBe(`actions.defs.${VERB} must be a base64url digest`);
    expect(actionPinError(pinWith({ defs: { [VERB]: A + 'A' } }))).toBe(`actions.defs.${VERB} must be a base64url digest`);
    expect(actionPinError(pinWith({ defs: { [VERB]: '!' + A } }))).toBe(`actions.defs.${VERB} must be a base64url digest`);
    expect(actionPinError(pinWith({ defs: { [VERB]: A + '!' } }))).toBe(`actions.defs.${VERB} must be a base64url digest`);
  });
  it('verb grammar', () => {
    const v = (n: string) => actionPinError(pinWith({ defs: { [n]: A } }));
    for (const ok of ['a.bc', 'a.b.c', 'a_1.b2', 'a.b.c.d.e.f']) expect(v(ok), ok).toBeNull();
    for (const bad of ['acme', 'Acme.x', 'acme.x!', '!acme.x', 'a.b.c.d.e.f.g', 'a..b', '.a.b', 'a.b.', '']) expect(v(bad), bad).toBe(`actions.defs: '${bad}' is not a verb`);
  });
});

describe('evolutionRecordError exact refusals', () => {
  const base = rec(A, B, 'narrow');
  const bare = unsigned(base);
  it('well formed passes; non-objects and unknown members', () => {
    expect(evolutionRecordError(base)).toBeNull();
    expect(evolutionRecordError(bare, { signed: false })).toBeNull();
    expect(evolutionRecordError(null)).toBe('evolution record must be an object');
    expect(evolutionRecordError({ ...bare, sig: base.sig, extra: 1 })).toBe("evolution record: unknown member 'extra'");
    expect(evolutionRecordError(base, { signed: false })).toBe("evolution record: unknown member 'sig'");
  });
  it('v and kind are checked separately', () => {
    expect(evolutionRecordError({ ...base, v: 2 })).toBe('evolution record: bad v/kind');
    expect(evolutionRecordError({ ...base, kind: 'x' })).toBe('evolution record: bad v/kind');
  });
  it('ns and verb', () => {
    for (const ns of ['Bad', 'acme!', '', ['acme'], 5]) expect(evolutionRecordError({ ...base, ns }), String(ns)).toBe('evolution record: bad ns');
    for (const ns of ['a.bc', 'a.b.c.d.e.f', 'a_1']) expect(evolutionRecordError({ ...base, ns }), ns).toBeNull();
    for (const ns of ['a.b.c.d.e.f.g', 'a..b', 'A']) expect(evolutionRecordError({ ...base, ns }), ns).toBe('evolution record: bad ns');
    for (const verb of ['acme', 'Acme.x', 'acme.x!', [VERB], 5, 'a.b.c.d.e.f.g']) expect(evolutionRecordError({ ...base, verb }), String(verb)).toBe('evolution record: bad verb');
    for (const verb of ['a.bc', 'a.b.c', 'a.b.c.d.e.f']) expect(evolutionRecordError({ ...base, verb }), verb).toBeNull();
  });
  it('from and to are null or a digest', () => {
    for (const bad of ['x', [A], 5, undefined, A + 'A', '!' + A, A + '!']) {
      expect(evolutionRecordError({ ...base, from: bad }), String(bad)).toBe('evolution record: bad from');
      expect(evolutionRecordError({ ...base, to: bad }), String(bad)).toBe('evolution record: bad to');
    }
  });
  it('class and endpoints', () => {
    expect(evolutionRecordError({ ...base, class: 'sideways' })).toBe('evolution record: bad class');
    const ep = 'evolution record: endpoints do not match the class';
    expect(evolutionRecordError({ ...base, class: 'added' })).toBe(ep);
    expect(evolutionRecordError({ ...base, from: null })).toBe(ep);
    expect(evolutionRecordError({ ...base, class: 'removed' })).toBe(ep);
    expect(evolutionRecordError({ ...base, to: null })).toBe(ep);
    expect(evolutionRecordError({ ...base, class: 'removed', to: null })).toBeNull();
    expect(evolutionRecordError({ ...base, class: 'added', from: null })).toBeNull();
  });
  it('reasons', () => {
    const msg = 'evolution record: bad reasons';
    expect(evolutionRecordError({ ...base, reasons: Array.from({ length: 64 }, () => 'r') })).toBeNull();
    expect(evolutionRecordError({ ...base, reasons: ['r'.repeat(512)] })).toBeNull();
    expect(evolutionRecordError({ ...base, reasons: Array.from({ length: 65 }, () => 'r') })).toBe(msg);
    expect(evolutionRecordError({ ...base, reasons: ['r'.repeat(513)] })).toBe(msg);
    expect(evolutionRecordError({ ...base, reasons: [5] })).toBe(msg);
    expect(evolutionRecordError({ ...base, reasons: ['ok', null] })).toBe(msg);
    expect(evolutionRecordError({ ...base, reasons: 'abc' })).toBe(msg);
    expect(evolutionRecordError({ ...base, reasons: {} })).toBe(msg);
    expect(evolutionRecordError({ ...base, reasons: undefined })).toBe(msg);
  });
  it('signature shape', () => {
    const bad = 'evolution record: bad sig';
    const s = base.sig;
    expect(evolutionRecordError({ ...base, sig: undefined })).toBe(bad);
    expect(evolutionRecordError({ ...base, sig: 'x' })).toBe(bad);
    expect(evolutionRecordError({ ...base, sig: [] })).toBe(bad);
    expect(evolutionRecordError({ ...base, sig: { ...s, extra: 1 } })).toBe(bad);
    expect(evolutionRecordError({ ...base, sig: { ...s, pq_value: 'abc' } })).toBeNull();
    expect(evolutionRecordError({ ...base, sig: { ...s, pq_value: 5 } })).toBe(bad);
    for (const kid of [5, '', 'k'.repeat(129), undefined]) expect(evolutionRecordError({ ...base, sig: { ...s, kid } }), String(kid)).toBe(bad);
    expect(evolutionRecordError({ ...base, sig: { ...s, kid: 'k'.repeat(128) } })).toBeNull();
    expect(evolutionRecordError({ ...base, sig: { ...s, kid: 'k' } })).toBeNull();
    expect(evolutionRecordError({ ...base, sig: { ...s, value: 5 } })).toBe(bad);
    expect(evolutionRecordError({ ...base, sig: { ...s, alg: 5 } })).toBe(bad);
    expect(evolutionRecordError({ ...base, sig: { ...s, alg: 'anything' } })).toBeNull();
  });
  it('content that cannot be canonicalized is refused with the encoder message', () => {
    expect(evolutionRecordError({ ...base, reasons: ['\ud800'] })).toBe('evolution record: canonicalize: lone surrogate in string');
    expect(evolutionRecordError({ ...bare, reasons: ['\ud800'] }, { signed: false })).toBe('evolution record: canonicalize: lone surrogate in string');
  });
  it('verifyEvolutionRecord relays the shape refusal', () => {
    expect(verifyEvolutionRecord({ ...base, ns: 'Bad' }, KEYS)).toEqual({ ok: false, reason: 'evolution record: bad ns' });
    expect(verifyEvolutionRecord(base, KEYS)).toEqual({ ok: true });
  });
});

describe('verifyRegistrySig exact refusals and suites', () => {
  const DOM = 'test/domain\0';
  const body = { a: 1 };
  const sig = signRegistryDoc(DOM, body, 'r1', reg.secretKey);
  it('signs ed25519 without any pq member, and the registry key has none either', () => {
    expect(Object.keys(sig).sort()).toEqual(['alg', 'kid', 'value']);
    expect(sig.alg).toBe('ed25519');
    expect(Object.keys(KEY).sort()).toEqual(['alg', 'kid', 'pk']);
    expect(verifyRegistrySig(DOM, body, sig, KEYS)).toEqual({ ok: true });
    expect(verifyRegistrySig(DOM, body, { alg: undefined, kid: 'r1', value: sig.value }, KEYS)).toEqual({ ok: true });
  });
  it('refusals carry their exact reason', () => {
    const r = (b: unknown, s: { alg: unknown; kid: unknown; value: unknown; pq_value?: unknown }, k: unknown) => verifyRegistrySig(DOM, b, s, k as never);
    expect(r(body, sig, 'x')).toEqual({ ok: false, reason: 'the registry keys must be an array' });
    expect(r(body, sig, { length: 1 })).toEqual({ ok: false, reason: 'the registry keys must be an array' });
    expect(r(body, { ...sig, kid: 'zz' }, KEYS)).toEqual({ ok: false, reason: "no registry key with kid 'zz'" });
    expect(r(body, { ...sig, kid: undefined }, [{ ...KEY, kid: undefined }])).toEqual({ ok: false, reason: "no registry key with kid 'undefined'" });
    expect(r(body, { ...sig, kid: 'r1' }, [registryKeyOf('zz', other.secretKey), KEY])).toEqual({ ok: true });
    expect(r(body, sig, [{ ...KEY, pq_pk: 5 }])).toEqual({ ok: false, reason: 'the registry key pq_pk must be a string' });
    expect(r(body, sig, [{ ...KEY, pk: 'x' }])).toEqual({ ok: false, reason: 'registry key pk is not canonical base64url (32 bytes)' });
    expect(r(body, sig, [{ ...KEY, pk: undefined }])).toEqual({ ok: false, reason: 'registry key pk is not canonical base64url (32 bytes)' });
    expect(r(body, { ...sig, alg: 'ml-dsa-65' }, KEYS)).toEqual({ ok: false, reason: 'sig.alg does not match the pinned key suite' });
    expect(r(body, { ...sig, alg: 'bogus' }, KEYS)).toEqual({ ok: false, reason: 'sig.alg does not match the pinned key suite' });
    expect(r(body, sig, [{ ...KEY, alg: 'bogus' }])).toEqual({ ok: false, reason: 'sig.alg does not match the pinned key suite' });
    expect(r({ a: 2 }, sig, KEYS)).toEqual({ ok: false, reason: 'signature invalid' });
    expect(r(body, sig, [registryKeyOf('r1', other.secretKey)])).toEqual({ ok: false, reason: 'signature invalid' });
    expect(r({ a: '\ud800' }, sig, KEYS)).toEqual({ ok: false, reason: 'verification error: canonicalize: lone surrogate in string' });
  });
  it('a hybrid suite carries pq_value, the key pins pq_pk, and both halves are required', () => {
    const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(7));
    const suite = { alg: 'hybrid-ed25519-ml-dsa-65' as const, mlDsa };
    const hs = signRegistryDoc(DOM, body, 'h1', reg.secretKey, suite);
    const hk = registryKeyOf('h1', reg.secretKey, suite);
    expect(hs.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(typeof hs.pq_value).toBe('string');
    expect(hk.pq_pk).toBe(suitePqPublicKey('hybrid-ed25519-ml-dsa-65', suite));
    expect(typeof hk.pq_pk).toBe('string');
    expect(verifyRegistrySig(DOM, body, hs, [hk])).toEqual({ ok: true });
    expect(verifyRegistrySig(DOM, body, { ...hs, pq_value: undefined }, [hk])).toEqual({ ok: false, reason: 'signature invalid' });
    expect(verifyRegistrySig(DOM, body, hs, [{ ...hk, pq_pk: undefined } as never])).toEqual({ ok: false, reason: 'signature invalid' });
    const wrongPq = registryKeyOf('h1', reg.secretKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(8)) });
    expect(verifyRegistrySig(DOM, body, hs, [wrongPq])).toEqual({ ok: false, reason: 'signature invalid' });
    expect(verifyRegistrySig(DOM, body, hs, [KEY])).toEqual({ ok: false, reason: "no registry key with kid 'h1'" });
    const asEd = { ...hk, alg: 'ed25519' as const };
    expect(verifyRegistrySig(DOM, body, hs, [asEd])).toEqual({ ok: false, reason: 'sig.alg does not match the pinned key suite' });
    // a signed hybrid evolution record verifies end to end
    const hr = signEvolutionRecord(unsigned(rec(A, B, 'equal')), 'h1', reg.secretKey, suite);
    expect(verifyEvolutionRecord(hr, [hk])).toEqual({ ok: true });
  });
});

describe('reapprovalValid', () => {
  const r0 = rec(A, B, 'widen');
  const diff = evolutionDiffDigest(r0);
  const craft = (over: Record<string, unknown> = {}) => {
    const body = { v: 1, kind: 'pca-reapproval', grant: grant.id, verb: VERB, diff, ...over };
    const sig = signSuiteArtifact(undefined, suiteKeysOf(principal.secretKey, undefined), cat(utf8(REAPPROVAL_DOMAIN), canonicalBytesStrict(body))).sig;
    return { ...body, sig: { alg: 'ed25519', value: sig } };
  };
  const ok = (r: unknown) => reapprovalValid(r, grant.id, grant.issuer, VERB, diff);
  it('the crafted baseline is valid, so each refusal below is attributable to one member', () => {
    expect(ok(craft())).toBe(true);
    expect(ok(signReapproval({ grantId: grant.id, record: r0, principalSecret: principal.secretKey }))).toBe(true);
  });
  it('shape: plain object, closed members, v, kind', () => {
    const g = craft();
    expect(ok(Object.assign(Object.create({}), g))).toBe(false);
    expect(ok(craft({ extra: 1 }))).toBe(false);
    expect(ok(craft({ v: 2 }))).toBe(false);
    expect(ok(craft({ kind: 'other' }))).toBe(false);
    expect(ok(null)).toBe(false);
    expect(ok([])).toBe(false);
  });
  it('sig member shape does not rely on the signature check', () => {
    const g = craft();
    expect(ok({ ...g, sig: { ...g.sig, extra: 1 } })).toBe(false);
    expect(ok({ ...g, sig: { ...g.sig, alg: 'ml-dsa-65' } })).toBe(false);
    expect(ok(Object.assign({ ...g }, { sig: Object.assign(Object.create({}), g.sig) }))).toBe(false);
    expect(ok({ ...g, sig: { ...g.sig, value: 5 } })).toBe(false);
    expect(ok({ ...g, sig: 'x' })).toBe(false);
  });
  it('an unencodable body is a plain false', () => {
    const bad = { v: 1, kind: 'pca-reapproval', grant: '\ud800', verb: VERB, diff, sig: { alg: 'ed25519', value: 'x' } };
    expect(reapprovalValid(bad, '\ud800', grant.issuer, VERB, diff)).toBe(false);
  });
});

describe('decidePin exact decisions', () => {
  it('malformed pin and unknown verb', () => {
    expect(decide(A, [], [], { ...PIN, on_new_action: 'maybe' })).toStrictEqual({ ok: false, code: 'bad_pin', escalate: false, reason: "actions.on_new_action must be 'deny' or 'escalate'" });
    expect(decide(A, [], [], 'x')).toStrictEqual({ ok: false, code: 'bad_pin', escalate: false, reason: 'actions must be an object' });
    const unk = { ok: false, code: 'unknown_verb', escalate: false, reason: `the accepted schema does not declare '${VERB}'` };
    expect(decidePin({ pin: PIN, doc: null as never, verb: VERB, grant })).toStrictEqual(unk);
    expect(decidePin({ pin: PIN, doc: { pack: PIN.pack } as never, verb: VERB, grant })).toStrictEqual(unk);
    expect(decidePin({ pin: PIN, doc: { pack: PIN.pack, verbs: 'x' } as never, verb: VERB, grant })).toStrictEqual(unk);
    expect(decidePin({ pin: PIN, doc: { pack: PIN.pack, verbs: [] }, verb: VERB, grant })).toStrictEqual(unk);
  });
  it('the verb is found by name, skipping null entries and other verbs', () => {
    const d = { pack: PIN.pack, verbs: [null, { verb: 'acme.other.do', def: B }, { verb: VERB, def: A }] as never };
    expect(decidePin({ pin: PIN, doc: d, verb: VERB, grant })).toStrictEqual({ ok: true, via: 'exact' });
  });
  it('pack checks carry their reason', () => {
    const mism = { ok: false, code: 'pack_mismatch', escalate: false, reason: "the schema does not come from the pinned pack 'acme'" };
    expect(decide(A, [], [], PIN, doc(A, { ns: 'other', root: dg('R') }))).toStrictEqual(mism);
    expect(decide(A, [], [], PIN, doc(A, null))).toStrictEqual(mism);
    const packOnly = { pack: PIN.pack, on_new_action: 'deny' };
    expect(decide(A, [], [], packOnly)).toStrictEqual({ ok: true, via: 'pack' });
    expect(decide(A, [], [], packOnly, doc(A, { ns: 'acme', root: dg('S') }))).toStrictEqual({
      ok: false, code: 'pack_mismatch', escalate: false, reason: 'the pack root differs from the pinned root (the grant pins the pack as a whole)',
    });
  });
  it('a verb the pin does not name', () => {
    const pin = { ...PIN, defs: { 'acme.x.y': A } };
    expect(decidePin({ pin, doc: doc(A), verb: VERB, grant })).toStrictEqual({ ok: false, code: 'new_action', escalate: false, reason: `the grant does not name '${VERB}' (on_new_action: deny)` });
    expect(decidePin({ pin: { ...pin, on_new_action: 'escalate' }, doc: doc(A), verb: VERB, grant })).toStrictEqual({
      ok: false, code: 'new_action', escalate: true, reason: `the grant does not name '${VERB}' (on_new_action: escalate)`,
    });
  });
  it('a missing or different digest', () => {
    expect(decide(undefined)).toStrictEqual({ ok: false, code: 'def_changed', escalate: false, reason: 'the schema verb carries no definition digest' });
    expect(decide(undefined, [rec(A, B, 'equal')])).toStrictEqual({ ok: false, code: 'def_changed', escalate: false, reason: 'the schema verb carries no definition digest' });
    expect(decide(B)).toStrictEqual({ ok: false, code: 'def_changed', escalate: false, reason: 'the definition differs from the pinned digest and no signed evolution record chains to it' });
  });
  it('a throwing document fails closed with the error message', () => {
    const d = { get verbs(): never { throw new Error('boom'); } } as never;
    expect(decidePin({ pin: PIN, doc: d, verb: VERB, grant })).toStrictEqual({ ok: false, code: 'bad_pin', escalate: false, reason: 'pin evaluation error (fail closed): boom' });
  });
  it('blocked steps name the first step to approve, nearest the pin', () => {
    const msg = 'the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve';
    const ab = rec(A, B, 'widen'), bc = rec(B, C, 'widen');
    expect(decide(B, [ab])).toStrictEqual({ ok: false, code: 'def_changed', escalate: false, reason: msg, needs_reapproval: evolutionDiffDigest(ab) });
    expect(decide(C, [ab, bc])).toStrictEqual({ ok: false, code: 'def_changed', escalate: false, reason: msg, needs_reapproval: evolutionDiffDigest(ab) });
    const free = rec(A, B, 'narrow');
    expect(decide(C, [free, bc])).toStrictEqual({ ok: false, code: 'def_changed', escalate: false, reason: msg, needs_reapproval: evolutionDiffDigest(bc) });
    const ab2 = rec(A, B, 'widen'), bcFree = rec(B, C, 'narrow');
    expect(decide(C, [ab2, bcFree])).toStrictEqual({ ok: false, code: 'def_changed', escalate: false, reason: msg, needs_reapproval: evolutionDiffDigest(ab2) });
  });
  it('the first discoverer of a node keeps it (diamond)', () => {
    const ab = rec(A, B, 'widen'), ac = rec(A, C, 'widen');
    const out = decide(D, [ab, ac, rec(B, D, 'narrow'), rec(C, D, 'narrow')]);
    expect(out).toMatchObject({ ok: false, code: 'def_changed', needs_reapproval: evolutionDiffDigest(ab) });
  });
  it('a re-approved step opens the chain only for its own diff and grant', () => {
    const ab = rec(A, B, 'widen');
    const a = signReapproval({ grantId: grant.id, record: ab, principalSecret: principal.secretKey });
    expect(decide(B, [ab], [a])).toStrictEqual({ ok: true, via: 'chain' });
    expect(decide(B, [ab], [{ ...a, grant: dg('X') }]).ok).toBe(false);
    expect(decide(B, [ab], ['junk', null, a])).toStrictEqual({ ok: true, via: 'chain' });
  });
  it('the chain is followed for exactly MAX_EVOLUTION_STEPS hops', () => {
    const chain = (n: number) => Array.from({ length: n }, (_, i) => rec(i === 0 ? A : dd(i), dd(i + 1), 'equal'));
    expect(decide(dd(MAX_EVOLUTION_STEPS), chain(MAX_EVOLUTION_STEPS))).toStrictEqual({ ok: true, via: 'chain' });
    expect(decide(dd(MAX_EVOLUTION_STEPS + 1), chain(MAX_EVOLUTION_STEPS + 1))).toStrictEqual({
      ok: false, code: 'def_changed', escalate: false, reason: 'the definition differs from the pinned digest and no signed evolution record chains to it',
    });
  });
  it('a blocked chain longer than the bound is not reported as approvable', () => {
    const chain = Array.from({ length: MAX_EVOLUTION_STEPS + 1 }, (_, i) => rec(i === 0 ? A : dd(i), dd(i + 1), 'widen'));
    expect(decide(dd(MAX_EVOLUTION_STEPS + 1), chain)).toStrictEqual({
      ok: false, code: 'def_changed', escalate: false, reason: 'the definition differs from the pinned digest and no signed evolution record chains to it',
    });
  });
});
