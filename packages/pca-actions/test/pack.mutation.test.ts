// Behaviour tests for signed action packs: exact shape errors, shard handling, build errors and options, verification
// reasons and upgrade reasons. Every assertion pins a whole message or a whole output.
import { generateKeyPair } from '@atlasauth/pca';
import { EVOLUTION_RECORD_KIND, registryKeyOf, signEvolutionRecord, signRegistryDoc } from '@atlasauth/pca/ext/intent';
import { describe, expect, it } from 'vitest';
import {
  ActionKitError, BUILTIN_DEFS, CORE_REGISTRY, MAX_EVOLUTION_RECORDS, MAX_PACK_DEFS, PACK_SHARD_KIND, PACK_SIG_DOMAIN, buildPack, compareVersions, defDigest, extendRegistry, packDefs,
  packDigest, packShapeError, shardDefs, shardDigest, validateDef, verifyActionPack, verifyUpgrade, type ActionDef, type ActionPack, type PackShard,
} from '../src';
import { confirmed, testReview } from './reviewed';

const reg = generateKeyPair();
const other = generateKeyPair();
const KEYS = [registryKeyOf('reg-1', reg.secretKey)];
const SRC = { kind: 'hand', uri: 'internal://pack', spec_digest: 'A'.repeat(43), licence: 'Apache-2.0', licence_notes: 'authored in house' };
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const charge = BUILTIN_DEFS.find((d) => d.verb === 'stripe.charge')!;
const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
const stripe = BUILTIN_DEFS.filter((d) => d.verb.startsWith('stripe.'));
const mkDef = (verb: string, rtype: string): ActionDef => {
  const c = clone(charge) as any;
  c.verb = verb;
  c.resource.type = rtype;
  return c as ActionDef;
};
const patchDef = (d: ActionDef, f: (x: any) => void): ActionDef => {
  const c = clone(d) as any;
  f(c);
  return c as ActionDef;
};
const alphaGet = mkDef('acme.alpha.get', 'alpha');
const alphaPut = mkDef('acme.alpha.put', 'alpha.sub');
const betaGet = mkDef('acme.beta.get', 'beta');
const betaPut = mkDef('acme.beta.put', 'beta');
const defs3 = [alphaGet, alphaPut, betaGet];

type BA = Parameters<typeof buildPack>[0];
const mk = (defs: readonly ActionDef[], version: string, prev?: { pack: ActionPack; shards?: Record<string, PackShard> }, extra: Partial<BA> = {}) =>
  buildPack({ ns: 'acme', version, stability: 'stable', defs, source: SRC, kid: 'reg-1', secret: reg.secretKey, ...(prev ? { prev } : {}), ...extra });
const thrown = (f: () => unknown): ActionKitError => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(ActionKitError);
    return e as ActionKitError;
  }
  throw new Error('expected a throw');
};
const codeMsg = (f: () => unknown) => {
  const e = thrown(f);
  return [e.code, e.message];
};
const unsignedOf = (p: ActionPack): any => {
  const { sig: _s, ...b } = clone(p) as any;
  void _s;
  return b;
};
const resign = (p: ActionPack, f: (b: any) => void): ActionPack => {
  const b = unsignedOf(p);
  f(b);
  return { ...b, sig: signRegistryDoc(PACK_SIG_DOMAIN, b, 'reg-1', reg.secretKey) } as ActionPack;
};
const rec = (over: Record<string, unknown>, secret = reg.secretKey) =>
  signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'acme', verb: 'acme.alpha.get', from: null, to: defDigest(alphaGet), class: 'added', reasons: [], ...over } as never, 'reg-1', secret);

const base = mk(defs3, '1.0.0').pack;
const sharded = mk(defs3, '1.0.0', undefined, { shard: { max: 1, uri: (n: string) => `mem://${n}` } });
const shapeU = (f: (b: any) => void, signed = false) => {
  const b = unsignedOf(base);
  f(b);
  return packShapeError(b, { signed });
};
const shapeS = (f: (p: any) => void, from: ActionPack = base) => {
  const p = clone(from) as any;
  f(p);
  return packShapeError(p);
};

describe('compareVersions', () => {
  it('returns the numeric difference of the first differing component', () => {
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
    expect(compareVersions('2.0.0', '1.5.5')).toBe(1);
    expect(compareVersions('1.9.0', '1.4.9')).toBe(5);
    expect(compareVersions('1.2.3', '1.2.1')).toBe(2);
    expect(compareVersions('1.0.1', '1.0.0')).toBe(1);
    expect(compareVersions('1.0.0', '1.0.1')).toBe(-1);
  });
  it('refuses a non MAJOR.MINOR.PATCH string with a typed error naming the offending side', () => {
    expect(codeMsg(() => compareVersions('1.0', '1.0.0'))).toEqual(['bad_version', "'1.0' is not MAJOR.MINOR.PATCH"]);
    expect(codeMsg(() => compareVersions('1.0.0', 'x'))).toEqual(['bad_version', "'x' is not MAJOR.MINOR.PATCH"]);
    expect(codeMsg(() => compareVersions('a', 'b'))).toEqual(['bad_version', "'a' is not MAJOR.MINOR.PATCH"]);
  });
});

describe('shardDefs', () => {
  const fake = (verb: string, type: string): ActionDef => ({ verb, resource: { type } }) as unknown as ActionDef;
  const ds = [fake('x.g1', 'gamma'), fake('x.b1', 'beta.q'), fake('x.b2', 'beta'), fake('x.a1', 'alpha'), fake('x.b3', 'beta'), fake('x.a2', 'alpha.z')];
  it('names shards by family in sorted order and splits only families larger than the shard size', () => {
    expect(shardDefs(ds, 2).map((s) => [s.name, s.defs.map((d) => d.verb)])).toEqual([
      ['alpha', ['x.a1', 'x.a2']],
      ['beta-1', ['x.b1', 'x.b2']],
      ['beta-2', ['x.b3']],
      ['gamma', ['x.g1']],
    ]);
  });
  it('a size of one is valid and splits every multi-def family', () => {
    expect(shardDefs(ds, 1).map((s) => s.name)).toEqual(['alpha-1', 'alpha-2', 'beta-1', 'beta-2', 'beta-3', 'gamma']);
  });
  it('the default size keeps a small set in one shard per family', () => {
    expect(shardDefs(ds).map((s) => [s.name, s.defs.length])).toEqual([['alpha', 2], ['beta', 3], ['gamma', 1]]);
  });
  it('refuses a size that is not a positive integer', () => {
    for (const bad of [0, -1, 1.5, NaN, Infinity]) expect(codeMsg(() => shardDefs(ds, bad))).toEqual(['bad_shard_size', 'the shard size must be a positive integer']);
  });
});

describe('packDefs', () => {
  const sh = (name: string, defs: unknown[], over: Record<string, unknown> = {}): PackShard => ({ v: 1, kind: PACK_SHARD_KIND, ns: 'acme', version: '1.0.0', name, defs, ...over }) as unknown as PackShard;
  const packOf = (shards: PackShard[]): ActionPack => ({ ...base, defs: { shards: shards.map((s) => ({ name: s.name, digest: shardDigest(s), uri: `u/${s.name}` })) } }) as unknown as ActionPack;
  const byName = (shards: PackShard[]) => Object.fromEntries(shards.map((s) => [s.name, s]));
  it('gathers the shards and sorts all defs by verb', () => {
    const shards = [sh('one', [{ verb: 'm.f' }, { verb: 'm.d' }]), sh('two', [{ verb: 'm.e' }, { verb: 'm.a' }]), sh('three', [{ verb: 'm.c' }, { verb: 'm.b' }])];
    expect(packDefs(packOf(shards), byName(shards)).map((d) => d.verb)).toEqual(['m.a', 'm.b', 'm.c', 'm.d', 'm.e', 'm.f']);
  });
  it('keeps defs of an equal verb in shard order', () => {
    const shards = [sh('x', [{ verb: 'm.k', n: 1 }]), sh('y', [{ verb: 'm.k', n: 2 }]), sh('z', [{ verb: 'm.a', n: 3 }])];
    expect(packDefs(packOf(shards), byName(shards))).toEqual([{ verb: 'm.a', n: 3 }, { verb: 'm.k', n: 1 }, { verb: 'm.k', n: 2 }]);
  });
  it('an inline pack returns a copy of its defs', () => {
    const out = packDefs(base);
    expect(out).toEqual(defs3);
    expect(out).not.toBe(base.defs);
  });
  it('a missing shard is a typed error', () => {
    const shards = [sh('one', [{ verb: 'm.a' }])];
    expect(codeMsg(() => packDefs(packOf(shards), {}))).toEqual(['missing_shard', "shard 'one' was not supplied"]);
    expect(codeMsg(() => packDefs(packOf(shards)))).toEqual(['missing_shard', "shard 'one' was not supplied"]);
  });
  it('a shard that does not match its digest is a typed error', () => {
    const shards = [sh('one', [{ verb: 'm.a' }])];
    const forged = { one: sh('one', [{ verb: 'm.b' }]) };
    expect(codeMsg(() => packDefs(packOf(shards), forged))).toEqual(['shard_digest_mismatch', "shard 'one' does not match its digest"]);
  });
  it('a shard whose own header is not this pack is refused, one field at a time', () => {
    const bad: Record<string, unknown>[] = [{ v: 2 }, { kind: 'other' }, { ns: 'other' }, { version: '9.9.9' }, { name: 'zzz' }, { defs: 'nope' }];
    for (const over of bad) {
      const s = sh('one', [{ verb: 'm.a' }], over);
      const p = { ...packOf([sh('one', [])]), defs: { shards: [{ name: 'one', digest: shardDigest(s), uri: 'u/one' }] } } as unknown as ActionPack;
      expect(codeMsg(() => packDefs(p, { one: s })), JSON.stringify(over)).toEqual(['bad_shard', "shard 'one' is not a shard of this pack"]);
    }
  });
});

describe('packShapeError', () => {
  it('accepts a built pack, signed and unsigned', () => {
    expect(packShapeError(base)).toBeNull();
    expect(shapeU(() => {})).toBeNull();
    expect(packShapeError(sharded.pack)).toBeNull();
    for (const stability of ['draft', 'beta', 'stable']) expect(shapeU((b) => { b.stability = stability; })).toBeNull();
  });
  it('refuses a non-object', () => {
    for (const x of [null, undefined, 5, 'x', [], [1]]) expect(packShapeError(x)).toBe('pack must be an object');
  });
  it('closes the member set; only a signed pack may carry sig', () => {
    expect(shapeU((b) => { b.zzz = 1; })).toBe("pack: unknown member 'zzz'");
    expect(shapeU((b) => { b['Stryker was here'] = 1; })).toBe("pack: unknown member 'Stryker was here'");
    expect(shapeU((b) => { b.sig = clone(base.sig); })).toBe("pack: unknown member 'sig'");
    expect(shapeS((p) => { p.zzz = 1; })).toBe("pack: unknown member 'zzz'");
  });
  it('checks v and kind independently', () => {
    expect(shapeU((b) => { b.v = 2; })).toBe('pack: bad v/kind');
    expect(shapeU((b) => { b.kind = 'other'; })).toBe('pack: bad v/kind');
  });
  it('checks ns, including a non-string that prints like a valid one', () => {
    for (const ns of [5, ['acme'], 'Bad NS', '', 'a..b']) expect(shapeU((b) => { b.ns = ns; }), String(ns)).toBe('pack: bad ns');
  });
  it('checks version, including a non-string that prints like a valid one', () => {
    for (const v of [['1.0.0'], '1.0', 5, '1.0.0-rc1', '01.0.0']) expect(shapeU((b) => { b.version = v; }), String(v)).toBe('pack: version must be MAJOR.MINOR.PATCH');
  });
  it('checks stability', () => {
    for (const s of ['nope', 5, undefined, ['stable']]) expect(shapeU((b) => { b.stability = s; })).toBe('pack: bad stability');
  });
  it('checks each of the four digests', () => {
    for (const k of ['traits_digest', 'roles_digest', 'rules_digest', 'root']) {
      for (const v of [5, 'short', ['A'.repeat(43)], 'A'.repeat(44), '!'.repeat(43)]) expect(shapeU((b) => { b[k] = v; }), `${k} ${String(v)}`).toBe(`pack: ${k} must be a base64url digest`);
    }
  });
  it('checks prev: null is the first version, anything else is a digest', () => {
    expect(shapeU((b) => { b.prev = null; })).toBeNull();
    expect(shapeU((b) => { b.prev = 'A'.repeat(43); })).toBeNull();
    for (const v of [5, 'short', ['A'.repeat(43)], undefined]) expect(shapeU((b) => { b.prev = v; }), String(v)).toBe('pack: bad prev');
  });
  it('checks the source object', () => {
    const msg = 'pack: source must be {kind, uri, spec_digest, licence, licence_notes}';
    for (const s of [5, null, [], 'x']) expect(shapeU((b) => { b.source = s; })).toBe(msg);
    expect(shapeU((b) => { b.source.extra = 'x'; })).toBe(msg);
  });
  it('checks every source member: non-empty strings up to 2048 characters, licence_notes may be empty', () => {
    for (const k of ['kind', 'uri', 'spec_digest', 'licence', 'licence_notes']) {
      const msg = `pack: source.${k} is not a string of 1..2048 characters`;
      expect(shapeU((b) => { b.source[k] = 'x'.repeat(2049); }), k).toBe(msg);
      expect(shapeU((b) => { b.source[k] = 5; }), k).toBe(msg);
      expect(shapeU((b) => { b.source[k] = ['x']; }), k).toBe(msg);
      expect(shapeU((b) => { delete b.source[k]; }), k).toBe(msg);
      expect(shapeU((b) => { b.source[k] = 'x'.repeat(2048); }), k).toBeNull();
    }
    for (const k of ['kind', 'uri', 'spec_digest', 'licence']) expect(shapeU((b) => { b.source[k] = ''; }), k).toBe(`pack: source.${k} is not a string of 1..2048 characters`);
    expect(shapeU((b) => { b.source.licence_notes = ''; })).toBeNull();
  });
  it('checks inline defs: count, validity, order and uniqueness', () => {
    const cnt = `pack: inline defs must number 1..${MAX_PACK_DEFS} (larger packs are sharded)`;
    expect(shapeU((b) => { b.defs = []; })).toBe(cnt);
    expect(shapeU((b) => { b.defs = new Array(MAX_PACK_DEFS + 1).fill(alphaGet); })).toBe(cnt);
    // exactly the limit is not a count error (the repeated def is then a duplicate)
    expect(shapeU((b) => { b.defs = new Array(MAX_PACK_DEFS).fill(alphaGet); })).toBe("pack: defs must be sorted by verb and unique (at 'acme.alpha.get')");
    expect(validateDef(patchDef(alphaGet, (x) => { x.v = 2; }))).toBe('unsupported def version');
    expect(shapeU((b) => { b.defs[1].v = 2; })).toBe('pack: def 1: unsupported def version');
    expect(shapeU((b) => { b.defs[0].v = 2; })).toBe('pack: def 0: unsupported def version');
    expect(shapeU((b) => { b.defs.reverse(); })).toBe("pack: defs must be sorted by verb and unique (at 'acme.alpha.put')");
    expect(shapeU((b) => { b.defs.splice(1, 0, clone(b.defs[0])); })).toBe("pack: defs must be sorted by verb and unique (at 'acme.alpha.get')");
  });
  it('checks the shard list', () => {
    const msg = 'pack: defs must be a list of defs or {shards}';
    for (const d of [5, null, 'x', {}, { shards: [] }, { shards: 5 }, { shards: {} }, { shards: [{}], extra: 1 }]) expect(shapeU((b) => { b.defs = d; }), JSON.stringify(d)).toBe(msg);
    expect(shapeU((b) => { b.defs = { shards: new Array(4097).fill({}) }; })).toBe(msg);
    // exactly the limit passes the count test (the empty refs then fail on the name)
    expect(shapeU((b) => { b.defs = { shards: new Array(4096).fill({}) }; })).toBe('pack: shard names must be distinct simple names');
  });
  it('checks every shard ref', () => {
    const sp = sharded.pack;
    expect(shapeS((p) => { p.defs.shards[0] = 5; }, sp)).toBe('pack: bad shard ref');
    expect(shapeS((p) => { p.defs.shards[0].extra = 1; }, sp)).toBe('pack: bad shard ref');
    const nm = 'pack: shard names must be distinct simple names';
    for (const n of [['alpha-1'], 5, 'Bad Name', '', 'a b']) expect(shapeS((p) => { p.defs.shards[0].name = n; }, sp), String(n)).toBe(nm);
    expect(shapeS((p) => { p.defs.shards[1].name = p.defs.shards[0].name; }, sp)).toBe(nm);
    expect(shapeS((p) => { p.defs.shards[2].name = p.defs.shards[0].name; }, sp)).toBe(nm);
    const du = 'pack: bad shard digest or uri';
    for (const v of [5, 'short', ['A'.repeat(43)], 'A'.repeat(44)]) expect(shapeS((p) => { p.defs.shards[0].digest = v; }, sp), String(v)).toBe(du);
    for (const v of [5, '', 'x'.repeat(2049), ['u'], undefined]) expect(shapeS((p) => { p.defs.shards[0].uri = v; }, sp), String(v)).toBe(du);
    expect(shapeS((p) => { p.defs.shards[0].uri = 'x'.repeat(2048); }, sp)).toBeNull();
    expect(shapeS((p) => { delete p.defs.shards[0].digest; }, sp)).toBe(du);
  });
  it('checks the evolution list', () => {
    const msg = 'pack: evolution must be a list of records';
    for (const v of ['x', null, {}, undefined, 5]) expect(shapeU((b) => { b.evolution = v; })).toBe(msg);
    expect(shapeU((b) => { b.evolution = new Array(MAX_EVOLUTION_RECORDS + 1).fill(0); })).toBe(msg);
    expect(shapeU((b) => { b.evolution = new Array(MAX_EVOLUTION_RECORDS).fill(0); })).toBe('pack: evolution record must be an object');
    expect(shapeU((b) => { b.evolution = [5]; })).toBe('pack: evolution record must be an object');
    expect(shapeU((b) => { b.evolution = []; })).toBeNull();
  });
  it('checks the signature object of a signed pack', () => {
    for (const s of [5, undefined, null, [], 'x']) expect(shapeS((p) => { p.sig = s; })).toBe('pack: bad sig');
    expect(shapeS((p) => { p.sig.extra = 1; })).toBe('pack: bad sig');
    for (const k of ['kid', 'value', 'alg']) expect(shapeS((p) => { p.sig[k] = 5; }), k).toBe('pack: bad sig');
    expect(shapeS((p) => { p.sig.pq_value = 'abc'; })).toBeNull();
  });
  it('requires strict canonical form and never throws', () => {
    const e = shapeU((b) => { b.source.licence_notes = '\ud800'; });
    expect(e).toMatch(/^pack: .+/);
    expect(e).toMatch(/surrogate/);
    const e2 = shapeS((p) => { p.source.licence_notes = '\ud800'; });
    expect(e2).toMatch(/^pack: .+surrogate/);
  });
});

describe('buildPack', () => {
  it('refuses invalid, unsorted-equal and empty def sets with typed errors', () => {
    expect(codeMsg(() => mk([patchDef(alphaGet, (x) => { x.v = 2; })], '1.0.0'))).toEqual(['bad_pack', 'def 0: unsupported def version']);
    expect(codeMsg(() => mk([alphaGet, clone(alphaGet)], '1.0.0'))).toEqual(['bad_pack', "defs must be sorted by verb and unique (at 'acme.alpha.get')"]);
    // two defs of one verb: the builder sort keeps their given order, so the valid one is checked first
    expect(codeMsg(() => mk([alphaGet, patchDef(alphaGet, (x) => { x.v = 2; })], '1.0.0'))).toEqual(['bad_pack', 'def 1: unsupported def version']);
    expect(codeMsg(() => mk([], '1.0.0'))).toEqual(['empty_pack', 'a pack has at least one def']);
  });
  it('sorts the given defs by verb', () => {
    const p = mk([betaGet, alphaPut, alphaGet], '1.0.0').pack;
    expect((p.defs as ActionDef[]).map((d) => d.verb)).toEqual(['acme.alpha.get', 'acme.alpha.put', 'acme.beta.get']);
  });
  it('checks the chain: same namespace, strictly increasing version', () => {
    const o = mk(defs3, '1.0.0', undefined, { ns: 'other' });
    expect(codeMsg(() => mk(defs3, '2.0.0', { pack: o.pack }))).toEqual(['bad_chain', 'the previous pack is of another namespace']);
    expect(codeMsg(() => mk(defs3, '1.0.0', { pack: base }))).toEqual(['bad_chain', 'the version must increase']);
    expect(codeMsg(() => mk(defs3, '0.9.0', { pack: base }))).toEqual(['bad_chain', 'the version must increase']);
    const next = mk(defs3, '1.0.1', { pack: base }).pack;
    expect(next.prev).toBe(packDigest(base));
    expect(next.evolution).toEqual([]);
  });
  it('refuses a pack whose own shape is invalid', () => {
    expect(codeMsg(() => mk(defs3, '1.0.0', undefined, { stability: 'zzz' as never }))).toEqual(['bad_pack', 'pack: bad stability']);
    expect(codeMsg(() => mk(defs3, '1.0', undefined))).toEqual(['bad_pack', 'pack: version must be MAJOR.MINOR.PATCH']);
    expect(codeMsg(() => mk(defs3, '1.0.0', undefined, { source: { ...SRC, uri: '' } }))).toEqual(['bad_pack', 'pack: source.uri is not a string of 1..2048 characters']);
  });
  it('an inline pack carries its defs, the added records and a verifiable signature', () => {
    expect(base.defs).toEqual(defs3);
    expect(base.prev).toBeNull();
    expect(base.evolution.map((r) => [r.verb, r.class, r.from, r.to])).toEqual(defs3.map((d) => [d.verb, 'added', null, defDigest(d)]));
    expect(verifyActionPack(base, KEYS)).toEqual({ ok: true, defs: defs3, digest: packDigest(base) });
  });
  it('shard: false and an omitted shard keep a small pack inline; shard: true shards it', () => {
    const off = mk(defs3, '1.0.0', undefined, { shard: false });
    expect(Array.isArray(off.pack.defs)).toBe(true);
    expect(off.shards).toEqual({});
    const on = mk(defs3, '1.0.0', undefined, { shard: true });
    expect(Array.isArray(on.pack.defs)).toBe(false);
    expect(Object.keys(on.shards)).toEqual(['alpha', 'beta']);
    expect((on.pack.defs as { shards: unknown[] }).shards).toEqual([
      { name: 'alpha', digest: shardDigest(on.shards.alpha!), uri: 'shards/alpha.json' },
      { name: 'beta', digest: shardDigest(on.shards.beta!), uri: 'shards/beta.json' },
    ]);
    expect(on.shards.alpha).toEqual({ v: 1, kind: PACK_SHARD_KIND, ns: 'acme', version: '1.0.0', name: 'alpha', defs: [alphaGet, alphaPut] });
    expect(verifyActionPack(on.pack, KEYS, { shards: on.shards })).toEqual({ ok: true, defs: defs3, digest: packDigest(on.pack) });
  });
  it('shard options set the size and the uri of each shard', () => {
    expect(Object.keys(sharded.shards)).toEqual(['alpha-1', 'alpha-2', 'beta']);
    expect((sharded.pack.defs as { shards: unknown[] }).shards).toEqual([
      { name: 'alpha-1', digest: shardDigest(sharded.shards['alpha-1']!), uri: 'mem://alpha-1' },
      { name: 'alpha-2', digest: shardDigest(sharded.shards['alpha-2']!), uri: 'mem://alpha-2' },
      { name: 'beta', digest: shardDigest(sharded.shards.beta!), uri: 'mem://beta' },
    ]);
    expect(sharded.shards['alpha-2']!.defs).toEqual([alphaPut]);
    const objOnly = mk(defs3, '1.0.0', undefined, { shard: {} });
    expect(Object.keys(objOnly.shards)).toEqual(['alpha', 'beta']);
  });
  it('a pack of exactly the inline limit stays inline', () => {
    const many = Array.from({ length: MAX_PACK_DEFS }, (_, i) => mkDef(`acme.bulk.n${String(i).padStart(4, '0')}`, 'bulk'));
    const b = mk(many, '1.0.0');
    expect(Array.isArray(b.pack.defs)).toBe(true);
    expect((b.pack.defs as ActionDef[]).length).toBe(MAX_PACK_DEFS);
    expect(b.shards).toEqual({});
  }, 300_000);
  it('the review options reach the computed evolution', () => {
    // a confirmed def edited to an unconfirmed one: the digest changes, and only a verifier-checked confirmation makes that a narrowing
    const edited = { ...patchDef(refund, (x) => { x.title = 'Refund a payment'; }), review: { state: 'authored' as const } } as ActionDef;
    const v1 = mk([confirmed(refund)], '1.0.0', undefined, { ns: 'stripe' }).pack;
    const withReview = mk([edited], '1.1.0', { pack: v1 }, { ns: 'stripe', review: testReview() }).pack;
    const without = mk([edited], '1.1.0', { pack: v1 }, { ns: 'stripe' }).pack;
    expect(withReview.evolution.map((r) => r.class)).toEqual(['narrow']);
    expect(without.evolution.map((r) => r.class)).toEqual(['equal']);
  });
});

describe('verifyActionPack', () => {
  const v = (p: unknown, o?: Parameters<typeof verifyActionPack>[2]) => verifyActionPack(p, KEYS, o);
  it('returns the shape error for a malformed pack', () => {
    expect(v(5)).toEqual({ ok: false, reason: 'pack must be an object' });
    expect(v({ ...clone(base), v: 2 })).toEqual({ ok: false, reason: 'pack: bad v/kind' });
  });
  it('names the signature failure', () => {
    const t = clone(base) as any;
    t.root = 'C'.repeat(43);
    expect(v(t)).toEqual({ ok: false, reason: 'pack signature: signature invalid' });
    expect(verifyActionPack(base, [])).toEqual({ ok: false, reason: "pack signature: no registry key with kid 'reg-1'" });
  });
  it('names each vocabulary digest mismatch', () => {
    const creg = extendRegistry(CORE_REGISTRY, [{ id: 'acme.strict', implies: ['pca.money_moving'], floor: { ...CORE_REGISTRY.traits.get('pca.money_moving')!.floor, esc: 3 }, card_phrase: 'is stricter' }]);
    expect(v(base, { reg: creg })).toEqual({ ok: false, reason: 'traits_digest does not match the trait registry' });
    expect(v(resign(base, (b) => { b.roles_digest = 'C'.repeat(43); }))).toEqual({ ok: false, reason: 'roles_digest does not match the vocabulary tables' });
    expect(v(resign(base, (b) => { b.rules_digest = 'C'.repeat(43); }))).toEqual({ ok: false, reason: 'rules_digest does not match the rule tables' });
  });
  it('reports shard problems with the shard error message', () => {
    expect(v(sharded.pack)).toEqual({ ok: false, reason: "shard 'alpha-1' was not supplied" });
    const altered = clone(sharded.shards);
    altered['alpha-1']!.defs[0]!.title = 'Altered';
    expect(v(sharded.pack, { shards: altered })).toEqual({ ok: false, reason: "shard 'alpha-1' does not match its digest" });
    expect(v(sharded.pack, { shards: sharded.shards })).toEqual({ ok: true, defs: defs3, digest: packDigest(sharded.pack) });
  });
  it('validates the gathered defs', () => {
    const shards = clone(sharded.shards);
    (shards['alpha-1']!.defs[0] as any).v = 2;
    const p = resign(sharded.pack, (b) => { b.defs.shards[0].digest = shardDigest(shards['alpha-1']!); });
    expect(v(p, { shards })).toEqual({ ok: false, reason: 'def 0: unsupported def version' });
  });
  it('refuses a pack that lists no defs', () => {
    const empty: PackShard = { v: 1, kind: PACK_SHARD_KIND, ns: 'acme', version: '1.0.0', name: 'e', defs: [] };
    const p = resign(sharded.pack, (b) => { b.defs = { shards: [{ name: 'e', digest: shardDigest(empty), uri: 'x' }] }; });
    expect(v(p, { shards: { e: empty } })).toEqual({ ok: false, reason: 'the pack lists no defs or too many' });
  });
  it('recomputes the Merkle root', () => {
    expect(v(resign(base, (b) => { b.root = 'C'.repeat(43); }))).toEqual({ ok: false, reason: 'the Merkle root does not match the defs' });
  });
  it('checks every evolution record: signature, namespace and the def it names', () => {
    expect(v(resign(base, (b) => { b.evolution = [rec({}, other.secretKey)]; }))).toEqual({ ok: false, reason: 'evolution record: signature invalid' });
    expect(v(resign(base, (b) => { b.evolution = [rec({ ns: 'other' })]; }))).toEqual({ ok: false, reason: 'evolution record of another namespace' });
    expect(v(resign(base, (b) => { b.evolution = [rec({ to: 'Z'.repeat(43) })]; }))).toEqual({ ok: false, reason: "evolution record for 'acme.alpha.get' names a definition that is not in the pack" });
    // a removed record names no def of this pack and is fine
    const ok = resign(base, (b) => { b.evolution = [rec({ verb: 'acme.gone.one', from: 'Y'.repeat(43), to: null, class: 'removed' }), rec({})]; });
    expect(v(ok)).toEqual({ ok: true, defs: defs3, digest: packDigest(ok) });
  });
  it('never throws: an unusable registry is a verification error', () => {
    const r = v(base, { reg: {} as never });
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/^pack verification error: .+/);
  });
});

describe('verifyUpgrade', () => {
  const v1 = mk(stripe, '1.0.0', undefined, { ns: 'stripe' }).pack;
  const rest = stripe.filter((d) => d.verb !== refund.verb);
  const narrowRefund = patchDef(refund, (x) => { x.params.amount.max = 5000; });
  const v2 = mk([narrowRefund, ...rest], '1.1.0', { pack: v1 }, { ns: 'stripe' }).pack;
  it('accepts a chained upgrade whose evolution is exactly the computed change', () => {
    expect(v2.evolution.map((r) => r.class)).toEqual(['narrow']);
    expect(verifyUpgrade(v1, v2, KEYS)).toEqual({ ok: true });
  });
  it('names which pack failed to verify', () => {
    expect(verifyUpgrade(5 as never, v2, KEYS)).toEqual({ ok: false, reason: 'previous pack: pack must be an object' });
    expect(verifyUpgrade(v1, 5 as never, KEYS)).toEqual({ ok: false, reason: 'pack: pack must be an object' });
  });
  it('refuses another namespace, a chain gap and a version that does not increase', () => {
    const o = mk(stripe, '1.1.0', undefined, { ns: 'other' }).pack;
    expect(verifyUpgrade(v1, o, KEYS)).toEqual({ ok: false, reason: 'the packs are of different namespaces' });
    const gap = mk([narrowRefund, ...rest], '1.1.0', undefined, { ns: 'stripe' }).pack;
    expect(verifyUpgrade(v1, gap, KEYS)).toEqual({ ok: false, reason: 'chain gap: prev does not name the previous pack' });
    for (const ver of ['1.0.0', '0.9.0']) expect(verifyUpgrade(v1, resign(v2, (b) => { b.version = ver; }), KEYS)).toEqual({ ok: false, reason: 'the version does not increase' });
  });
  it('reports a signed evolution that is not the computed change', () => {
    const lie = resign(v2, (b) => {
      b.evolution = b.evolution.map((r: any) => signEvolutionRecord({ v: 1, kind: r.kind, ns: r.ns, verb: r.verb, from: r.from, to: r.to, class: 'widen', reasons: [] }, 'reg-1', reg.secretKey));
    });
    expect(verifyUpgrade(v1, lie, KEYS)).toEqual({ ok: false, reason: 'evolution records do not match the computed change (a missing, extra or mis-classified record)' });
    const dropped = resign(v2, (b) => { b.evolution = []; });
    expect(verifyUpgrade(v1, dropped, KEYS)).toEqual({ ok: false, reason: 'evolution has 0 records, the change needs 1' });
  });
  it('threads the shard contents of both packs through verification', () => {
    const s1 = mk(defs3, '1.0.0', undefined, { shard: { max: 1 } });
    const s2 = mk([...defs3, betaPut], '1.1.0', { pack: s1.pack, shards: s1.shards }, { shard: { max: 1 } });
    expect(verifyUpgrade(s1.pack, s2.pack, KEYS, { prevShards: s1.shards, shards: s2.shards })).toEqual({ ok: true });
    expect(verifyUpgrade(s1.pack, s2.pack, KEYS, { shards: s2.shards })).toEqual({ ok: false, reason: "previous pack: shard 'alpha-1' was not supplied" });
    expect(verifyUpgrade(s1.pack, s2.pack, KEYS, { prevShards: s1.shards })).toEqual({ ok: false, reason: "pack: shard 'alpha-1' was not supplied" });
  });
  it('threads a custom trait registry through verification and the evolution check', () => {
    const creg = extendRegistry(CORE_REGISTRY, [{ id: 'acme.strict', implies: ['pca.money_moving'], floor: { ...CORE_REGISTRY.traits.get('pca.money_moving')!.floor, esc: 3 }, card_phrase: 'is stricter' }]);
    const c1 = mk([refund], '1.0.0', undefined, { ns: 'stripe', reg: creg }).pack;
    const stricter = patchDef(refund, (x) => { x.traits = [...(x.traits ?? []), 'acme.strict']; });
    const c2 = mk([stricter], '1.1.0', { pack: c1 }, { ns: 'stripe', reg: creg }).pack;
    expect(verifyUpgrade(c1, c2, KEYS, { reg: creg })).toEqual({ ok: true });
    expect(verifyUpgrade(c1, c2, KEYS).ok).toBe(false);
  });
  it('threads the review options through the evolution check', () => {
    const edited = { ...patchDef(refund, (x) => { x.title = 'Refund a payment'; }), review: { state: 'authored' as const } } as ActionDef;
    const e1 = mk([confirmed(refund)], '1.0.0', undefined, { ns: 'stripe' }).pack;
    const e2 = mk([edited], '1.1.0', { pack: e1 }, { ns: 'stripe', review: testReview() }).pack;
    expect(verifyUpgrade(e1, e2, KEYS, { review: testReview() })).toEqual({ ok: true });
    expect(verifyUpgrade(e1, e2, KEYS)).toEqual({ ok: false, reason: 'evolution records do not match the computed change (a missing, extra or mis-classified record)' });
  });
});
