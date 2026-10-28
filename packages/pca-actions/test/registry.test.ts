import { generateKeyPairSync } from 'node:crypto';
import { generateKeyPair } from '@atlasauth/pca';
import { registryKeyOf, signEvolutionRecord } from '@atlasauth/pca/ext/intent';
import { TransparencyService } from '@atlasauth/pca-scitt/testing';
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_DEFS, MAX_PACK_DEFS, PackTracker, appendPackToLog, buildPack, compareVersions, defDigest, evolutionError, evolutionRecords, packDefs, packDigest, packProof, packRoot, packShapeError, packStatementPayload,
  shardDefs, validateDef, verifyActionPack as verifyPack, verifyPackLogEntry, verifyPackProof, verifyUpgrade, type ActionDef, type ActionPack,
} from '../src';
import { genDef, rng } from './vectors-gen';

const reg = generateKeyPair();
const other = generateKeyPair();
const KEYS = [registryKeyOf('reg-1', reg.secretKey)];
const SRC = { kind: 'hand', uri: 'internal://pack', spec_digest: 'A'.repeat(43), licence: 'Apache-2.0', licence_notes: 'authored in house' };
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const stripe = BUILTIN_DEFS.filter((d) => d.verb.startsWith('stripe.'));
const mk = (defs: readonly ActionDef[], version: string, prev?: ActionPack, extra: Partial<Parameters<typeof buildPack>[0]> = {}) =>
  buildPack({ ns: 'stripe', version, stability: 'stable', defs, source: SRC, kid: 'reg-1', secret: reg.secretKey, ...(prev ? { prev: { pack: prev } } : {}), ...extra });
const patchDef = (d: ActionDef, f: (x: Record<string, any>) => void): ActionDef => {
  const c = clone(d) as unknown as Record<string, any>;
  f(c);
  return c as ActionDef;
};

describe('signed packs', () => {
  const { pack } = mk(stripe, '1.0.0');
  it('a built pack verifies and returns its defs and digest', () => {
    const v = verifyPack(pack, KEYS);
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.defs.map((d) => d.verb)).toEqual([...stripe.map((d) => d.verb)].sort());
      expect(v.digest).toBe(packDigest(pack));
    }
    expect(pack.root).toBe(packRoot(stripe.map(defDigest)));
    expect(pack.prev).toBeNull();
    expect(pack.evolution.every((r) => r.class === 'added')).toBe(true);
  });
  it('rejects a changed def, a changed root, a swapped key and an unknown kid', () => {
    const t1 = clone(pack) as any;
    t1.defs[0].title = 'Tampered title';
    expect(verifyPack(t1, KEYS).ok).toBe(false);
    const t2 = clone(pack) as any;
    t2.root = 'B'.repeat(43);
    expect(verifyPack(t2, KEYS).ok).toBe(false);
    expect(verifyPack(pack, [registryKeyOf('reg-1', other.secretKey)]).ok).toBe(false);
    expect(verifyPack(pack, [registryKeyOf('reg-2', reg.secretKey)]).ok).toBe(false);
    expect(verifyPack(pack, []).ok).toBe(false);
  });
  it('rejects a downgraded suite claim, unknown members, unsorted or duplicate defs, and bad vocabulary digests', () => {
    const t1 = clone(pack) as any;
    t1.sig.alg = 'ml-dsa-65';
    expect(verifyPack(t1, KEYS).ok).toBe(false);
    const t2 = clone(pack) as any;
    t2.extra = 1;
    expect(packShapeError(t2)).toMatch(/unknown member/);
    const t3 = clone(pack) as any;
    t3.defs.reverse();
    expect(packShapeError(t3)).toMatch(/sorted/);
    const t4 = clone(pack) as any;
    t4.defs.push(clone(t4.defs[0]));
    expect(packShapeError(t4)).toMatch(/sorted by verb and unique/);
    for (const k of ['traits_digest', 'roles_digest', 'rules_digest']) {
      const t = clone(pack) as any;
      t[k] = 'C'.repeat(43);
      expect(verifyPack(t, KEYS).ok, k).toBe(false);
    }
  });
  it('a pack signed over valid content but re-signed by another key is refused', () => {
    const { pack: forged } = buildPack({ ns: 'stripe', version: '1.0.0', stability: 'stable', defs: stripe, source: SRC, kid: 'reg-1', secret: other.secretKey });
    expect(verifyPack(forged, KEYS).ok).toBe(false);
  });
  it('compareVersions orders MAJOR.MINOR.PATCH numerically and refuses anything else', () => {
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
    expect(compareVersions('1.10.0', '1.9.9')).toBeGreaterThan(0);
    expect(compareVersions('0.9.9', '1.0.0')).toBeLessThan(0);
    expect(() => compareVersions('1.0', '1.0.0')).toThrow();
    expect(() => compareVersions('1.0.0-rc1', '1.0.0')).toThrow();
  });
});

describe('sharded packs and inclusion proofs', () => {
  const r = rng(0x5ead01);
  const many: ActionDef[] = [];
  while (many.length < 1300) {
    const d = genDef(r, many.length);
    if (validateDef(d) === null) many.push(d);
  }
  it('a pack above the inline limit is sharded automatically and verifies with its shards only', () => {
    const big: ActionDef[] = [];
    const rr = rng(0x5ead02);
    while (big.length < MAX_PACK_DEFS + 20) {
      const d = genDef(rr, big.length);
      if (validateDef(d) === null) big.push(d);
    }
    const { pack, shards } = mk(big, '1.0.0', undefined, { ns: 'gen' } as never);
    expect(Array.isArray(pack.defs)).toBe(false);
    expect(Object.keys(shards).length).toBeGreaterThan(1);
    expect(verifyPack(pack, KEYS, { shards }).ok).toBe(true);
    expect(verifyPack(pack, KEYS).ok).toBe(false);
  }, 120_000);
  it('verifies across shards; a missing, altered or foreign shard is refused', () => {
    const { pack, shards } = mk(many, '1.0.0', undefined, { shard: { max: 100 } });
    expect(Object.keys(shards).length).toBeGreaterThan(5);
    expect(verifyPack(pack, KEYS, { shards }).ok).toBe(true);
    const names = Object.keys(shards);
    const missing = { ...shards };
    delete missing[names[0]!];
    expect(verifyPack(pack, KEYS, { shards: missing }).ok).toBe(false);
    const altered = clone(shards);
    altered[names[1]!]!.defs[0]!.title = 'Altered';
    expect(verifyPack(pack, KEYS, { shards: altered }).ok).toBe(false);
    const foreign = clone(shards);
    foreign[names[2]!]!.version = '9.9.9';
    expect(verifyPack(pack, KEYS, { shards: foreign }).ok).toBe(false);
  }, 120_000);
  it('one inclusion proof shows a def belongs to the pack root, whatever the shard', () => {
    const { pack } = mk(many, '1.0.0', undefined, { shard: { max: 100 } });
    const digests = many.map(defDigest);
    for (const i of [0, 1, 99, 100, 777, many.length - 1]) {
      const proof = packProof(digests, digests[i]!);
      expect(verifyPackProof(pack.root, proof, digests[i]!)).toBe(true);
      expect(verifyPackProof(pack.root, proof, digests[(i + 1) % digests.length]!)).toBe(false);
    }
  });
  it('shardDefs groups by resource family and splits a large family in order', () => {
    const s = shardDefs(many, 100);
    expect(s.reduce((n, x) => n + x.defs.length, 0)).toBe(many.length);
    expect(s.every((x) => x.defs.length <= 100)).toBe(true);
    expect(new Set(s.map((x) => x.name)).size).toBe(s.length);
    expect(() => shardDefs(many, 0)).toThrow();
  });
});

describe('hash chain and signed evolution', () => {
  const v1 = mk(stripe, '1.0.0').pack;
  const refund = stripe.find((d) => d.verb === 'stripe.refund')!;
  const charge = stripe.find((d) => d.verb === 'stripe.charge')!;
  const narrowRefund = patchDef(refund, (x) => { x.params.amount.max = 5000; });
  const widenRefund = patchDef(refund, (x) => { x.params.amount.max = 999_999_999_999; });
  const next = (defs: ActionDef[], version = '1.1.0', prev = v1) => mk(defs, version, prev).pack;

  it('an upgrade chains prev, increases the version and signs exactly the computed change', () => {
    const v2 = next([narrowRefund, ...stripe.filter((d) => d.verb !== refund.verb)]);
    expect(v2.prev).toBe(packDigest(v1));
    expect(v2.evolution).toHaveLength(1);
    expect(v2.evolution[0]).toMatchObject({ verb: 'stripe.refund', class: 'narrow', from: defDigest(refund), to: defDigest(narrowRefund) });
    expect(verifyUpgrade(v1, v2, KEYS)).toEqual({ ok: true });
  });
  it('records added and removed verbs, and classifies a widening as widen', () => {
    const extra: ActionDef = patchDef(charge, (x) => { x.verb = 'stripe.charge.extra'; });
    const v2 = next([widenRefund, extra, ...stripe.filter((d) => d.verb !== refund.verb && d.verb !== charge.verb)]);
    const by = Object.fromEntries(v2.evolution.map((r) => [r.verb, r.class]));
    expect(by).toMatchObject({ 'stripe.refund': 'widen', 'stripe.charge.extra': 'added', 'stripe.charge': 'removed' });
    expect(verifyUpgrade(v1, v2, KEYS)).toEqual({ ok: true });
  });
  it('rejects a chain gap, a non-increasing version and a different namespace', () => {
    const v2 = next([narrowRefund, ...stripe.filter((d) => d.verb !== refund.verb)]);
    const gap = clone(v2) as any;
    gap.prev = 'D'.repeat(43);
    expect(verifyUpgrade(v1, gap, KEYS).ok).toBe(false);
    const same = mk([narrowRefund, ...stripe.filter((d) => d.verb !== refund.verb)], '1.0.0').pack;
    expect(verifyUpgrade(v1, same, KEYS).ok).toBe(false);
    expect(() => mk([narrowRefund], '0.9.0', v1)).toThrow(/version must increase/);
  });
  it('a registry cannot sign narrow for a widening, drop a record, or add an extra one', () => {
    const defs2 = [widenRefund, ...stripe.filter((d) => d.verb !== refund.verb)];
    const truth = evolutionRecords('stripe', stripe, defs2);
    const lie = signEvolutionRecord({ ...truth[0]!, class: 'narrow' }, 'reg-1', reg.secretKey);
    expect(evolutionError('stripe', stripe, defs2, [lie], KEYS)).toMatch(/do not match/);
    expect(evolutionError('stripe', stripe, defs2, [], KEYS)).toMatch(/needs 1/);
    const ok = signEvolutionRecord(truth[0]!, 'reg-1', reg.secretKey);
    expect(evolutionError('stripe', stripe, defs2, [ok], KEYS)).toBeNull();
    const extra = signEvolutionRecord({ ...truth[0]!, verb: 'stripe.other.thing' }, 'reg-1', reg.secretKey);
    expect(evolutionError('stripe', stripe, defs2, [ok, extra], KEYS)).toMatch(/needs 1/);
    const wrongKey = signEvolutionRecord(truth[0]!, 'reg-1', other.secretKey);
    expect(evolutionError('stripe', stripe, defs2, [wrongKey], KEYS)).toMatch(/signature invalid/);
  });
  it('a pack whose evolution lies about a widening fails verifyUpgrade', () => {
    const defs2 = [widenRefund, ...stripe.filter((d) => d.verb !== refund.verb)];
    const good = next(defs2);
    const lie = clone(good) as any;
    lie.evolution = good.evolution.map((r) => signEvolutionRecord({ v: 1, kind: r.kind, ns: r.ns, verb: r.verb, from: r.from, to: r.to, class: 'narrow', reasons: [] }, 'reg-1', reg.secretKey));
    // re-sign the pack body so only the evolution is wrong
    const { pack: relied } = buildPack({ ns: 'stripe', version: '1.1.0', stability: 'stable', defs: defs2, source: SRC, kid: 'reg-1', secret: reg.secretKey, prev: { pack: v1 } });
    expect(verifyUpgrade(v1, relied, KEYS)).toEqual({ ok: true });
    expect(verifyUpgrade(v1, lie, KEYS).ok).toBe(false);
  });
});

describe('rollback, replay, fork and chain-gap negative controls', () => {
  const refund = stripe.find((d) => d.verb === 'stripe.refund')!;
  const rest = stripe.filter((d) => d.verb !== refund.verb);
  const v1 = mk(stripe, '1.0.0').pack;
  const v2 = mk([patchDef(refund, (x) => { x.params.amount.max = 5000; }), ...rest], '1.1.0', v1).pack;
  const v3 = mk([patchDef(refund, (x) => { x.params.amount.max = 4000; }), ...rest], '1.2.0', v2).pack;

  it('accepts first, same and upgrade in order', () => {
    const t = new PackTracker(KEYS);
    expect(t.accept(v1)).toEqual({ ok: true, status: 'first' });
    expect(t.accept(v1)).toEqual({ ok: true, status: 'same' });
    expect(t.accept(v2)).toEqual({ ok: true, status: 'upgrade' });
    expect(t.accept(v3)).toEqual({ ok: true, status: 'upgrade' });
    expect(t.snapshot()).toEqual([{ ns: 'stripe', version: '1.2.0', digest: packDigest(v3) }]);
  });
  it('refuses a rollback to an older signed pack', () => {
    const t = new PackTracker(KEYS);
    t.accept(v1);
    t.accept(v2);
    const r = t.accept(v1);
    expect(r).toMatchObject({ ok: false, code: 'rollback' });
  });
  it('refuses a fork: a second pack at an accepted version', () => {
    const t = new PackTracker(KEYS);
    t.accept(v1);
    t.accept(v2);
    const forkV2 = mk([patchDef(refund, (x) => { x.params.amount.max = 4999; }), ...rest], '1.1.0', v1).pack;
    expect(t.accept(forkV2)).toMatchObject({ ok: false, code: 'fork' });
  });
  it('refuses a chain gap: a newer pack that skips a version', () => {
    const t = new PackTracker(KEYS);
    t.accept(v1);
    expect(t.accept(v3)).toMatchObject({ ok: false, code: 'chain_gap' });
    expect(t.snapshot()[0]!.version).toBe('1.0.0');
  });
  it('refuses a forged pack and one with a lying evolution', () => {
    const t = new PackTracker(KEYS);
    t.accept(v1);
    const forged = clone(v2) as any;
    forged.defs[0].title = 'x';
    expect(t.accept(forged)).toMatchObject({ ok: false, code: 'bad_pack' });
    const lying = clone(v2) as any;
    lying.evolution = [];
    expect(t.accept(lying).ok).toBe(false);
  });
  it('survives a restart through snapshot and restore', () => {
    const a = new PackTracker(KEYS);
    a.accept(v1);
    a.accept(v2);
    const b = new PackTracker(KEYS);
    b.restore(a.snapshot());
    expect(b.accept(v1)).toMatchObject({ ok: false, code: 'rollback' });
    expect(b.accept(v3)).toEqual({ ok: true, status: 'upgrade' });
  });
});

describe('transparency log', () => {
  const log = generateKeyPairSync('ed25519');
  const registry = generateKeyPairSync('ed25519');
  const svc = new TransparencyService({ alg: 'EdDSA', key: log.privateKey, issuer: 'log' });
  const { pack } = mk(stripe, '1.0.0');
  it('appends a pack statement and verifies the receipt against the pinned keys and tree root', () => {
    const e = appendPackToLog(pack, svc, { alg: 'EdDSA', key: registry.privateKey, issuer: 'reg' });
    expect(verifyPackLogEntry(pack, e, { registry: registry.publicKey, log: log.publicKey }, svc.root)).toBe(true);
    expect(packStatementPayload(pack)).toMatchObject({ ns: 'stripe', version: '1.0.0', digest: packDigest(pack) });
  });
  it('refuses a receipt for another pack, a wrong log key, a wrong registry key and a wrong tree root', () => {
    const e = appendPackToLog(pack, svc, { alg: 'EdDSA', key: registry.privateKey, issuer: 'reg' });
    const refund = stripe.find((d) => d.verb === 'stripe.refund')!;
    const v2 = mk([patchDef(refund, (x) => { x.params.amount.max = 5000; }), ...stripe.filter((d) => d !== refund)], '1.1.0', pack).pack;
    expect(verifyPackLogEntry(v2, e, { registry: registry.publicKey, log: log.publicKey })).toBe(false);
    expect(verifyPackLogEntry(pack, e, { registry: registry.publicKey, log: generateKeyPairSync('ed25519').publicKey })).toBe(false);
    expect(verifyPackLogEntry(pack, e, { registry: generateKeyPairSync('ed25519').publicKey, log: log.publicKey })).toBe(false);
    expect(verifyPackLogEntry(pack, e, { registry: registry.publicKey, log: log.publicKey }, 'E'.repeat(43))).toBe(false);
  });
  it('packDefs of an inline pack is its defs and a sharded pack without shards throws', () => {
    expect(packDefs(pack)).toHaveLength(stripe.length);
    const { pack: sh } = mk(stripe, '1.0.0', undefined, { shard: true });
    expect(() => packDefs(sh)).toThrow(/missing_shard|was not supplied/);
  });
});
