import { generateKeyPairSync } from 'node:crypto';
import { generateKeyPair } from '@atlasauth/pca';
import { EVOLUTION_RECORD_KIND, registryKeyOf, signEvolutionRecord, signRegistryDoc } from '@atlasauth/pca/ext/intent';
import { CWT_SUB, HDR_CONTENT_TYPE, HDR_CWT_CLAIMS, decodeCoseSign1 } from '@atlasauth/pca-scitt';
import { TransparencyService } from '@atlasauth/pca-scitt/testing';
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_DEFS, CORE_REGISTRY, PACK_SIG_DOMAIN, PACK_STATEMENT_CONTENT_TYPE, PackTracker, appendPackToLog, buildPack, defDigest, evolutionError, evolutionRecords, extendRegistry, packDigest, packStatementPayload,
  profile, verifyPackLogEntry, type ActionDef, type ActionPack, type PackShard,
} from '../src';

const reg = generateKeyPair();
const KEYS = [registryKeyOf('reg-1', reg.secretKey)];
const SRC = { kind: 'hand', uri: 'internal://pack', spec_digest: 'A'.repeat(43), licence: 'Apache-2.0', licence_notes: 'authored in house' };
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const stripe = BUILTIN_DEFS.filter((d) => d.verb.startsWith('stripe.'));
const refund = stripe.find((d) => d.verb === 'stripe.refund')!;
const rest = stripe.filter((d) => d.verb !== refund.verb);
const patchRefund = (max: number): ActionDef => {
  const c = clone(refund) as unknown as Record<string, any>;
  c.params.amount.max = max;
  return c as ActionDef;
};
type BuildArgs = Parameters<typeof buildPack>[0];
const mk = (defs: readonly ActionDef[], version: string, over: Partial<BuildArgs> = {}) =>
  buildPack({ ns: 'stripe', version, stability: 'stable', defs, source: SRC, kid: 'reg-1', secret: reg.secretKey, ...over });
// a validly signed pack whose signed evolution is empty although the defs changed
const lying = (honest: ActionPack): ActionPack => {
  const { sig: _s, ...body } = clone(honest);
  const b = { ...body, evolution: [] };
  return { ...b, sig: signRegistryDoc(PACK_SIG_DOMAIN, b, 'reg-1', reg.secretKey) } as unknown as ActionPack;
};
const thrown = (f: () => unknown): unknown => {
  try {
    f();
  } catch (e) {
    return e;
  }
  return undefined;
};

describe('evolutionRecords', () => {
  const [lo, hi] = [...stripe].sort((a, b) => (a.verb < b.verb ? -1 : 1)) as [ActionDef, ActionDef];
  it('an added and a removed verb are whole records with no reasons, sorted by verb across both sides', () => {
    const recs = evolutionRecords('stripe', [hi], [lo]);
    expect(recs).toEqual([
      { v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'stripe', verb: lo.verb, from: null, to: defDigest(lo), class: 'added', reasons: [] },
      { v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'stripe', verb: hi.verb, from: defDigest(hi), to: null, class: 'removed', reasons: [] },
    ]);
    expect(evolutionRecords('stripe', [lo], [hi]).map((r) => r.verb)).toEqual([lo.verb, hi.verb]);
  });
  it('an unchanged def yields no record', () => {
    expect(evolutionRecords('stripe', stripe, stripe)).toEqual([]);
  });
  it('a verb listed twice on either side is refused with its code and message', () => {
    for (const [p, n] of [[[refund, refund], []], [[], [refund, refund]]] as ActionDef[][][]) {
      expect(thrown(() => evolutionRecords('stripe', p!, n!))).toMatchObject({ name: 'ActionKitError', code: 'duplicate_def', message: `verb '${refund.verb}' appears twice` });
    }
  });
});

describe('evolutionError', () => {
  it('a record of another namespace is named in the refusal', () => {
    const other = evolutionRecords('other', [], [refund]).map((r) => signEvolutionRecord(r, 'reg-1', reg.secretKey));
    expect(evolutionError('stripe', [], [refund], other, KEYS)).toBe("evolution record names namespace 'other', not 'stripe'");
    const ok = evolutionRecords('stripe', [], [refund]).map((r) => signEvolutionRecord(r, 'reg-1', reg.secretKey));
    expect(evolutionError('stripe', [], [refund], ok, KEYS)).toBeNull();
  });
  it('a thrown failure becomes the error text', () => {
    expect(evolutionError('stripe', [refund, refund], [], [], KEYS)).toBe(`evolution error: verb '${refund.verb}' appears twice`);
  });
  it('a record count that matches but whose content differs is refused', () => {
    const [truth] = evolutionRecords('stripe', [], [refund]);
    const lie = signEvolutionRecord({ ...truth!, class: 'removed' as never, from: truth!.to, to: null }, 'reg-1', reg.secretKey);
    expect(evolutionError('stripe', [], [refund], [lie], KEYS)).toBe('evolution records do not match the computed change (a missing, extra or mis-classified record)');
  });
});

describe('PackTracker', () => {
  const v1 = mk(stripe, '1.0.0').pack;
  const v2 = mk([patchRefund(5000), ...rest], '1.1.0', { prev: { pack: v1 } }).pack;
  const v3 = mk([patchRefund(4000), ...rest], '1.2.0', { prev: { pack: v2 } }).pack;

  it('refusals carry their exact reasons', () => {
    const t = new PackTracker(KEYS);
    t.accept(v1);
    t.accept(v2);
    expect(t.accept(v1)).toEqual({ ok: false, code: 'rollback', reason: 'version 1.0.0 is older than the accepted 1.1.0' });
    const fork = mk([patchRefund(4999), ...rest], '1.1.0', { prev: { pack: v1 } }).pack;
    expect(t.accept(fork)).toEqual({ ok: false, code: 'fork', reason: 'two different packs claim version 1.1.0' });
    const u = new PackTracker(KEYS);
    u.accept(v1);
    expect(u.accept(v3)).toEqual({ ok: false, code: 'chain_gap', reason: 'prev does not name the accepted pack' });
  });

  it('a signed pack whose evolution lies is a bad_upgrade while content is kept, and accepted when it is not kept', () => {
    const bad = lying(v2);
    const expected = { ok: false, code: 'bad_upgrade', reason: 'evolution has 0 records, the change needs 1' };
    for (const opts of [{}, { keepContent: true }]) {
      const t = new PackTracker(KEYS, opts);
      t.accept(v1);
      expect(t.accept(bad), JSON.stringify(opts)).toEqual(expected);
      expect(t.snapshot()[0]!.version).toBe('1.0.0');
    }
    const t = new PackTracker(KEYS, { keepContent: false });
    t.accept(v1);
    expect(t.accept(bad)).toEqual({ ok: true, status: 'upgrade' });
    expect(t.snapshot()[0]!.version).toBe('1.1.0');
  });

  it('a restored tracker holds no content, so the same lie passes on chain and version alone', () => {
    const a = new PackTracker(KEYS);
    a.accept(v1);
    const b = new PackTracker(KEYS);
    b.restore(a.snapshot());
    expect(b.accept(lying(v2))).toEqual({ ok: true, status: 'upgrade' });
  });

  it('sharded packs are verified, kept with their shards and upgraded with both sides shards', () => {
    const s1 = mk(stripe, '1.0.0', { shard: true });
    const s2 = mk([patchRefund(5000), ...rest], '1.1.0', { shard: true, prev: { pack: s1.pack, shards: s1.shards } });
    expect(Object.keys(s1.shards).length).toBeGreaterThan(0);
    const t = new PackTracker(KEYS);
    expect(t.accept(s1.pack)).toMatchObject({ ok: false, code: 'bad_pack' });
    expect(t.accept(s1.pack, s1.shards)).toEqual({ ok: true, status: 'first' });
    expect(t.accept(s2.pack)).toMatchObject({ ok: false, code: 'bad_pack' });
    expect(t.accept(s2.pack, s2.shards)).toEqual({ ok: true, status: 'upgrade' });
    // the kept shards also drive a later honest upgrade
    const s3 = mk([patchRefund(4000), ...rest], '1.2.0', { shard: true, prev: { pack: s2.pack, shards: s2.shards } });
    expect(t.accept(s3.pack, s3.shards)).toEqual({ ok: true, status: 'upgrade' });
    const lieShards = new PackTracker(KEYS);
    lieShards.accept(s1.pack, s1.shards);
    const dropped: Record<string, PackShard> = {};
    expect(lieShards.accept(s2.pack, dropped)).toMatchObject({ ok: false, code: 'bad_pack' });
  });

  it('a tracker built with a custom trait registry verifies and upgrades under it, not under the core one', () => {
    const custom = extendRegistry(CORE_REGISTRY, [{ id: 'acme.extra', implies: [], floor: profile(), card_phrase: 'an extra trait' }]);
    const c1 = mk(stripe, '1.0.0', { reg: custom }).pack;
    const c2 = mk([patchRefund(5000), ...rest], '1.1.0', { reg: custom, prev: { pack: c1 } }).pack;
    expect(new PackTracker(KEYS).accept(c1)).toMatchObject({ ok: false, code: 'bad_pack' });
    const t = new PackTracker(KEYS, { reg: custom });
    expect(t.accept(c1)).toEqual({ ok: true, status: 'first' });
    expect(t.accept(c2)).toEqual({ ok: true, status: 'upgrade' });
  });

  it('snapshot lists exactly {ns, version, digest} sorted by namespace whatever the acceptance order', () => {
    const p = (ns: string) => mk(stripe, '1.0.0', { ns }).pack;
    const t = new PackTracker(KEYS);
    const [pa, pz, pm] = [p('alpha'), p('zeta'), p('mid')];
    t.accept(pa);
    t.accept(pz);
    t.accept(pm);
    expect(t.snapshot()).toEqual([
      { ns: 'alpha', version: '1.0.0', digest: packDigest(pa) },
      { ns: 'mid', version: '1.0.0', digest: packDigest(pm) },
      { ns: 'zeta', version: '1.0.0', digest: packDigest(pz) },
    ]);
  });
});

describe('pack log entries', () => {
  const log = generateKeyPairSync('ed25519');
  const registry = generateKeyPairSync('ed25519');
  const svc = new TransparencyService({ alg: 'EdDSA', key: log.privateKey, issuer: 'log' });
  const signer = { alg: 'EdDSA' as const, key: registry.privateKey, issuer: 'reg' };
  const k = { registry: registry.publicKey, log: log.publicKey };
  const { pack } = mk(stripe, '1.0.0');

  it('the statement payload is the exact small document', () => {
    expect(packStatementPayload(pack)).toEqual({ v: 1, kind: 'pca-action-pack-statement', ns: 'stripe', version: '1.0.0', digest: packDigest(pack), root: pack.root, prev: null });
  });
  it('the statement is addressed by namespace@version with the pack content type', () => {
    const e = appendPackToLog(pack, svc, signer);
    const prot = decodeCoseSign1(e.statement).protectedMap as Map<unknown, unknown>;
    const claims = prot.get(HDR_CWT_CLAIMS);
    const sub = claims instanceof Map ? claims.get(CWT_SUB) : (claims as Record<number, unknown>)[CWT_SUB];
    expect(sub).toBe('stripe@1.0.0');
    expect(prot.get(HDR_CONTENT_TYPE)).toBe(PACK_STATEMENT_CONTENT_TYPE);
    expect(e.root).toBe(svc.root);
    expect(verifyPackLogEntry(pack, e, k)).toBe(true);
    expect(verifyPackLogEntry(pack, e, k, svc.root)).toBe(true);
  });
  it('a statement of one pack never proves another pack of the same byte length', () => {
    const e = appendPackToLog(pack, svc, signer);
    const twin = mk(stripe, '1.0.1').pack;
    expect(packStatementPayload(twin).version).toHaveLength(packStatementPayload(pack).version.length);
    expect(packDigest(twin)).toHaveLength(packDigest(pack).length);
    expect(verifyPackLogEntry(twin, e, k)).toBe(false);
    expect(verifyPackLogEntry(pack, e, k)).toBe(true);
  });
  it('a pack that cannot be canonicalised is refused, not thrown', () => {
    const e = appendPackToLog(pack, svc, signer);
    const broken = { ...pack, version: Number.NaN } as unknown as ActionPack;
    expect(verifyPackLogEntry(broken, e, k)).toBe(false);
  });
});
