import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, b64u, generateKeyPair } from '@atlasauth/pca';
import { noWidenViolation } from '@atlasauth/pca/ext/research';
import { RevocationRegistry, checkRevocation } from '@atlasauth/pca-revoke';
import { verifyWebhook } from '@atlasauth/pca-events';
import { EVENT_TYPES } from '@atlasauth/pca-signals';
import {
  ControlPlane,
  InMemoryControlPlaneStore,
  directiveSiemEvent,
  directiveWebhookBody,
  effectiveOf,
  signDirective,
  signDirectiveWebhook,
  signHumanAction,
  signIngest,
  syncRegistry,
  tightenPolicy,
  toRevocationInputs,
  toSignalEvents,
  verifyDirective,
  type ControlPlaneOptions,
  type Directive,
  type DirectiveEvent,
} from './index';

const NOW = Date.UTC(2026, 10, 17, 12);
const signer = generateKeyPair();
const src = generateKeyPair();
const human = generateKeyPair();
const other = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => b64u(k.publicKey);
/** Change one character in the middle of a signature (the last character carries padding bits, so it is not a reliable flip). */
const flip = (sig: string) => sig.slice(0, 10) + (sig[10] === 'A' ? 'B' : 'A') + sig.slice(11);

function setup(over: Partial<ControlPlaneOptions> = {}) {
  const store = new InMemoryControlPlaneStore();
  let now = NOW;
  const emitted: DirectiveEvent[] = [];
  const cp = new ControlPlane({ store, signer: signer.secretKey, sources: { gw: pub(src) }, humans: [pub(human)], now: () => now, onDirective: (e) => void emitted.push(e), ...over });
  let seq = 0;
  let nonce = 0;
  return {
    store,
    cp,
    emitted,
    advance: (ms: number) => (now += ms),
    batch: (events: unknown[], o: { seq?: number; sent_at?: number } = {}) => signIngest(src.secretKey, { source: 'gw', seq: o.seq ?? ++seq, sent_at: o.sent_at ?? now, events }),
    human: (op: 'unfreeze' | 'revoke', directive: string, o: { iat?: number; exp?: number; nonce?: string } = {}) =>
      signHumanAction(human.secretKey, { op, directive, nonce: o.nonce ?? `nonce-${++nonce}-0123456789`, iat: o.iat ?? now, exp: o.exp ?? now + 60_000 }),
  };
}
const ev = (i: number, o: Record<string, unknown> = {}) => ({ id: `e${i}`, at: NOW, agent: 'A', verb: 'pay', resource: 'invoice', outcome: 'auto', r: 0.1, ...o });
const denies = (n: number, agent = 'A') => Array.from({ length: n }, (_, i) => ev(i, { agent, outcome: 'deny', r: 0.9, id: `d-${agent}-${i}` }));

describe('ingest authentication', () => {
  it('accepts a signed batch from a pinned source and refuses everything else', async () => {
    const t = setup();
    const ok = await t.cp.ingest(t.batch([ev(1)]));
    expect(ok).toMatchObject({ ok: true, accepted: 1 });
    const unknown = signIngest(src.secretKey, { source: 'nobody', seq: 1, sent_at: NOW, events: [ev(2)] });
    expect(await t.cp.ingest(unknown)).toEqual({ ok: false, reason: 'source' });
    const wrongKey = signIngest(other.secretKey, { source: 'gw', seq: 99, sent_at: NOW, events: [ev(3)] });
    expect(await t.cp.ingest(wrongKey)).toEqual({ ok: false, reason: 'signature' });
    const tampered = { ...t.batch([ev(4)]), events: [ev(4, { r: 0.9 })] };
    expect(await t.cp.ingest(tampered)).toEqual({ ok: false, reason: 'signature' });
    expect(await t.cp.ingest(null)).toEqual({ ok: false, reason: 'malformed' });
    expect(await t.cp.ingest({ ...t.batch([]), sig: 'x' })).toEqual({ ok: false, reason: 'malformed' });
    // nothing from a refused batch reached the baselines
    expect((await t.store.countAgents())).toBe(1);
  });

  it('a forged batch does not burn the real source sequence', async () => {
    const t = setup();
    await t.cp.ingest(signIngest(other.secretKey, { source: 'gw', seq: 1_000_000, sent_at: NOW, events: [] }));
    expect(await t.cp.ingest(t.batch([ev(1)], { seq: 5 }))).toMatchObject({ ok: true });
  });

  it('refuses a replayed or reordered sequence, and a stale or future clock', async () => {
    const t = setup();
    const b = t.batch([ev(1)], { seq: 10 });
    expect(await t.cp.ingest(b)).toMatchObject({ ok: true });
    expect(await t.cp.ingest(b)).toEqual({ ok: false, reason: 'replayed' });
    expect(await t.cp.ingest(t.batch([ev(2)], { seq: 9 }))).toEqual({ ok: false, reason: 'replayed' });
    expect(await t.cp.ingest(t.batch([ev(3)], { sent_at: NOW - 3_600_000 }))).toEqual({ ok: false, reason: 'stale' });
    expect(await t.cp.ingest(t.batch([ev(4)], { sent_at: NOW + 3_600_000 }))).toEqual({ ok: false, reason: 'future' });
  });

  it('a source cannot sign for another source', async () => {
    const t = setup({ sources: { gw: pub(src), other: pub(other) } });
    const asOther = signIngest(src.secretKey, { source: 'other', seq: 1, sent_at: NOW, events: [] });
    expect(await t.cp.ingest(asOther)).toEqual({ ok: false, reason: 'signature' });
  });

  it('a source id that is an Object.prototype name is not a source', async () => {
    const t = setup();
    expect(await t.cp.ingest(signIngest(src.secretKey, { source: 'constructor', seq: 1, sent_at: NOW, events: [] }))).toEqual({ ok: false, reason: 'source' });
    expect(await t.cp.ingest(signIngest(src.secretKey, { source: '__proto__', seq: 1, sent_at: NOW, events: [] }))).toEqual({ ok: false, reason: 'source' });
  });
});

describe('floods', () => {
  it('refuses an oversized batch before any work', async () => {
    const t = setup({ maxBatch: 50 });
    const r = await t.cp.ingest(t.batch(Array.from({ length: 51 }, (_, i) => ev(i))));
    expect(r).toEqual({ ok: false, reason: 'too_large' });
    expect(await t.store.countAgents()).toBe(0);
  });

  it('a stream of violating batches issues a bounded number of directives (no directive per event)', async () => {
    const t = setup();
    for (let i = 0; i < 40; i++) await t.cp.ingest(t.batch(denies(20).map((e, j) => ({ ...e, id: `b${i}-${j}` }))));
    const all = await t.cp.history({ limit: 500 });
    expect(all.length).toBeLessThanOrEqual(4);
    expect(new Set(all.map((s) => s.directive.kind)).size).toBe(all.length);
  });

  it('an agent-id spray stops creating agents at the cap but still feeds the fleet baseline', async () => {
    const t = setup({ maxAgents: 5 });
    const events = Array.from({ length: 20 }, (_, i) => ev(i, { agent: `spray-${i}` }));
    const r = await t.cp.ingest(t.batch(events));
    expect(r).toMatchObject({ ok: true });
    expect(await t.store.countAgents()).toBe(5);
    expect((r as { dropped: { agent_cap: number } }).dropped.agent_cap).toBe(15);
    expect((await t.store.getFleet())?.events).toBe(20);
  });

  it('duplicate event ids in one batch count once; stale events are dropped', async () => {
    const t = setup();
    const r = await t.cp.ingest(t.batch([ev(1), ev(1), ev(2, { at: NOW - 3 * 86_400_000 })]));
    expect(r).toMatchObject({ ok: true, accepted: 1, dropped: { duplicate: 1, stale: 1 } });
  });

  it('timeline and per-agent lists stay bounded', async () => {
    const t = setup({ timelineLimit: 10 });
    for (let i = 0; i < 5; i++) await t.cp.ingest(t.batch(Array.from({ length: 20 }, (_, j) => ev(i * 20 + j, { session: `s${i * 20 + j}`, grant: `g${i * 20 + j}` }))));
    const a = await t.store.getAgent('A');
    expect(a!.timeline.length).toBe(10);
    expect(a!.sessions.length).toBeLessThanOrEqual(8);
    expect(a!.grants.length).toBeLessThanOrEqual(8);
  });
});

describe('non-finite and malformed metrics fail closed and tighten', () => {
  const bads: Array<[string, Record<string, unknown>]> = [
    ['NaN risk', { r: Number.NaN }],
    ['Infinity risk', { r: Number.POSITIVE_INFINITY }],
    ['negative risk', { r: -1 }],
    ['risk above 1', { r: 7 }],
    ['string risk', { r: '0.1' }],
    ['null risk', { r: null }],
    ['NaN time', { at: Number.NaN }],
    ['Infinity time', { at: Number.POSITIVE_INFINITY }],
    ['unknown outcome', { outcome: 'allow' }],
  ];
  for (const [name, patch] of bads) {
    it(`${name}: counted as a violation at maximum risk, never calm`, async () => {
      const t = setup();
      const events = Array.from({ length: 4 }, (_, i) => ev(i, patch));
      const r = await t.cp.ingestEvents(events);
      expect(r.dropped.malformed).toBe(4);
      const a = await t.store.getAgent('A');
      expect(a!.malformed).toBe(4);
      expect(a!.level).toBe('high');
      expect(a!.score).toBeGreaterThanOrEqual(0.66);
      expect(r.directives.some((d) => d.kind === 'tighten')).toBe(true);
      expect(Number.isFinite(a!.immune.ewma) && Number.isFinite(a!.immune.denies) && Number.isFinite(a!.immune.lastAt)).toBe(true);
    });
  }

  it('a non-object event and an event with no agent still move the fleet baseline', async () => {
    const t = setup();
    const r = await t.cp.ingestEvents([null, 7, 'x', { id: 'z' }, ev(1, { agent: '' })]);
    expect(r.dropped.malformed).toBe(5);
    expect((await t.store.getFleet())?.malformed).toBe(5);
    expect(await t.store.countAgents()).toBe(0);
  });

  it('a future-dated event is malformed, not placed on the timeline', async () => {
    const t = setup();
    const r = await t.cp.ingestEvents([ev(1, { at: NOW + 86_400_000 })]);
    expect(r.dropped.malformed).toBe(1);
    expect((await t.store.getAgent('A'))!.timeline.every((e) => e.outcome === 'malformed')).toBe(true);
  });

  it('a corrupted stored agent state is treated as saturated, never reset to calm', async () => {
    const t = setup();
    await t.cp.ingestEvents([ev(1)]);
    await t.store.updateAgent('A', (p) => ({ ...p!, immune: { ...p!.immune, ewma: Number.NaN } }));
    await t.cp.ingestEvents([ev(2)]);
    expect((await t.store.getAgent('A'))!.level).toBe('high');
  });
});

describe('automatic directives only tighten', () => {
  it('a violation burst issues tighten, shrink_budget, step-up and freeze, all valid and verifiable', async () => {
    const t = setup();
    const r = await t.cp.ingest(t.batch(denies(5)));
    expect(r).toMatchObject({ ok: true });
    const kinds = (r as { directives: Directive[] }).directives.map((d) => d.kind).sort();
    expect(kinds).toEqual(['freeze', 'require_step_up', 'shrink_budget', 'tighten']);
    for (const d of (r as { directives: Directive[] }).directives) {
      expect(verifyDirective(d, { signer: t.cp.publicKey, now: NOW })).toEqual({ ok: true });
      expect(d.cause).toBe('auto');
      if (d.kind === 'tighten') {
        expect(d.params.kappa_mult).toBeGreaterThanOrEqual(1);
        expect(d.params.theta_mult).toBeLessThanOrEqual(1);
      }
      if (d.kind === 'shrink_budget') expect(d.params.factor).toBeLessThan(1);
      if (d.kind !== 'freeze') expect(d.exp! - d.iat).toBeLessThanOrEqual(24 * 3_600_000);
    }
    expect(t.emitted.length).toBe(4);
  });

  it('calm behaviour after an anomaly never lifts anything: the freeze stays until a human signs', async () => {
    const t = setup();
    await t.cp.ingest(t.batch(denies(5)));
    for (let i = 0; i < 10; i++) {
      t.advance(3_600_000);
      await t.cp.ingest(t.batch(Array.from({ length: 5 }, (_, j) => ev(i * 5 + j, { at: NOW + (i + 1) * 3_600_000, id: `calm-${i}-${j}` }))));
    }
    const eff = (await t.cp.effective({ agent: 'A' })).effective;
    expect(eff.frozen).toBe(true);
  });

  it('automatic expiry is the only automatic relaxation: an expired tighten is no longer in force, a freeze is', async () => {
    const t = setup();
    await t.cp.ingest(t.batch(denies(5)));
    t.advance(25 * 3_600_000);
    const eff = (await t.cp.effective({ agent: 'A' })).effective;
    expect(eff.kappa_mult).toBe(1);
    expect(eff.step_up).toBe(false);
    expect(eff.frozen).toBe(true);
  });

  it('an agent that behaves like the fleet is left alone', async () => {
    const t = setup();
    const events = Array.from({ length: 60 }, (_, i) => ev(i, { agent: `n${i % 6}`, r: 0.1 }));
    const r = await t.cp.ingest(t.batch(events));
    expect((r as { directives: Directive[] }).directives).toEqual([]);
  });

  it('refuses to sign or issue anything that would loosen', async () => {
    const t = setup();
    const base = { v: 1 as const, subject: { kind: 'agent' as const, id: 'A' }, cause: 'auto' as const, by: 'x', reason: 'r', evidence: '', iat: NOW, exp: NOW + 1000, seq: 1 };
    expect(() => signDirective(signer.secretKey, { ...base, kind: 'tighten', params: { kappa_mult: 0.5, theta_mult: 1 } })).toThrow(/kappa_mult/);
    expect(() => signDirective(signer.secretKey, { ...base, kind: 'tighten', params: { kappa_mult: 2, theta_mult: 1.5 } })).toThrow(/theta_mult/);
    expect(() => signDirective(signer.secretKey, { ...base, kind: 'tighten', params: { kappa_mult: Number.NaN, theta_mult: 1 } })).toThrow();
    expect(() => signDirective(signer.secretKey, { ...base, kind: 'shrink_budget', params: { factor: 1 } })).toThrow(/factor/);
    expect(() => signDirective(signer.secretKey, { ...base, kind: 'shrink_budget', params: { factor: 2 } })).toThrow();
    expect(() => signDirective(signer.secretKey, { ...base, kind: 'freeze', params: {}, exp: NOW + 5 })).toThrow(/does not expire/);
    expect(() => signDirective(signer.secretKey, { ...base, kind: 'require_step_up', params: {}, exp: NOW + 25 * 3_600_000 })).toThrow(/24 hours/);
    expect(() => signDirective(signer.secretKey, { ...base, kind: 'require_step_up', params: { x: 1 } as never })).toThrow();
    await expect(t.cp.issue({ kind: 'tighten', subject: { kind: 'agent', id: 'A' }, params: { kappa_mult: 0.1, theta_mult: 1 }, by: 'op', reason: 'x' })).rejects.toThrow(RangeError);
  });
});

describe('directive replay and expiry', () => {
  const claim = { v: 1 as const, kind: 'tighten' as const, subject: { kind: 'agent' as const, id: 'A' }, params: { kappa_mult: 2, theta_mult: 0.5 }, cause: 'operator' as const, by: 'op', reason: 'r', evidence: '', iat: NOW, exp: NOW + 60_000, seq: 7 };
  const pubKey = pub(signer);

  it('verifies, then refuses a replay at or below the floor, expiry, a future iat, the wrong signer and any edit', () => {
    const d = signDirective(signer.secretKey, claim);
    expect(verifyDirective(d, { signer: pubKey, now: NOW })).toEqual({ ok: true });
    expect(verifyDirective(d, { signer: pubKey, now: NOW, floorSeq: 6 })).toEqual({ ok: true });
    expect(verifyDirective(d, { signer: pubKey, now: NOW, floorSeq: 7 })).toEqual({ ok: false, reason: 'replayed' });
    expect(verifyDirective(d, { signer: pubKey, now: NOW + 60_000 })).toEqual({ ok: false, reason: 'expired' });
    expect(verifyDirective(d, { signer: pubKey, now: NOW - 3_600_000 })).toEqual({ ok: false, reason: 'not_yet_valid' });
    expect(verifyDirective(d, { signer: pub(other), now: NOW })).toEqual({ ok: false, reason: 'signer' });
    expect(verifyDirective({ ...d, params: { kappa_mult: 1, theta_mult: 1 } }, { signer: pubKey, now: NOW })).toMatchObject({ ok: false });
    expect(verifyDirective({ ...d, exp: d.exp! + 86_400_000 }, { signer: pubKey, now: NOW })).toMatchObject({ ok: false });
    expect(verifyDirective({ ...d, subject: { kind: 'agent', id: 'B' } }, { signer: pubKey, now: NOW })).toMatchObject({ ok: false });
    expect(verifyDirective({ ...d, sig: flip(d.sig) }, { signer: pubKey, now: NOW })).toEqual({ ok: false, reason: 'signature' });
    expect(verifyDirective({ ...d, id: 'x' }, { signer: pubKey, now: NOW })).toEqual({ ok: false, reason: 'id' });
    expect(verifyDirective(null, { signer: pubKey, now: NOW })).toEqual({ ok: false, reason: 'malformed' });
    expect(verifyDirective(d, { signer: pubKey, now: Number.NaN })).toEqual({ ok: false, reason: 'malformed' });
  });

  it('a directive signed by another key never takes effect, and a forged one cannot loosen what is in force', () => {
    const real = signDirective(signer.secretKey, claim);
    const forged = signDirective(other.secretKey, { ...claim, params: { kappa_mult: 1, theta_mult: 1 }, seq: 8 });
    const { effective, invalid } = effectiveOf([real, forged], { signer: pubKey, now: NOW });
    expect(invalid).toBe(1);
    expect(effective.kappa_mult).toBe(2);
    expect(effective.theta_mult).toBe(0.5);
  });

  it('the strictest directive wins across overlapping ones', () => {
    const a = signDirective(signer.secretKey, { ...claim, seq: 1 });
    const b = signDirective(signer.secretKey, { ...claim, params: { kappa_mult: 3, theta_mult: 0.9 }, seq: 2 });
    const c = signDirective(signer.secretKey, { ...claim, kind: 'shrink_budget', params: { factor: 0.25 }, seq: 3 });
    const d = signDirective(signer.secretKey, { ...claim, kind: 'require_step_up', params: {}, seq: 4 });
    const { effective } = effectiveOf([a, b, c, d], { signer: pubKey, now: NOW });
    expect(effective).toMatchObject({ kappa_mult: 3, theta_mult: 0.5, budget_factor: 0.25, step_up: true, frozen: false });
  });

  it('engine: an expired directive is not in force and a renewed one replaces it', async () => {
    const t = setup({ directiveTtlMs: 60_000 });
    await t.cp.issue({ kind: 'tighten', subject: { kind: 'agent', id: 'A' }, params: { kappa_mult: 2, theta_mult: 0.5 }, by: 'op', reason: 'x' });
    expect((await t.cp.effective({ agent: 'A' })).effective.kappa_mult).toBe(2);
    t.advance(61_000);
    expect((await t.cp.effective({ agent: 'A' })).effective.kappa_mult).toBe(1);
  });
});

describe('freeze and signed unfreeze', () => {
  const A = { kind: 'agent' as const, id: 'A' };

  it('freezes in one call, idempotently, and racing freezes create exactly one directive', async () => {
    const t = setup();
    const rs = await Promise.all(Array.from({ length: 12 }, () => t.cp.freeze(A, 'op')));
    expect(rs.filter((r) => r.created).length).toBe(1);
    expect(new Set(rs.map((r) => r.directive.id)).size).toBe(1);
    expect(t.emitted.filter((e) => e.type === 'directive.issued').length).toBe(1);
    expect((await t.cp.effective({ agent: 'A' })).effective.frozen).toBe(true);
    expect((await t.cp.effective({ agent: 'B' })).effective.frozen).toBe(false);
  });

  it('a fleet freeze applies to every agent', async () => {
    const t = setup();
    await t.cp.freezeFleet('op');
    expect((await t.cp.effective({ agent: 'anyone' })).effective.frozen).toBe(true);
    expect((await t.cp.overview()).frozen_fleet).toBe(true);
  });

  it('session and grant freezes apply to the actor that names them', async () => {
    const t = setup();
    await t.cp.freeze({ kind: 'session', id: 's1' }, 'op');
    await t.cp.freeze({ kind: 'grant', id: 'g1' }, 'op');
    expect((await t.cp.effective({ agent: 'A', session: 's1' })).effective.frozen).toBe(true);
    expect((await t.cp.effective({ agent: 'A', grant: 'g1' })).effective.frozen).toBe(true);
    expect((await t.cp.effective({ agent: 'A', session: 's2', grant: 'g2' })).effective.frozen).toBe(false);
  });

  it('unfreeze needs a valid signature from a pinned human', async () => {
    const t = setup();
    const f = (await t.cp.freeze(A, 'op')).directive;
    const good = t.human('unfreeze', f.id);

    expect(await t.cp.lift(undefined)).toMatchObject({ ok: false, reason: 'malformed' });
    expect(await t.cp.lift({})).toMatchObject({ ok: false, reason: 'malformed' });
    expect(await t.cp.lift({ ...good, sig: '' })).toMatchObject({ ok: false, reason: 'malformed' });
    expect(await t.cp.lift({ ...good, sig: flip(good.sig) })).toMatchObject({ ok: false, reason: 'signature' });
    expect(await t.cp.lift({ ...good, directive: 'another' })).toMatchObject({ ok: false, reason: 'signature' });
    const stranger = signHumanAction(other.secretKey, { op: 'unfreeze', directive: f.id, nonce: 'n'.repeat(20), iat: NOW, exp: NOW + 1000 });
    expect(await t.cp.lift(stranger)).toMatchObject({ ok: false, reason: 'human' });
    const operatorKey = signHumanAction(signer.secretKey, { op: 'unfreeze', directive: f.id, nonce: 'o'.repeat(20), iat: NOW, exp: NOW + 1000 });
    expect(await t.cp.lift(operatorKey)).toMatchObject({ ok: false, reason: 'human' });
    expect(await t.cp.lift(t.human('unfreeze', f.id, { iat: NOW - 120_000, exp: NOW - 60_000 }))).toMatchObject({ ok: false, reason: 'expired' });
    expect(await t.cp.lift(t.human('unfreeze', f.id, { iat: NOW + 3_600_000, exp: NOW + 3_660_000 }))).toMatchObject({ ok: false, reason: 'not_yet_valid' });
    expect(await t.cp.lift(t.human('unfreeze', f.id, { iat: NOW, exp: NOW + 3_600_000 }))).toMatchObject({ ok: false, reason: 'too_long' });
    expect(await t.cp.lift(t.human('unfreeze', 'no-such'))).toMatchObject({ ok: false, reason: 'unknown_directive' });
    expect(await t.cp.lift(t.human('revoke', f.id))).toMatchObject({ ok: false, reason: 'wrong_kind' });
    expect((await t.cp.effective({ agent: 'A' })).effective.frozen).toBe(true);
    expect(t.emitted.some((e) => e.type === 'directive.lifted')).toBe(false);

    expect(await t.cp.lift(good)).toMatchObject({ ok: true });
    expect((await t.cp.effective({ agent: 'A' })).effective.frozen).toBe(false);
    expect(t.emitted.filter((e) => e.type === 'directive.lifted').length).toBe(1);
  });

  it('a human action is single use, and racing lifts have one winner', async () => {
    const t = setup();
    const f = (await t.cp.freeze(A, 'op')).directive;
    const a1 = t.human('unfreeze', f.id);
    const a2 = t.human('unfreeze', f.id);
    const rs = await Promise.all([t.cp.lift(a1), t.cp.lift(a1), t.cp.lift(a2), t.cp.lift(a2)]);
    expect(rs.filter((r) => r.ok).length).toBe(1);
    expect(await t.cp.lift(a1)).toMatchObject({ ok: false });
  });

  it('a signature for an old freeze does not lift a newer freeze of the same subject', async () => {
    const t = setup();
    const f1 = (await t.cp.freeze(A, 'op')).directive;
    const old = t.human('unfreeze', f1.id);
    expect(await t.cp.lift(old)).toMatchObject({ ok: true });
    const f2 = (await t.cp.freeze(A, 'op')).directive;
    expect(f2.id).not.toBe(f1.id);
    expect(await t.cp.lift(t.human('unfreeze', f1.id, { nonce: old.nonce }))).toMatchObject({ ok: false });
    expect(await t.cp.lift({ ...old, directive: f2.id })).toMatchObject({ ok: false, reason: 'signature' });
    expect((await t.cp.effective({ agent: 'A' })).effective.frozen).toBe(true);
  });

  it('freeze racing a signed unfreeze ends in a defined state: frozen by the newest freeze', async () => {
    const t = setup();
    const f1 = (await t.cp.freeze(A, 'op')).directive;
    const [lifted, again] = await Promise.all([t.cp.lift(t.human('unfreeze', f1.id)), t.cp.freeze(A, 'op')]);
    expect(lifted).toMatchObject({ ok: true });
    const eff = (await t.cp.effective({ agent: 'A' })).effective;
    expect(eff.frozen).toBe(again.created ? true : false);
  });

  it('with no pinned human nothing can be lifted', async () => {
    const t = setup({ humans: [] });
    const f = (await t.cp.freeze(A, 'op')).directive;
    expect(await t.cp.lift(t.human('unfreeze', f.id))).toMatchObject({ ok: false, reason: 'human' });
  });

  it('a signed human revoke ends an expiring directive early', async () => {
    const t = setup();
    const d = (await t.cp.issue({ kind: 'require_step_up', subject: A, by: 'op', reason: 'x' })).directive;
    expect((await t.cp.effective({ agent: 'A' })).effective.step_up).toBe(true);
    expect(await t.cp.lift(t.human('unfreeze', d.id))).toMatchObject({ ok: false, reason: 'wrong_kind' });
    expect(await t.cp.lift(t.human('revoke', d.id))).toMatchObject({ ok: true });
    expect((await t.cp.effective({ agent: 'A' })).effective.step_up).toBe(false);
  });

  it('a throwing sink never breaks the engine and is reported', async () => {
    const errors: string[] = [];
    const t = setup({
      onDirective: () => {
        throw new Error('boom');
      },
      onError: (_e, what) => void errors.push(what),
    });
    await expect(t.cp.freeze(A, 'op')).resolves.toMatchObject({ created: true });
    expect(errors).toEqual(['onDirective']);
  });
});

describe('verifier-side hooks', () => {
  const A = { kind: 'agent' as const, id: 'holder-key-A' };

  it('tightenPolicy never widens and step-up drives the thresholds to zero', () => {
    const t = setup();
    const claim = { v: 1 as const, kind: 'tighten' as const, subject: A, params: { kappa_mult: 2, theta_mult: 0.5 }, cause: 'operator' as const, by: 'op', reason: 'r', evidence: '', iat: NOW, exp: NOW + 1000, seq: 1 };
    const { effective } = effectiveOf([signDirective(signer.secretKey, claim)], { signer: t.cp.publicKey, now: NOW });
    const p = tightenPolicy(DEFAULT_RISK_POLICY, effective);
    expect(noWidenViolation(DEFAULT_RISK_POLICY, p)).toBeNull();
    expect(p.kappa).toBe(DEFAULT_RISK_POLICY.kappa * 2);
    expect(p.theta1).toBe(DEFAULT_RISK_POLICY.theta1 * 0.5);
    const q = tightenPolicy(DEFAULT_RISK_POLICY, { ...effective, step_up: true });
    expect([q.theta1, q.theta2]).toEqual([0, 0]);
    expect(tightenPolicy(DEFAULT_RISK_POLICY, { frozen: false, kappa_mult: 1, theta_mult: 1, budget_factor: 1, step_up: false, directives: [] })).toEqual(DEFAULT_RISK_POLICY);
  });

  it('an agent freeze becomes a holder revocation the registry enforces', async () => {
    const t = setup();
    const f = (await t.cp.freeze(A, 'op')).directive;
    const inputs = toRevocationInputs(f);
    expect(inputs).toEqual([expect.objectContaining({ kind: 'holder', value: A.id })]);
    const registry = new RevocationRegistry();
    expect(await syncRegistry(registry, await t.cp.activeDirectives())).toBe(1);
    const pcactn = { cap_chain: [{ id: 'c1', holder: A.id, issuer: 'p' }] } as never;
    expect((await checkRevocation(pcactn, registry, { now: NOW })).revoked).toBe(true);
    expect(toRevocationInputs((await t.cp.issue({ kind: 'tighten', subject: A, params: { kappa_mult: 2, theta_mult: 1 }, by: 'op', reason: 'x' })).directive)).toEqual([]);
  });

  it('freezes and tightenings map onto the Shared Signals events', async () => {
    const t = setup();
    const kill = (await t.cp.freeze(A, 'op')).directive;
    expect(toSignalEvents(kill)[EVENT_TYPES.killSwitch]).toMatchObject({ agent: A.id });
    const grant = (await t.cp.freeze({ kind: 'grant', id: 'g1' }, 'op')).directive;
    expect(toSignalEvents(grant)[EVENT_TYPES.grantRevoked]).toMatchObject({ grant_ref: 'g1' });
    const sess = (await t.cp.freeze({ kind: 'session', id: 's1' }, 'op')).directive;
    expect(toSignalEvents(sess)[EVENT_TYPES.intentRevoked]).toMatchObject({ ids: ['pca-intent:session:s1'] });
    const fleet = (await t.cp.freezeFleet('op')).directive;
    expect(toSignalEvents(fleet)[EVENT_TYPES.riskLevelChange]).toMatchObject({ principal: 'TENANT', current_level: 'HIGH' });
    const tight = (await t.cp.issue({ kind: 'tighten', subject: A, params: { kappa_mult: 2, theta_mult: 1 }, by: 'op', reason: 'x' })).directive;
    expect(toSignalEvents(tight)[EVENT_TYPES.riskLevelChange]).toMatchObject({ current_level: 'MEDIUM' });
  });
});

describe('webhooks and SIEM for every directive', () => {
  it('every issued and lifted directive is delivered as a signed webhook body and renders in all three SIEM formats', async () => {
    const t = setup();
    await t.cp.ingest(t.batch(denies(5)));
    const f = t.emitted.find((e) => e.directive.kind === 'freeze')!.directive;
    await t.cp.lift(t.human('unfreeze', f.id));
    expect(t.emitted.length).toBe(5);
    expect(new Set(t.emitted.map((e) => e.directive.id)).size).toBe(4);
    const secret = 'whsec_0123456789abcdef';
    for (const e of t.emitted) {
      const { body, headers } = signDirectiveWebhook(secret, e, { timestamp: Math.floor(NOW / 1000) });
      expect(verifyWebhook(secret, body, headers['PCA-Signature']!, { now: Math.floor(NOW / 1000) })).toBe(true);
      expect(verifyWebhook(secret, body + ' ', headers['PCA-Signature']!, { now: Math.floor(NOW / 1000) })).toBe(false);
      const parsed = JSON.parse(body) as { type: string; directive: Directive };
      expect(parsed.type).toBe(e.type === 'directive.issued' ? 'pca.control.directive.issued' : 'pca.control.directive.lifted');
      expect(verifyDirective(parsed.directive, { signer: t.cp.publicKey, now: NOW })).toEqual({ ok: true });
      for (const format of ['ocsf', 'ecs', 'cef'] as const) {
        const s = directiveSiemEvent(e, format);
        expect(s.line.includes('\n')).toBe(false);
        expect(s.line).toContain(e.directive.id);
      }
    }
    expect(directiveWebhookBody(t.emitted[4]!).lift).toMatchObject({ op: 'unfreeze' });
  });

  it('SIEM output escapes caller text and keeps a CEF line to one record', async () => {
    const t = setup();
    const d = (await t.cp.issue({ kind: 'require_step_up', subject: { kind: 'agent', id: 'a|b=c' }, by: 'op', reason: 'x|y=z\nCEF:0|forged' })).directive;
    const cef = directiveSiemEvent({ type: 'directive.issued', at: NOW, directive: d }, 'cef').line;
    expect(cef.split('\n').length).toBe(1);
    expect(cef.startsWith('CEF:0|Atlas|PCA Control Plane|1|')).toBe(true);
    // the header has exactly seven fields: caller text with a pipe cannot add or end one
    const fields = cef.split(/(?<!\\)\|/);
    expect(fields[0]).toBe('CEF:0');
    expect(fields[5]).toContain('CEF:0\\|forged');
    expect(fields[6]).toBe('6');
  });
});

describe('views', () => {
  it('overview ranks agents by threat and marks frozen ones; agentView returns the timeline and directives', async () => {
    const t = setup();
    await t.cp.ingest(t.batch([...denies(5, 'bad'), ...Array.from({ length: 5 }, (_, i) => ev(i, { agent: 'good', id: `g${i}` }))]));
    const o = await t.cp.overview();
    expect(o.agents[0]!.agent).toBe('bad');
    expect(o.agents[0]!.frozen).toBe(true);
    expect(o.agents.find((a) => a.agent === 'good')!.level).toBe('calm');
    const v = await t.cp.agentView('bad');
    expect(v!.agent.timeline.length).toBe(5);
    expect(v!.directives.length).toBe(4);
    expect(v!.effective.frozen).toBe(true);
    expect(await t.cp.agentView('ghost')).toBeUndefined();
  });
});
