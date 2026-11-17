import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import { DEFAULT_MAX_STH_AGE_MS, checkAgent, decodeBundle, encodeBundle, refreshBundle, signRevocation, stapleBundle, type CheckOptions, type StapledBundle } from './index';
import { HOUR, makeAgent, makeWorld, register, type World } from './test-util';

const MIN = 60_000;
const opts = (w: World, p: Partial<CheckOptions['policy']> = {}, logs = w.trusted()): CheckOptions => ({
  logs,
  witnesses: { keys: w.witnessKeys, threshold: 2 },
  policy: { trustedIssuers: [b64u(w.issuer.publicKey)], minLogs: 2, now: w.clock.now(), online: 'off', ...p },
});
const clientsOf = (w: World) => w.logs.map((l, i) => ({ id: l.id, client: w.clients[i]! }));

async function listed(w: World) {
  const agent = makeAgent(w.issuer);
  for (const l of w.logs) await register(l, agent);
  await w.round();
  return { agent, bundle: await stapleBundle(agent.sp, clientsOf(w)) };
}

describe('the age limit on a stapled head', () => {
  it('defaults to one hour: a relying party that sets nothing misses a revocation for at most that long', async () => {
    expect(DEFAULT_MAX_STH_AGE_MS).toBe(HOUR);
    const w = makeWorld(2, 3);
    const { bundle } = await listed(w);
    w.clock.advance(59 * MIN);
    expect((await checkAgent(bundle, opts(w, { now: w.clock.now() }))).decision).toBe('trusted');
    w.clock.advance(2 * MIN);
    const r = await checkAgent(bundle, opts(w, { now: w.clock.now() }));
    expect(r.decision).toBe('unknown');
    expect(r.logs.every((l) => l.state === 'stale')).toBe(true);
  });

  it('is a policy knob in both directions', async () => {
    const w = makeWorld(2, 3);
    const { bundle } = await listed(w);
    w.clock.advance(3 * HOUR);
    expect((await checkAgent(bundle, opts(w, { now: w.clock.now() }))).decision).toBe('unknown');
    expect((await checkAgent(bundle, opts(w, { now: w.clock.now(), maxSthAgeMs: 4 * HOUR }))).decision).toBe('trusted');
    expect((await checkAgent(bundle, opts(w, { now: w.clock.now(), maxSthAgeMs: MIN }))).decision).toBe('unknown');
  });
});

describe('freshness tokens', () => {
  it('let a relying party require a 10 minute old head while staying offline: the agent refreshes cheaply', async () => {
    const w = makeWorld(2, 3);
    const { bundle } = await listed(w);
    w.clock.advance(2 * HOUR);
    const policy = { now: w.clock.now(), freshness: { maxAgeMs: 10 * MIN, require: true } };
    // the stapled proof alone is two hours old
    expect((await checkAgent(bundle, opts(w, policy))).decision).toBe('unknown');
    // the agent refreshes (one status request per log) and presents the new bundle
    const fresh = await refreshBundle(bundle, clientsOf(w));
    expect(fresh.freshness).toHaveLength(2);
    expect((await checkAgent(fresh, opts(w, policy))).decision).toBe('trusted');
    // and it survives the header round trip
    expect((await checkAgent(encodeBundle(fresh), opts(w, policy))).decision).toBe('trusted');
    // eleven minutes later the token no longer meets the policy
    w.clock.advance(11 * MIN);
    const late = await checkAgent(fresh, opts(w, { ...policy, now: w.clock.now() }));
    expect(late.decision).toBe('unknown');
    expect(late.reasons.join()).toContain('no_fresh_token');
    // refreshing again fixes it
    expect((await checkAgent(await refreshBundle(fresh, clientsOf(w)), opts(w, { ...policy, now: w.clock.now() }))).decision).toBe('trusted');
  });

  it('without `require`, a fresh token rescues an old stapled head, and an old token does nothing', async () => {
    const w = makeWorld(2, 3);
    const { bundle } = await listed(w);
    w.clock.advance(2 * HOUR);
    const fresh = await refreshBundle(bundle, clientsOf(w));
    expect((await checkAgent(fresh, opts(w, { now: w.clock.now() }))).decision).toBe('trusted');
    w.clock.advance(2 * HOUR);
    expect((await checkAgent(fresh, opts(w, { now: w.clock.now() }))).decision).toBe('unknown');
  });

  it('carry a revocation: a token that shows one convicts offline, even if the stapled proof is genuine', async () => {
    const w = makeWorld(2, 3);
    const { agent, bundle } = await listed(w);
    for (const l of w.logs) await l.submit({ revocation: signRevocation(w.issuer.secretKey, agent.sp, { iat: w.clock.now() }) }, 'issuer');
    await w.round();
    const fresh = await refreshBundle(bundle, clientsOf(w));
    const r = await checkAgent(fresh, opts(w, { freshness: { maxAgeMs: 10 * MIN } }));
    expect(r.decision).toBe('untrusted');
    expect(r.logs.some((l) => l.state === 'revoked')).toBe(true);
  });

  it('a token that hides the passport, forges an entry or is signed by another key does not count', async () => {
    const w = makeWorld(2, 3);
    const { bundle } = await listed(w);
    w.clock.advance(2 * HOUR);
    const policy = { now: w.clock.now(), freshness: { maxAgeMs: 10 * MIN, require: true } };
    const fresh = await refreshBundle(bundle, clientsOf(w));

    const hidden: StapledBundle = JSON.parse(JSON.stringify(fresh));
    for (const f of hidden.freshness!) f.status.entries = [];
    expect((await checkAgent(hidden, opts(w, policy))).decision).toBe('unknown');

    const forged: StapledBundle = JSON.parse(JSON.stringify(fresh));
    for (const f of forged.freshness!) f.status.entries[0]!.entry.entry.iat += 1; // no longer what the proof commits to
    expect((await checkAgent(forged, opts(w, policy))).decision).toBe('unknown');

    const stranger = makeWorld(2, 3);
    const alien = await stranger.logs[0]!.sth();
    const swapped: StapledBundle = JSON.parse(JSON.stringify(fresh));
    swapped.freshness![0]!.status.sth = alien;
    const r = await checkAgent(swapped, opts(w, policy));
    expect(r.decision).toBe('untrusted');
    expect(r.logs[0]!.state).toBe('invalid');
  });

  it('are bounded and validated at the decoder', async () => {
    const w = makeWorld(2, 3);
    const { bundle } = await listed(w);
    const fresh = await refreshBundle(bundle, clientsOf(w));
    expect(decodeBundle(encodeBundle(fresh)).freshness).toHaveLength(2);
    const bad = { ...fresh, freshness: [{ log: 'x' }] } as unknown as StapledBundle;
    expect(() => decodeBundle(encodeBundle(bad))).toThrow();
    const many = { ...fresh, freshness: Array.from({ length: 40 }, () => fresh.freshness![0]!) };
    expect(() => decodeBundle(encodeBundle(many))).toThrow();
  });

  it('refreshing keeps the old token for a log that does not answer', async () => {
    const w = makeWorld(2, 3);
    const { bundle } = await listed(w);
    const once = await refreshBundle(bundle, clientsOf(w));
    const dead = { ...w.clients[0]!, status: async () => { throw new Error('down'); } };
    const twice = await refreshBundle(once, [{ id: w.logs[0]!.id, client: dead }, { id: w.logs[1]!.id, client: w.clients[1]! }]);
    expect(twice.freshness).toHaveLength(2);
    expect(twice.freshness!.find((f) => f.log === w.logs[0]!.id)).toEqual(once.freshness!.find((f) => f.log === w.logs[0]!.id));
  });
});

