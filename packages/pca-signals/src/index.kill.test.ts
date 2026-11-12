import { CompactSign, SignJWT, decodeJwt, generateKeyPair, type KeyLike } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import type { Capability, PCActn, VerifyContext } from '@atlasauth/pca';
import {
  EVENT_TYPES,
  SignalsError,
  applySET,
  applyStandardRevocations,
  buildSET,
  createInMemorySetReplayStore,
  createRevocationHook,
  createRevocationState,
  isIntentRevoked,
  isRevoked,
  planStandardRevocations,
  receiveSET,
  restoreRevocationState,
  runSetReplayStoreConformance,
  snapshotRevocationState,
  streamProcessor,
  verifySET,
  type ParsedSet,
  type RevocationState,
  type SetEvents,
  type SetReplayStore,
  type VerifyKey,
} from './index';

const hoisted = vi.hoisted(() => ({ throwString: false }));
vi.mock('@atlasauth/pca', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@atlasauth/pca')>();
  return {
    ...actual,
    assertCanonicalCompactJws: (...a: Parameters<typeof actual.assertCanonicalCompactJws>) => {
      if (hoisted.throwString) throw 'not an error object';
      return actual.assertCanonicalCompactJws(...a);
    },
  };
});

const ISS = 'https://transmitter.example';
const AUD = 'https://rs.example';
const NOW = 1_800_000_000;
const GR = EVENT_TYPES.grantRevoked;
const KS = EVENT_TYPES.killSwitch;
const IR = EVENT_TYPES.intentRevoked;

const keys = () => generateKeyPair('EdDSA');
const grantEv = { [GR]: { grant_ref: 'g1', reason: 'r', event_timestamp: NOW } };
const claims = (over: Record<string, unknown> = {}) => ({ iss: ISS, aud: AUD, iat: NOW, jti: 'jti-1', events: grantEv, ...over });
const sign = (key: KeyLike, c: Record<string, unknown>, header: Record<string, unknown> = { alg: 'EdDSA', typ: 'secevent+jwt' }) =>
  new SignJWT(c).setProtectedHeader(header as { alg: string }).sign(key);
const manual = (events: Record<string, unknown>, sub_id?: unknown): ParsedSet =>
  ({ events, iss: ISS, jti: 'j', payload: { events, ...(sub_id !== undefined ? { sub_id } : {}) } }) as unknown as ParsedSet;
const opaque = (id: string) => ({ format: 'opaque', id });
const err = (fn: () => unknown): Error => {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error('did not throw');
};

describe('buildSET', () => {
  it('refuses a missing, non-object or empty events map with the exact message', async () => {
    const { privateKey } = await keys();
    const msg = 'buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)';
    for (const events of [null, 'x', {}]) {
      await expect(buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: events as unknown as SetEvents })).rejects.toThrow(new Error(msg));
    }
  });
  it('emits neither sub nor sub_id without a subject, and both with one', async () => {
    const { privateKey } = await keys();
    const bare = decodeJwt(await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: grantEv as SetEvents }));
    expect('sub' in bare).toBe(false);
    expect('sub_id' in bare).toBe(false);
    const withSub = decodeJwt(await buildSET({ issuer: ISS, audience: AUD, key: privateKey, subject: 's1', events: grantEv as SetEvents }));
    expect(withSub.sub).toBe('s1');
    expect(withSub['sub_id']).toEqual({ format: 'opaque', id: 's1' });
  });
});

describe('verifySET', () => {
  it('honours clockTolerance and only that', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await sign(privateKey, claims({ exp: NOW - 30 }));
    const base = { currentDate: new Date(NOW * 1000) };
    await expect(verifySET(set, publicKey, base)).rejects.toThrow();
    await expect(verifySET(set, publicKey, { ...base, clockTolerance: 60 })).resolves.toBeDefined();
    await expect(verifySET(set, publicKey, { ...base, clockTolerance: 10 })).rejects.toThrow();
  });
  it('requireTyp false skips the typ check; the default and an override enforce it', async () => {
    const { publicKey, privateKey } = await keys();
    const wrongTyp = await sign(privateKey, claims(), { alg: 'EdDSA', typ: 'JWT' });
    const noTyp = await sign(privateKey, claims(), { alg: 'EdDSA' });
    await expect(verifySET(wrongTyp, publicKey)).rejects.toThrow();
    await expect(verifySET(noTyp, publicKey)).rejects.toThrow();
    await expect(verifySET(wrongTyp, publicKey, { requireTyp: false })).resolves.toBeDefined();
    await expect(verifySET(noTyp, publicKey, { requireTyp: false })).resolves.toBeDefined();
    await expect(verifySET(wrongTyp, publicKey, { typ: 'JWT' })).resolves.toBeDefined();
  });
  it('refuses a missing or non-string iss / jti with the exact message', async () => {
    const { publicKey, privateKey } = await keys();
    const issMsg = 'SET invalid: missing or non-string `iss`';
    const jtiMsg = 'SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)';
    await expect(verifySET(await sign(privateKey, claims({ iss: undefined })), publicKey)).rejects.toThrow(new Error(issMsg));
    await expect(verifySET(await sign(privateKey, claims({ iss: 5 })), publicKey)).rejects.toThrow(new Error(issMsg));
    await expect(verifySET(await sign(privateKey, claims({ jti: undefined })), publicKey)).rejects.toThrow(new Error(jtiMsg));
    await expect(verifySET(await sign(privateKey, claims({ jti: 7 })), publicKey)).rejects.toThrow(new Error(jtiMsg));
  });
  it('ignores a non-string sub', async () => {
    const { publicKey, privateKey } = await keys();
    expect((await verifySET(await sign(privateKey, claims({ sub: 5 })), publicKey)).sub).toBeUndefined();
    expect((await verifySET(await sign(privateKey, claims({ sub: 'u' })), publicKey)).sub).toBe('u');
  });
  it('refuses a malformed events claim with the exact message', async () => {
    const { publicKey, privateKey } = await keys();
    const v = async (events: unknown) => verifySET(await sign(privateKey, claims({ events })), publicKey);
    await expect(v(undefined)).rejects.toThrow(new Error('SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)'));
    await expect(v([])).rejects.toThrow(new Error('SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)'));
    await expect(v('x')).rejects.toThrow(new Error('SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)'));
    await expect(v({})).rejects.toThrow(new Error('SET invalid: `events` claim is empty (RFC 8417 §2.2)'));
    await expect(v({ 'https://x.example/e': 'str' })).rejects.toThrow(
      new Error('SET invalid: event payload for `https://x.example/e` is not a JSON object (RFC 8417 §2.2)'),
    );
    await expect(v({ ok: {}, bad: [1] })).rejects.toThrow(new Error('SET invalid: event payload for `bad` is not a JSON object (RFC 8417 §2.2)'));
  });
});

describe('applySET', () => {
  it('skips an undefined event without throwing', () => {
    const s = applySET(createRevocationState(), manual({ [GR]: undefined, [KS]: undefined, [IR]: undefined }));
    expect(s.revokedGrants.size + s.killedAgents.size).toBe(0);
    expect(s.revokedIntentIds).toBeUndefined();
  });
  it('a missing or non-numeric event_timestamp records 0', () => {
    const s = applySET(createRevocationState(), manual({ [GR]: { grant_ref: 'g' }, [KS]: { agent: 'a', event_timestamp: '9' } }));
    expect(s.revokedGrants).toEqual(new Map([['g', 0]]));
    expect(s.killedAgents).toEqual(new Map([['a', 0]]));
  });
  it('grant-revoked records only a non-empty string grant_ref', () => {
    for (const grant_ref of ['', ['x'], 5, null, undefined]) {
      const s = applySET(createRevocationState(), manual({ [GR]: { grant_ref, event_timestamp: 4 } }));
      expect(s.revokedGrants.size).toBe(0);
    }
    const s = applySET(createRevocationState(), manual({ [GR]: { grant_ref: 'g', event_timestamp: 4 } }));
    expect(s.revokedGrants).toEqual(new Map([['g', 4]]));
  });
  it('kill-switch records agent and grant_ref independently, only non-empty strings', () => {
    const only = (ev: Record<string, unknown>) => applySET(createRevocationState(), manual({ [KS]: { event_timestamp: 8, ...ev } }));
    for (const bad of ['', ['x'], 5]) {
      const s = only({ agent: bad, grant_ref: bad });
      expect(s.killedAgents.size).toBe(0);
      expect(s.revokedGrants.size).toBe(0);
    }
    const a = only({ agent: 'ag' });
    expect(a.killedAgents).toEqual(new Map([['ag', 8]]));
    expect(a.revokedGrants.size).toBe(0);
    const g = only({ grant_ref: 'gr' });
    expect(g.revokedGrants).toEqual(new Map([['gr', 8]]));
    expect(g.killedAgents.size).toBe(0);
    const both = only({ agent: 'ag', grant_ref: 'gr' });
    expect(both.killedAgents).toEqual(new Map([['ag', 8]]));
    expect(both.revokedGrants).toEqual(new Map([['gr', 8]]));
  });
  it('only the named event types revoke: others carrying agent / grant_ref / ids do nothing', () => {
    const s = applySET(
      createRevocationState(),
      manual({
        [EVENT_TYPES.sessionRevoked]: { agent: 'a', grant_ref: 'g', ids: ['pca-intent:x'], event_timestamp: 1 },
        'https://x.example/e': { agent: 'a', grant_ref: 'g', ids: ['pca-intent:x'], event_timestamp: 1 },
      }),
    );
    expect(s.killedAgents.size + s.revokedGrants.size).toBe(0);
    expect(s.revokedIntentIds).toBeUndefined();
  });
  it('grant-revoked does not act as a kill-switch and vice versa', () => {
    const s = applySET(createRevocationState(), manual({ [GR]: { agent: 'a', grant_ref: 'g', event_timestamp: 1 } }));
    expect(s.killedAgents.size).toBe(0);
    expect(s.revokedGrants).toEqual(new Map([['g', 1]]));
  });
  it('intent-revoked records only strings with the pca-intent: prefix, keeping the max timestamp', () => {
    const s = applySET(
      createRevocationState(),
      manual({ [IR]: { ids: ['pca-intent:a', 'other', '', 5, 'x-pca-intent:', 'pca-intent:'], event_timestamp: 3 } }),
    );
    expect(s.revokedIntentIds).toEqual(new Map([['pca-intent:a', 3], ['pca-intent:', 3]]));
    applySET(s, manual({ [IR]: { ids: ['pca-intent:a'], event_timestamp: 9 } }));
    applySET(s, manual({ [IR]: { ids: ['pca-intent:a'], event_timestamp: 1 } }));
    expect(s.revokedIntentIds?.get('pca-intent:a')).toBe(9);
  });
  it('intent-revoked with non-array ids does nothing and does not throw', () => {
    for (const ids of [{}, 5, null, undefined]) {
      const s = applySET(createRevocationState(), manual({ [IR]: { ids, event_timestamp: 3 } }));
      expect(s.revokedIntentIds).toBeUndefined();
    }
  });
});

describe('isIntentRevoked / isRevoked', () => {
  it('isIntentRevoked is true only for a recorded id, and false with no map at all', () => {
    const s = createRevocationState();
    expect(isIntentRevoked(s, 'pca-intent:a')).toBe(false);
    applySET(s, manual({ [IR]: { ids: ['pca-intent:a'], event_timestamp: 1 } }));
    expect(isIntentRevoked(s, 'pca-intent:a')).toBe(true);
    expect(isIntentRevoked(s, 'pca-intent:b')).toBe(false);
  });
  it('isRevoked does not look up an undefined agent', () => {
    const s = createRevocationState();
    s.killedAgents.set(undefined as unknown as string, 1);
    expect(isRevoked(s, 'g')).toBe(false);
    expect(isRevoked(s, 'g', 'real')).toBe(false);
    s.killedAgents.set('real', 1);
    expect(isRevoked(s, 'g', 'real')).toBe(true);
  });
});

describe('streamProcessor ordering', () => {
  it('applies SETs ascending by their minimum numeric event_timestamp', () => {
    const M = manual({ [GR]: { grant_ref: 'gM', event_timestamp: 20 } });
    const Z = manual({ [GR]: { grant_ref: 'gZ', event_timestamp: '1' }, [KS]: { agent: 'kZ', event_timestamp: 7 } });
    const B = manual({ [GR]: { grant_ref: 'gB', event_timestamp: 6 }, [KS]: { agent: 'kB', event_timestamp: 60 } });
    const A = manual({ [GR]: { grant_ref: 'gA', event_timestamp: 50 }, [KS]: { agent: 'kA', event_timestamp: 5 } });
    const N = manual({ [GR]: { grant_ref: 'gN' } });
    const U = manual({ [GR]: undefined });
    const s = streamProcessor([M, Z, B, A, N, U]);
    expect([...s.revokedGrants.keys()]).toEqual(['gN', 'gA', 'gB', 'gZ', 'gM']);
  });
  it('does not mutate its input order', () => {
    const a = manual({ [GR]: { grant_ref: 'a', event_timestamp: 2 } });
    const b = manual({ [GR]: { grant_ref: 'b', event_timestamp: 1 } });
    const input = [a, b];
    streamProcessor(input);
    expect(input).toEqual([a, b]);
    expect(input[0]).toBe(a);
  });
});

describe('createInMemorySetReplayStore', () => {
  it('rejects a bad maxEntries with a SignalsError carrying the exact code and message', () => {
    for (const maxEntries of [0, -1, 1.5, Number.NaN]) {
      const e = err(() => createInMemorySetReplayStore({ maxEntries })) as SignalsError;
      expect(e).toBeInstanceOf(SignalsError);
      expect(e.name).toBe('SignalsError');
      expect(e.code).toBe('misconfigured');
      expect(e.message).toBe('maxEntries must be a positive integer');
    }
  });
  it('a full store does not forget an expired entry the clock has not reached yet', () => {
    const s = createInMemorySetReplayStore({ maxEntries: 10 });
    expect(s.addIfAbsent('x', 200, 100)).toBe(true);
    expect(s.addIfAbsent('y', 500, 300)).toBe(true);
    expect(s.addIfAbsent('x', 400, 150)).toBe(false);
  });
  it('re-adding an expired entry of a full store does not purge other expired entries', () => {
    const s = createInMemorySetReplayStore({ maxEntries: 3 });
    s.addIfAbsent('p', 200, 100);
    s.addIfAbsent('r', 250, 100);
    s.addIfAbsent('q', 1000, 100);
    expect(s.addIfAbsent('p', 900, 300)).toBe(true);
    expect(s.addIfAbsent('r', 400, 100)).toBe(false);
  });
  it('throws when full of live entries and frees expired ones first', () => {
    const s = createInMemorySetReplayStore({ maxEntries: 2 });
    s.addIfAbsent('a', 200, 100);
    s.addIfAbsent('b', 300, 100);
    expect(() => s.addIfAbsent('c', 400, 150)).toThrow('replay store is full');
    expect(s.addIfAbsent('c', 400, 250)).toBe(true);
  });
});

describe('runSetReplayStoreConformance failure names', () => {
  it('names exactly the failed checks for an always-false store', async () => {
    const fails = await runSetReplayStoreConformance(() => ({ addIfAbsent: () => false }));
    expect(fails).toEqual([
      'first sight of a jti returns true',
      'a different jti is independent',
      'an expired entry may be added again (nowSec >= expiresAtSec)',
      '16 concurrent adds of one jti: exactly one wins (got 0)',
    ]);
  });
  it('names exactly the failed checks for an always-true store', async () => {
    const fails = await runSetReplayStoreConformance(() => ({ addIfAbsent: () => true }));
    expect(fails).toEqual([
      'second sight of the same jti returns false',
      'still seen one second before expiry',
      '16 concurrent adds of one jti: exactly one wins (got 16)',
    ]);
  });
  it('probes with the documented jtis and passes a correct store', async () => {
    const calls: string[] = [];
    const fails = await runSetReplayStoreConformance(() => {
      const inner = createInMemorySetReplayStore();
      return {
        addIfAbsent(jti, exp, now) {
          calls.push(jti);
          return inner.addIfAbsent(jti, exp, now);
        },
      };
    });
    expect(fails).toEqual([]);
    expect(calls).toEqual(['a', 'a', 'b', 'a', 'c', 'c', ...Array<string>(16).fill('race')]);
  });
});

describe('receiveSET refusal values', () => {
  const opts = (over: Record<string, unknown> = {}) => ({
    issuer: ISS,
    audience: AUD,
    replayStore: createInMemorySetReplayStore(),
    state: createRevocationState(),
    maxAgeSec: 3600,
    nowSec: NOW,
    ...over,
  });
  it('oversize: a non-string and a string over maxBytes, with the exact boundary', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await sign(privateKey, claims());
    const oversize = { ok: false, code: 'oversize', reason: 'SET is not a string or exceeds maxBytes' };
    expect(await receiveSET(5 as unknown as string, publicKey, opts())).toEqual(oversize);
    expect(await receiveSET(set, publicKey, opts({ maxBytes: set.length - 1 }))).toEqual(oversize);
    expect((await receiveSET(set, publicKey, opts({ maxBytes: set.length }))).ok).toBe(true);
  });
  it('malformed: an Error keeps its message, a non-Error throw gets the fixed text', async () => {
    const { publicKey } = await keys();
    const r = await receiveSET('a.b', publicKey, opts());
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('malformed');
      expect(r.reason.length).toBeGreaterThan(0);
      expect(r.reason).not.toBe('not a canonical compact JWS');
    }
    hoisted.throwString = true;
    try {
      expect(await receiveSET('a.b.c', publicKey, opts())).toEqual({ ok: false, code: 'malformed', reason: 'not a canonical compact JWS' });
    } finally {
      hoisted.throwString = false;
    }
  });
  it('verify_failed: a non-Error throw gets the fixed text', async () => {
    const { privateKey } = await keys();
    const set = await sign(privateKey, claims());
    const key = (async () => {
      throw 'boom';
    }) as unknown as VerifyKey;
    expect(await receiveSET(set, key, opts())).toEqual({ ok: false, code: 'verify_failed', reason: 'verification failed' });
  });
  it('iat_missing: absent, non-numeric, and a non-finite number', async () => {
    const { publicKey, privateKey } = await keys();
    const missing = { ok: false, code: 'iat_missing', reason: 'SET has no numeric iat' };
    expect(await receiveSET(await sign(privateKey, claims({ iat: undefined })), publicKey, opts())).toEqual(missing);
    const raw = `{"iss":"${ISS}","aud":"${AUD}","jti":"j","iat":1e999,"events":{"${GR}":{"grant_ref":"g","event_timestamp":1}}}`;
    const infinite = await new CompactSign(new TextEncoder().encode(raw)).setProtectedHeader({ alg: 'EdDSA', typ: 'secevent+jwt' }).sign(privateKey);
    // a non-finite number never reaches the claim check: the strict-JSON gate refuses the exponent form first
    const refused = await receiveSET(infinite, publicKey, opts());
    expect(refused).toMatchObject({ ok: false, code: 'malformed' });
    expect((refused as { reason: string }).reason).toMatch(/^non-canonical compact JWS: bad-json \(strict JSON: exponent form is not allowed/);
    expect(await receiveSET(await sign(privateKey, claims({ iat: 'x' })), publicKey, opts())).toEqual(missing);
  });
  it('iat_future and iat_stale carry their exact reasons', async () => {
    const { publicKey, privateKey } = await keys();
    expect(await receiveSET(await sign(privateKey, claims({ iat: NOW + 61 })), publicKey, opts())).toEqual({
      ok: false,
      code: 'iat_future',
      reason: 'SET iat is in the future',
    });
    expect(await receiveSET(await sign(privateKey, claims({ iat: NOW - 3601 })), publicKey, opts())).toEqual({
      ok: false,
      code: 'iat_stale',
      reason: 'SET is older than 3600s',
    });
  });
  it('unmapped_subject: Error message kept, non-Error throw gets the fixed text', async () => {
    const { publicKey, privateKey } = await keys();
    const ev = { [EVENT_TYPES.sessionRevoked]: { event_timestamp: NOW } };
    const set = await sign(privateKey, claims({ events: ev }));
    const r = await receiveSET(set, publicKey, opts({ standardRevocations: { failOnUnmapped: true } }));
    expect(r).toEqual({ ok: false, code: 'unmapped_subject', reason: `event '${EVENT_TYPES.sessionRevoked}' names no mappable agent` });
    const throwing = {
      get subjectToAgent(): never {
        throw 'boom';
      },
    };
    expect(await receiveSET(set, publicKey, opts({ standardRevocations: throwing }))).toEqual({
      ok: false,
      code: 'unmapped_subject',
      reason: 'a revocation event could not be mapped to an agent',
    });
  });
  it('replay_store_error: Error message kept, non-Error throw gets the fixed text, SET not applied', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await sign(privateKey, claims());
    const state = createRevocationState();
    const store = (thrown: unknown): SetReplayStore => ({
      addIfAbsent() {
        throw thrown;
      },
    });
    expect(await receiveSET(set, publicKey, opts({ state, replayStore: store(new Error('db down')) }))).toEqual({
      ok: false,
      code: 'replay_store_error',
      reason: 'db down',
    });
    expect(await receiveSET(set, publicKey, opts({ state, replayStore: store('db down') }))).toEqual({
      ok: false,
      code: 'replay_store_error',
      reason: 'replay store failed',
    });
    expect(state.revokedGrants.size).toBe(0);
  });
});

describe('planStandardRevocations subject mapping', () => {
  const sr = EVENT_TYPES.sessionRevoked;
  it('skips an undefined event', () => {
    expect(planStandardRevocations(manual({ [sr]: undefined }))).toEqual({ agents: [], unmapped: [] });
  });
  it('the default mapper accepts only an opaque subject with a non-empty string id', () => {
    const plan = (subject: unknown) => planStandardRevocations(manual({ [sr]: { subject, event_timestamp: 2 } }));
    expect(plan(opaque('a'))).toEqual({ agents: [['a', 2]], unmapped: [] });
    for (const subject of [{ format: 'email', id: 'abc' }, { format: 'iss_sub', id: 'abc' }, { format: 'opaque', id: 5 }, { format: 'opaque', id: '' }, { format: 'opaque' }]) {
      expect(plan(subject)).toEqual({ agents: [], unmapped: [sr] });
    }
  });
  it('no subject at all is unmapped, not an error', () => {
    expect(planStandardRevocations(manual({ [sr]: { event_timestamp: 2 } }))).toEqual({ agents: [], unmapped: [sr] });
  });
  it('a subject without a string format is not handed to the mapper', () => {
    const seen: unknown[] = [];
    const subjectToAgent = (s: { id?: unknown }) => {
      seen.push(s);
      return s.id as string;
    };
    const plan = planStandardRevocations(manual({ [sr]: { subject: { id: 'z' }, event_timestamp: 2 } }), { subjectToAgent });
    expect(plan).toEqual({ agents: [], unmapped: [sr] });
    expect(seen).toEqual([]);
  });
  it('a mapper returning an empty string, a non-string, or throwing leaves the subject unmapped', () => {
    for (const subjectToAgent of [() => '', () => 5 as unknown as string, () => undefined, () => { throw new Error('x'); }]) {
      expect(planStandardRevocations(manual({ [sr]: { subject: opaque('a'), event_timestamp: 2 } }), { subjectToAgent })).toEqual({
        agents: [],
        unmapped: [sr],
      });
    }
  });
  it('failOnUnmapped throws a SignalsError with the exact code and message', () => {
    const e = err(() => planStandardRevocations(manual({ [sr]: { event_timestamp: 2 } }), { failOnUnmapped: true })) as SignalsError;
    expect(e).toBeInstanceOf(SignalsError);
    expect(e.code).toBe('unmapped_subject');
    expect(e.message).toBe(`event '${sr}' names no mappable agent`);
  });
});

describe('state validation', () => {
  const bad = [{}, { revokedGrants: new Map() }, { revokedGrants: new Map(), killedAgents: [] }, { revokedGrants: [], killedAgents: new Map() }, null, 'x'];
  const expectMisconfigured = (fn: () => unknown) => {
    const e = err(fn) as SignalsError;
    expect(e).toBeInstanceOf(SignalsError);
    expect(e.name).toBe('SignalsError');
    expect(e.code).toBe('misconfigured');
    expect(e.message).toBe('state must come from createRevocationState()');
  };
  it('applyStandardRevocations, snapshot, restore and the hook all validate state', () => {
    for (const s of bad) {
      expectMisconfigured(() => applyStandardRevocations(s as unknown as RevocationState, manual({})));
      expectMisconfigured(() => snapshotRevocationState(s as unknown as RevocationState));
      expectMisconfigured(() => restoreRevocationState({ v: 1, grants: [], agents: [], intents: [] }, s as unknown as RevocationState));
      expectMisconfigured(() => createRevocationHook(s as unknown as RevocationState));
    }
  });
});

describe('revocation hook edge cases', () => {
  const hookOf = (s: RevocationState) => createRevocationHook(s);
  const ctx = (pcactn: unknown, grant: unknown): VerifyContext => ({ pcactn: pcactn as PCActn, grant: grant as Capability });
  it('a PCActn without a grant_ref is denied as missing', async () => {
    const h = hookOf(createRevocationState());
    expect(await h(ctx({ cap_chain: [{ holder: 'h' }] }, { id: 'c' }))).toEqual({ enforced: true, ok: false, reason: 'grant_ref is missing' });
    expect(await h(ctx({ grant_ref: '', cap_chain: [{ holder: 'h' }] }, { id: 'c' }))).toEqual({ enforced: true, ok: false, reason: 'grant_ref is missing' });
  });
  it('an undefined grant is tolerated and decided by the agent alone', async () => {
    const s = createRevocationState();
    const h = hookOf(s);
    const pcactn = { grant_ref: 'g', cap_chain: [{ holder: 'h' }] };
    expect(await h(ctx(pcactn, undefined))).toEqual({ enforced: true, ok: true });
    s.killedAgents.set('h', 1);
    expect(await h(ctx(pcactn, undefined))).toEqual({ enforced: true, ok: false, reason: 'agent killed by signal' });
  });
});

describe('snapshot and restore', () => {
  it('a state without an intent map snapshots to an empty intents list', () => {
    expect(snapshotRevocationState(createRevocationState())).toEqual({ v: 1, grants: [], agents: [], intents: [] });
  });
  const code = (fn: () => unknown) => err(fn) as SignalsError;
  const snap = (over: Record<string, unknown> = {}) => ({ v: 1, grants: [], agents: [], intents: [], ...over });
  it('rejects a non-array section with the exact message and code', () => {
    for (const k of ['grants', 'agents', 'intents']) {
      const e = code(() => restoreRevocationState(snap({ [k]: 'x' })));
      expect(e).toBeInstanceOf(SignalsError);
      expect(e.code).toBe('bad_snapshot');
      expect(e.message).toBe(`${k} is not an array`);
      const missing = code(() => restoreRevocationState(snap({ [k]: undefined })));
      expect(missing.message).toBe(`${k} is not an array`);
    }
  });
  it('rejects every malformed entry shape on its own', () => {
    const entries: unknown[] = [5, 'ab', ['a'], ['a', 1, 2], [5, 1], ['', 1], ['a', 'x'], ['a', Number.NaN], ['a', Infinity], ['a', null], null];
    for (const entry of entries) {
      const e = code(() => restoreRevocationState(snap({ grants: [entry] })));
      expect(e).toBeInstanceOf(SignalsError);
      expect(e.code).toBe('bad_snapshot');
      expect(e.message).toBe('grants holds an entry that is not [string, number]');
    }
  });
  it('rejects a wrong version and unknown members with the bad_snapshot code', () => {
    expect(code(() => restoreRevocationState(snap({ v: 2 }))).code).toBe('bad_snapshot');
    expect(code(() => restoreRevocationState(snap({ v: 2 }))).message).toBe('snapshot is not a version 1 object');
    expect(code(() => restoreRevocationState([])).message).toBe('snapshot is not a version 1 object');
    const e = code(() => restoreRevocationState(snap({ extra: 1 })));
    expect(e.code).toBe('bad_snapshot');
    expect(e.message).toBe("snapshot has unknown member 'extra'");
  });
  it('a failed restore leaves the target untouched; a good one merges monotonically', () => {
    const into = createRevocationState();
    into.revokedGrants.set('g', 9);
    expect(() => restoreRevocationState(snap({ grants: [['g', 1]], agents: 'x' }), into)).toThrow();
    expect([...into.revokedGrants]).toEqual([['g', 9]]);
    restoreRevocationState(snap({ grants: [['g', 1], ['h', 2]], agents: [['a', 3]], intents: [['pca-intent:i', 4]] }), into);
    expect(into.revokedGrants).toEqual(new Map([['g', 9], ['h', 2]]));
    expect(into.killedAgents).toEqual(new Map([['a', 3]]));
    expect(into.revokedIntentIds).toEqual(new Map([['pca-intent:i', 4]]));
  });
});
