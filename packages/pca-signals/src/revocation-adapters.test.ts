/** Standard CAEP/RISC events -> revocation entries, the authorize() revocation adapters, snapshots, the bounded replay store. */
import { SignJWT, generateKeyPair, type KeyLike } from 'jose';
import { describe, expect, it } from 'vitest';
import type { Capability, PCActn, VerifyContext } from '@atlasauth/pca';
import {
  EVENT_TYPES,
  RISC_EVENT_TYPES,
  SET_INMEMORY_MAX_ENTRIES,
  SignalsError,
  applySET,
  applyStandardRevocations,
  createInMemorySetReplayStore,
  createIsRevoked,
  createRevocationHook,
  createRevocationState,
  planStandardRevocations,
  receiveSET,
  restoreRevocationState,
  runSetReplayStoreConformance,
  snapshotRevocationState,
  type ParsedSet,
  type SetEvents,
} from './index';

const ISS = 'https://transmitter.example';
const AUD = 'https://rs.example';
const NOW = 1_800_000_000;

const parsed = (events: SetEvents, sub_id?: unknown): ParsedSet => ({ events, iss: ISS, jti: 'j', payload: { events, ...(sub_id !== undefined ? { sub_id } : {}) } as ParsedSet['payload'] });
const opaque = (id: string) => ({ format: 'opaque', id });
const ctx = (grantRef: string, holder: string, grantId = 'cap-root'): VerifyContext =>
  ({ pcactn: { grant_ref: grantRef, cap_chain: [{ holder: 'root-holder' }, { holder }] } as unknown as PCActn, grant: { id: grantId } as unknown as Capability });
const fail = (reason: string) => ({ enforced: true, ok: false, reason });

describe('planStandardRevocations', () => {
  it('session-revoked with an event subject maps to that agent with its timestamp', () => {
    const p = parsed({ [EVENT_TYPES.sessionRevoked]: { subject: opaque('agent-1'), event_timestamp: 50 } });
    expect(planStandardRevocations(p)).toEqual({ agents: [['agent-1', 50]], unmapped: [] });
  });
  it('falls back to the SET-level sub_id; an event subject wins over it', () => {
    const ev = { event_timestamp: 7 };
    expect(planStandardRevocations(parsed({ [EVENT_TYPES.sessionRevoked]: ev }, opaque('set-sub')))).toEqual({ agents: [['set-sub', 7]], unmapped: [] });
    const own = { subject: opaque('own'), event_timestamp: 7 };
    expect(planStandardRevocations(parsed({ [EVENT_TYPES.sessionRevoked]: own }, opaque('set-sub')))).toEqual({ agents: [['own', 7]], unmapped: [] });
  });
  it.each(['revoke', 'update', 'delete', undefined, 'bogus'])('credential-change %s revokes', (change_type) => {
    const p = parsed({ [EVENT_TYPES.credentialChange]: { subject: opaque('a'), event_timestamp: 1, ...(change_type !== undefined ? { change_type: change_type as 'revoke' } : {}) } });
    expect(planStandardRevocations(p).agents).toEqual([['a', 1]]);
  });
  it('credential-change create does not revoke', () => {
    const p = parsed({ [EVENT_TYPES.credentialChange]: { subject: opaque('a'), event_timestamp: 1, change_type: 'create' } });
    expect(planStandardRevocations(p)).toEqual({ agents: [], unmapped: [] });
  });
  it.each(Object.values(RISC_EVENT_TYPES))('RISC %s revokes', (type) => {
    expect(planStandardRevocations(parsed({ [type]: { subject: opaque('a'), event_timestamp: 3 } as never })).agents).toEqual([['a', 3]]);
  });
  it('RISC type URIs are exactly the published ones', () => {
    expect(RISC_EVENT_TYPES).toEqual({
      sessionsRevoked: 'https://schemas.openid.net/secevent/risc/event-type/sessions-revoked',
      accountDisabled: 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
      accountPurged: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
      credentialCompromise: 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
    });
  });
  it('unknown event types and PCA event types are ignored here', () => {
    const p = parsed({ 'https://x.example/e': { subject: opaque('a'), event_timestamp: 1 } as never, [EVENT_TYPES.grantRevoked]: { grant_ref: 'g', reason: 'r', event_timestamp: 1 } });
    expect(planStandardRevocations(p)).toEqual({ agents: [], unmapped: [] });
  });
  it('unmappable subjects are reported, not silently dropped; failOnUnmapped throws', () => {
    for (const subject of [undefined, { format: 'email', email: 'a@b.example' }, { format: 'opaque' }, { format: 'opaque', id: '' }]) {
      const p = parsed({ [EVENT_TYPES.sessionRevoked]: { event_timestamp: 1, ...(subject ? { subject } : {}) } });
      expect(planStandardRevocations(p)).toEqual({ agents: [], unmapped: [EVENT_TYPES.sessionRevoked] });
      expect(() => planStandardRevocations(p, { failOnUnmapped: true })).toThrow(SignalsError);
    }
  });
  it('a custom subjectToAgent is used; one that throws or returns nothing counts as unmapped', () => {
    const p = parsed({ [EVENT_TYPES.sessionRevoked]: { subject: { format: 'email', email: 'a@b.example' }, event_timestamp: 2 } });
    expect(planStandardRevocations(p, { subjectToAgent: (s) => String(s['email']) }).agents).toEqual([['a@b.example', 2]]);
    expect(planStandardRevocations(p, { subjectToAgent: () => { throw new Error('x'); } }).unmapped).toEqual([EVENT_TYPES.sessionRevoked]);
    expect(planStandardRevocations(p, { subjectToAgent: () => undefined }).unmapped).toEqual([EVENT_TYPES.sessionRevoked]);
  });
  it('a missing event_timestamp is recorded as 0', () => {
    const p = parsed({ [EVENT_TYPES.sessionRevoked]: { subject: opaque('a') } as never });
    expect(planStandardRevocations(p).agents).toEqual([['a', 0]]);
  });
});

describe('applyStandardRevocations', () => {
  it('records the max timestamp and never lowers it', () => {
    const s = createRevocationState();
    applyStandardRevocations(s, parsed({ [EVENT_TYPES.sessionRevoked]: { subject: opaque('a'), event_timestamp: 9 } }));
    applyStandardRevocations(s, parsed({ [EVENT_TYPES.sessionRevoked]: { subject: opaque('a'), event_timestamp: 4 } }));
    expect([...s.killedAgents]).toEqual([['a', 9]]);
  });
  it('a failing plan leaves the state untouched', () => {
    const s = createRevocationState();
    const p = parsed({ [EVENT_TYPES.sessionRevoked]: { subject: opaque('a'), event_timestamp: 1 }, [RISC_EVENT_TYPES.accountDisabled]: { event_timestamp: 1 } as never });
    expect(() => applyStandardRevocations(s, p, { failOnUnmapped: true })).toThrow(SignalsError);
    expect(s.killedAgents.size).toBe(0);
  });
  it('a state that did not come from createRevocationState is a misconfiguration', () => {
    expect(() => applyStandardRevocations({} as never, parsed({}))).toThrow(new SignalsError('misconfigured', 'state must come from createRevocationState()'));
  });
});

describe('createRevocationHook / createIsRevoked (the authorize() revocation source)', () => {
  it('nothing revoked: enforced and ok', () => {
    const s = createRevocationState();
    expect(createRevocationHook(s)(ctx('g1', 'agent-a'))).toEqual({ enforced: true, ok: true });
    expect(createIsRevoked(s)(ctx('g1', 'agent-a').grant, ctx('g1', 'agent-a').pcactn)).toBe(false);
  });
  it('a revoked grant_ref, a revoked root capability id and a killed leaf holder each deny, with their reason', () => {
    const s = createRevocationState();
    const hook = createRevocationHook(s);
    s.revokedGrants.set('g1', 1);
    expect(hook(ctx('g1', 'agent-a'))).toEqual(fail('grant revoked by signal'));
    expect(hook(ctx('g2', 'agent-a', 'g1'))).toEqual(fail('grant revoked by signal'));
    s.killedAgents.set('agent-a', 1);
    expect(hook(ctx('g2', 'agent-a'))).toEqual(fail('agent killed by signal'));
    expect(hook(ctx('g2', 'agent-b'))).toEqual({ enforced: true, ok: true });
  });
  it('the state is read live: a SET folded in after the hook was built takes effect', () => {
    const s = createRevocationState();
    const hook = createRevocationHook(s);
    expect(hook(ctx('g1', 'a'))).toEqual({ enforced: true, ok: true });
    applySET(s, parsed({ [EVENT_TYPES.grantRevoked]: { grant_ref: 'g1', reason: 'r', event_timestamp: 1 } }));
    expect(hook(ctx('g1', 'a'))).toEqual(fail('grant revoked by signal'));
  });
  it('fails closed on undeterminable input', () => {
    const hook = createRevocationHook(createRevocationState());
    expect(hook(ctx('', 'a'))).toEqual(fail('grant_ref is missing'));
    expect(hook(ctx('g', ''))).toEqual(fail('agent could not be determined'));
    expect(hook({ pcactn: { grant_ref: 'g', cap_chain: [] } as unknown as PCActn, grant: { id: 'x' } as unknown as Capability })).toEqual(fail('agent could not be determined'));
    expect(hook({ pcactn: null as unknown as PCActn, grant: null as unknown as Capability })).toEqual(fail('revocation check error (fail closed)'));
    const isRev = createIsRevoked(createRevocationState());
    expect(isRev(null as unknown as Capability, null as unknown as PCActn)).toBe(true);
  });
  it('agentOf overrides how the agent is named; one that throws denies', () => {
    const s = createRevocationState();
    s.killedAgents.set('custom', 1);
    expect(createRevocationHook(s, { agentOf: () => 'custom' })(ctx('g', 'a'))).toEqual(fail('agent killed by signal'));
    expect(createRevocationHook(s, { agentOf: () => { throw new Error('x'); } })(ctx('g', 'a'))).toEqual(fail('revocation check error (fail closed)'));
    expect(createIsRevoked(s, { agentOf: () => 'custom' })(ctx('g', 'a').grant, ctx('g', 'a').pcactn)).toBe(true);
  });
  it('a foreign state object is a misconfiguration', () => {
    expect(() => createRevocationHook({} as never)).toThrow(SignalsError);
    expect(() => createIsRevoked(null as never)).toThrow(SignalsError);
  });
});

describe('receiveSET with standardRevocations', () => {
  async function signed(key: KeyLike, events: unknown, jti: string, extra: Record<string, unknown> = {}) {
    return new SignJWT({ iss: ISS, aud: AUD, iat: NOW, jti, events, ...extra }).setProtectedHeader({ alg: 'EdDSA', typ: 'secevent+jwt' }).sign(key);
  }
  const base = (over = {}) => ({ issuer: ISS, audience: AUD, replayStore: createInMemorySetReplayStore(), state: createRevocationState(), maxAgeSec: 3600, nowSec: NOW, ...over });
  const sess = { [EVENT_TYPES.sessionRevoked]: { subject: opaque('agent-1'), event_timestamp: NOW } };

  it('applies a standard revocation only when asked to', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const off = base();
    expect((await receiveSET(await signed(privateKey, sess, 'a'), publicKey, off)).ok).toBe(true);
    expect(off.state.killedAgents.size).toBe(0);
    const on = base({ standardRevocations: {} });
    expect((await receiveSET(await signed(privateKey, sess, 'b'), publicKey, on)).ok).toBe(true);
    expect([...on.state.killedAgents]).toEqual([['agent-1', NOW]]);
  });
  it('an unmappable subject under failOnUnmapped is refused and does not burn the jti', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const o = base({ standardRevocations: { failOnUnmapped: true } });
    const set = await signed(privateKey, { [EVENT_TYPES.sessionRevoked]: { event_timestamp: NOW } }, 'c');
    const r = await receiveSET(set, publicKey, o);
    expect(r).toEqual({ ok: false, code: 'unmapped_subject', reason: "event 'https://schemas.openid.net/secevent/caep/event-type/session-revoked' names no mappable agent" });
    expect(o.state.killedAgents.size).toBe(0);
    expect(await o.replayStore.addIfAbsent('c', NOW + 7200, NOW)).toBe(true);
  });
});

describe('snapshot / restore', () => {
  it('round-trips grants, agents and intent ids', () => {
    const s = createRevocationState();
    s.revokedGrants.set('g', 1);
    s.killedAgents.set('a', 2);
    s.revokedIntentIds = new Map([['pca-intent:session:x', 3]]);
    const snap = snapshotRevocationState(s);
    expect(snap).toEqual({ v: 1, grants: [['g', 1]], agents: [['a', 2]], intents: [['pca-intent:session:x', 3]] });
    const r = restoreRevocationState(JSON.parse(JSON.stringify(snap)));
    expect([[...r.revokedGrants], [...r.killedAgents], [...(r.revokedIntentIds ?? [])]]).toEqual([[['g', 1]], [['a', 2]], [['pca-intent:session:x', 3]]]);
  });
  it('restoring is monotone: it never lowers or removes anything already present', () => {
    const into = createRevocationState();
    into.revokedGrants.set('g', 10);
    into.revokedGrants.set('keep', 1);
    restoreRevocationState({ v: 1, grants: [['g', 2]], agents: [], intents: [] }, into);
    expect([...into.revokedGrants]).toEqual([['g', 10], ['keep', 1]]);
  });
  it.each([
    [null, 'snapshot is not a version 1 object'],
    [{ v: 2, grants: [], agents: [], intents: [] }, 'snapshot is not a version 1 object'],
    [{ v: 1, grants: [], agents: [], intents: [], extra: 1 }, "snapshot has unknown member 'extra'"],
    [{ v: 1, grants: 'x', agents: [], intents: [] }, 'grants is not an array'],
    [{ v: 1, grants: [['g']], agents: [], intents: [] }, 'grants holds an entry that is not [string, number]'],
    [{ v: 1, grants: [], agents: [['', 1]], intents: [] }, 'agents holds an entry that is not [string, number]'],
    [{ v: 1, grants: [], agents: [], intents: [['i', Number.NaN]] }, 'intents holds an entry that is not [string, number]'],
  ])('malformed snapshot %j is refused with bad_snapshot and nothing is merged', (snap, message) => {
    const into = createRevocationState();
    expect(() => restoreRevocationState(snap, into)).toThrow(new SignalsError('bad_snapshot', message));
    expect(into.revokedGrants.size + into.killedAgents.size).toBe(0);
  });
  it('a partially valid snapshot merges nothing', () => {
    const into = createRevocationState();
    expect(() => restoreRevocationState({ v: 1, grants: [['g', 1]], agents: [['a']], intents: [] }, into)).toThrow(SignalsError);
    expect(into.revokedGrants.size).toBe(0);
  });
});

describe('bounded in-memory replay store', () => {
  it('capacity constant and conformance', async () => {
    expect(SET_INMEMORY_MAX_ENTRIES).toBe(100_000);
    expect(await runSetReplayStoreConformance(() => createInMemorySetReplayStore())).toEqual([]);
  });
  it('a full store throws instead of evicting; expired entries are reclaimed at nowSec >= expiresAtSec', () => {
    const s = createInMemorySetReplayStore({ maxEntries: 1 });
    expect(s.addIfAbsent('a', 200, 100)).toBe(true);
    expect(() => s.addIfAbsent('b', 400, 199)).toThrow('replay store is full');
    expect(s.addIfAbsent('a', 200, 150)).toBe(false);
    expect(s.addIfAbsent('b', 400, 200)).toBe(true);
  });
  it('receiveSET refuses with replay_store_error when the store is full', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const store = createInMemorySetReplayStore({ maxEntries: 1 });
    const mk = (jti: string) => new SignJWT({ iss: ISS, aud: AUD, iat: NOW, jti, events: { [EVENT_TYPES.grantRevoked]: { grant_ref: jti, reason: 'r', event_timestamp: NOW } } }).setProtectedHeader({ alg: 'EdDSA', typ: 'secevent+jwt' }).sign(privateKey);
    const o = { issuer: ISS, audience: AUD, replayStore: store, state: createRevocationState(), maxAgeSec: 3600, nowSec: NOW };
    expect((await receiveSET(await mk('one'), publicKey, o)).ok).toBe(true);
    expect(await receiveSET(await mk('two'), publicKey, o)).toEqual({ ok: false, code: 'replay_store_error', reason: 'replay store is full' });
    expect(o.state.revokedGrants.has('two')).toBe(false);
  });
  it.each([0, -1, 1.5, Number.NaN])('maxEntries %s is a misconfiguration', (n) => {
    expect(() => createInMemorySetReplayStore({ maxEntries: n })).toThrow(new SignalsError('misconfigured', 'maxEntries must be a positive integer'));
  });
});
