/**
 * r13 (g3) mutation kills, rule 15 sequenced receipts and decideIntentV2 edges, measured on the box: a VALIDLY SIGNED
 * receipt for another session or accumulator, the expiry boundary (expires_at itself is still valid), the replay bound
 * (a seq above the last accepted passes), no env when no check filled it, an empty policy.schema, and a missing PCActn
 * view under a malformed context.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { type AccumulatorDecl, accReceiptDigest, pcactnReservationDigest, signAccReceipt, signSequencerKeySet } from './intent-acc';
import { sessionRootDigest, signSessionRoot } from './intent-session';
import { decideIntentV2, intentV2ContextError } from './intent-v2';
import { publicKeyOf } from './keys';

const seed = (l: string) => new Uint8Array(createHash('sha256').update(`r13-g3-rc/${l}`).digest());
const dg = (l: string) => b64u(seed('dg/' + l));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const P = key('principal');
const ROOTK = key('sequencer-root');
const SEQ = key('sequencer');
const NOW = 1_800_000_000_000;
const AUD = 'shop.example';
const SESSION = dg('session');
const N: AccumulatorDecl = { id: 'n', agg: 'count', sel: { verbs: ['shop.buy'] }, win: { kind: 'task' }, key: null, holder: { kind: 'sequenced', uri: 'https://seq.example', root: ROOTK.pk } };
const S = signSessionRoot({
  v: 1, kind: 'pca-intent-session', session: SESSION, principals: [{ key: P.pk }], intent_ref: dg('ref'),
  schema: { aud: AUD, digest: dg('schema') }, layers: { task: { map_digest: dg('map') } }, accumulators: [N], monitors: [],
  question_uri: 'https://principal.example/q', expires_at: NOW + 3_600_000,
}, P.sk);
const KS = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW - 5_000, keys: [{ kid: 's1', pk: SEQ.pk, not_before: NOW - 10_000 }] }, ROOTK.sk);
const view = { aud: AUD, action: { verb: 'shop.buy', resource: 'r', params_digest: dg('pd') }, intent: { ref: dg('ref'), map_digest: dg('map') } };
const receipt = (over: Record<string, unknown> = {}) => signAccReceipt({
  v: 1, kind: 'pca-acc-receipt', session: SESSION, acc: 'n', seq: 5, pre: 0, delta: 1, post: 1, pcactn_digest: pcactnReservationDigest(view as never),
  aud: AUD, issued_at: NOW - 1_000, expires_at: NOW + 60_000, kid: 's1', ledger: { index: 0, head: dg('head') }, ...over,
} as never, SEQ.sk);
const accCheck = (rc: ReturnType<typeof receipt>, o: { now?: number; last?: number } = {}) => {
  const p = { ...view, intent_session: { session: SESSION, root: sessionRootDigest(S), seq: 0, schema: dg('schema'), acc: [{ id: 'n', post: 1, receipt: accReceiptDigest(rc) }] } };
  const ctx = { session: { root: S }, params: {}, acc: { receipts: [rc], sequencer_keys: [KS], ...(o.last !== undefined ? { last_seq: { n: o.last } } : {}) } };
  return decideIntentV2(p as never, { caveats: [] } as never, ctx as never, o.now ?? NOW).checks.find((c) => c.name === 'accumulators');
};

describe('rule 15: sequenced receipts', () => {
  it('a receipt bound to this session, accumulator, audience and action passes', () => {
    expect(accCheck(receipt())).toEqual({ name: 'accumulators', ok: true });
  });
  it('a validly signed receipt for another session, or another accumulator, is refused', () => {
    const want = { name: 'accumulators', ok: false, reason: "the reservation receipt for 'n' is for another session, accumulator or audience" };
    expect(accCheck(receipt({ session: dg('other') }))).toEqual(want);
    expect(accCheck(receipt({ acc: 'm' }))).toEqual(want);
  });
  it('expires_at is the last valid instant', () => {
    const rc = receipt({ expires_at: NOW + 10 });
    expect(accCheck(rc, { now: NOW + 10 })).toEqual({ name: 'accumulators', ok: true });
    expect(accCheck(rc, { now: NOW + 11 })).toEqual({ name: 'accumulators', ok: false, reason: "the reservation receipt for 'n' has expired" });
  });
  it('the replay bound: a seq above the last accepted passes, the same seq does not', () => {
    expect(accCheck(receipt(), { last: 4 })).toEqual({ name: 'accumulators', ok: true });
    expect(accCheck(receipt(), { last: 5 })).toEqual({ name: 'accumulators', ok: false, reason: "the reservation receipt for 'n' replays seq 5 (last accepted 5)" });
  });
});

describe('decideIntentV2 edges', () => {
  it('no env when no check filled it (a failed accumulators check adds nothing; W-B denies, so it adds nothing either)', () => {
    const p = { ...view, intent_session: { session: SESSION, root: sessionRootDigest(S), seq: 0, schema: dg('schema'), classes: [dg('class')] } };
    const d = decideIntentV2(p as never, { caveats: [] } as never, { session: { root: S }, params: {} } as never, NOW);
    expect(d.checks.find((c) => c.name === 'accumulators')).toEqual({ name: 'accumulators', ok: false, reason: "no claim for accumulator 'n' that this action feeds" });
    expect(d.checks.at(-1)).toMatchObject({ name: 'classes', ok: false });
    expect(d.env).toBeUndefined();
    expect('env' in d).toBe(false);
  });
  it('an empty policy.schema is well formed (closed_world absent = default)', () => {
    expect(intentV2ContextError({ policy: { schema: {} } })).toBeNull();
    expect(intentV2ContextError({ policy: { schema: { closed_world: false } } })).toBeNull();
    expect(intentV2ContextError({ policy: { schema: { closed_world: 1 } } })).toBe('policy.schema.closed_world must be a boolean');
  });
  it('a missing PCActn view under a malformed context still fails closed (no throw)', () => {
    expect(() => decideIntentV2(undefined as never, {} as never, { policy: 1 } as never, NOW)).not.toThrow();
    const d = decideIntentV2(undefined as never, {} as never, { policy: 1 } as never, NOW);
    expect(d.checks).toEqual([
      { name: 'schema', ok: false, reason: 'malformed v2 context: policy must be an object' },
      { name: 'intent_session', ok: false, reason: 'malformed v2 context: policy must be an object' },
    ]);
  });
});
