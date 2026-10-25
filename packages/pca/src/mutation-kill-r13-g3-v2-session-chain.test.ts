/**
 * r13 (g3) mutation kills, rule 13 (`intent_session`) and rule 15 edges no golden case reaches: the admitting root's
 * session / root binding, an earlier grant bound to another root, a missing earlier-grant store, which grants feed the
 * revocation ids (only the first `seq` the verifier holds; no profile id without a standing profile), and the reason of
 * a malformed pre-state of an accumulator the action does not feed. decideIntentV2 is called directly (it does not
 * re-verify grant signatures), so the grants here are plain capability-shaped objects; the session root and the
 * revocation epochs are really signed.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import type { AccumulatorDecl } from './intent-acc';
import { deltaRevocationId, sessionRevocationScope } from './intent-revocation';
import { type SessionRootBody, sessionRootDigest, signSessionRoot } from './intent-session';
import { decideIntentV2 } from './intent-v2';
import { publicKeyOf } from './keys';
import { RevocationSet, signRevocationEpoch } from './revocation';

const seed = (l: string) => new Uint8Array(createHash('sha256').update(`r13-g3-chain/${l}`).digest());
const dg = (l: string) => b64u(seed('dg/' + l));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const P = key('principal');
const REV = key('revocation-authority');
const NOW = 1_800_000_000_000;
const AUD = 'shop.example';
const SESSION = dg('session');

const root = (over: Partial<SessionRootBody> = {}) => signSessionRoot({
  v: 1, kind: 'pca-intent-session', session: SESSION, principals: [{ key: P.pk }], intent_ref: dg('ref'),
  schema: { aud: AUD, digest: dg('schema') }, layers: { task: { map_digest: dg('map') } }, accumulators: [], monitors: [],
  question_uri: 'https://principal.example/q', expires_at: NOW + 3_600_000, ...over,
}, P.sk);
const grant = (id: string, cav: Record<string, unknown>) => ({ id, issuer: P.pk, holder: P.pk, caveats: [{ type: 'envelope' }, { type: 'intent_session', ...cav }] });
const pcactn = (S: ReturnType<typeof root>, seq: number) => ({
  aud: AUD, action: { verb: 'shop.buy', resource: 'r', params_digest: dg('pd') }, intent: { ref: dg('ref'), map_digest: dg('map') },
  intent_session: { session: SESSION, root: sessionRootDigest(S), seq, schema: dg('schema') },
});
const check = (d: ReturnType<typeof decideIntentV2>, name: string) => d.checks.find((c) => c.name === name);
const epoch = (revoked: string[]) => {
  const set = new RevocationSet(revoked);
  return { epoch: signRevocationEpoch(REV.sk, { instance_id: 'i', grant_ref: sessionRevocationScope(SESSION), epoch: set.size, set_size: set.size, root: set.root, issued_at: NOW - 1000, not_after: NOW + 300_000 }), revoked: set.list() };
};

describe('rule 13: the admitting root and the earlier grants', () => {
  const S = root();
  const R = sessionRootDigest(S);
  const G0 = grant(dg('g0'), { session: SESSION, seq: 0, root: R });
  it('a well-bound seq-0 admitting root passes (and with no accumulators, monitors or acc context, so does rule 15)', () => {
    const d = decideIntentV2(pcactn(S, 0) as never, G0 as never, { session: { root: S } }, NOW);
    expect(check(d, 'intent_session')).toEqual({ name: 'intent_session', ok: true });
    expect(check(d, 'accumulators')).toEqual({ name: 'accumulators', ok: true });
  });
  it('an admitting root bound to another session, or to another root, is refused', () => {
    const want = { name: 'intent_session', ok: false, reason: 'the admitting root is bound to another session, root or seq' };
    expect(check(decideIntentV2(pcactn(S, 0) as never, grant(dg('g0'), { session: dg('other'), seq: 0, root: R }) as never, { session: { root: S } }, NOW), 'intent_session')).toEqual(want);
    expect(check(decideIntentV2(pcactn(S, 0) as never, grant(dg('g0'), { session: SESSION, seq: 0, root: dg('other') }) as never, { session: { root: S } }, NOW), 'intent_session')).toEqual(want);
  });
  it('seq 1: the earlier grant must carry this root; without the earlier grants the verifier refuses', () => {
    const D1 = grant(dg('d1'), { session: SESSION, seq: 1, root: R, prev: G0.id });
    const ok = decideIntentV2(pcactn(S, 1) as never, D1 as never, { session: { root: S, grants: [G0] } } as never, NOW);
    expect(check(ok, 'intent_session')).toEqual({ name: 'intent_session', ok: true });
    const otherRoot = grant(G0.id, { session: SESSION, seq: 0, root: dg('other') });
    expect(check(decideIntentV2(pcactn(S, 1) as never, D1 as never, { session: { root: S, grants: [otherRoot] } } as never, NOW), 'intent_session'))
      .toEqual({ name: 'intent_session', ok: false, reason: 'session grant 0 does not belong to this session at seq 0' });
    for (const ctx of [{ session: { root: S } }, { session: { root: S, grants: [] } }]) {
      expect(check(decideIntentV2(pcactn(S, 1) as never, D1 as never, ctx as never, NOW), 'intent_session'))
        .toEqual({ name: 'intent_session', ok: false, reason: 'the verifier does not hold the 1 earlier grants of this session' });
    }
  });
});

describe('rule 13 step 7: the revocation ids', () => {
  const S = root({ revocation: { epoch_uri: 'https://rev.example/e', max_age_s: 60, key: REV.pk } });
  const R = sessionRootDigest(S);
  const G0 = grant(dg('g0'), { session: SESSION, seq: 0, root: R });
  it('at seq 0 an extra grant the verifier holds is not one of the ids (it is not part of this chain)', () => {
    const extra = { id: dg('extra') };
    const ev = epoch([deltaRevocationId(extra.id)]);
    expect(check(decideIntentV2(pcactn(S, 0) as never, G0 as never, { session: { root: S, revocation: ev, grants: [extra] } } as never, NOW), 'intent_session'))
      .toEqual({ name: 'intent_session', ok: true });
    // the admitting root itself is
    expect(check(decideIntentV2(pcactn(S, 0) as never, G0 as never, { session: { root: S, revocation: epoch([deltaRevocationId(G0.id)]) } } as never, NOW), 'intent_session'))
      .toEqual({ name: 'intent_session', ok: false, reason: `revocation: '${deltaRevocationId(G0.id)}' is revoked` });
  });
  it('without a standing profile no other id is checked: revoking arbitrary strings does not refuse the action', () => {
    const ev = epoch(['Stryker was here', 'pca-intent:profile:x@1', 'unrelated']);
    expect(check(decideIntentV2(pcactn(S, 0) as never, G0 as never, { session: { root: S, revocation: ev } } as never, NOW), 'intent_session'))
      .toEqual({ name: 'intent_session', ok: true });
  });
});

describe('rule 15: an accumulator the action does not feed', () => {
  it('a malformed site-local pre-state is refused with the pre-state reason (not an internal error)', () => {
    const A: AccumulatorDecl = { id: 'other_spend', agg: 'count', sel: { verbs: ['shop.refund'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
    const S = root({ accumulators: [A] });
    const G0 = grant(dg('g0'), { session: SESSION, seq: 0, root: sessionRootDigest(S) });
    const run = (pre: unknown) => check(decideIntentV2(pcactn(S, 0) as never, G0 as never, { session: { root: S }, acc: { state: { other_spend: pre } } } as never, NOW), 'accumulators');
    expect(run({ sum: 3 })).toEqual({ name: 'accumulators', ok: false, reason: "accumulator 'other_spend': pre-state of a count accumulator is {count}" });
    expect(run({ count: 7 })).toEqual({ name: 'accumulators', ok: true });
  });
});
