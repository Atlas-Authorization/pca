/**
 * r13 (g3) mutation kills, rule 15 (`accumulators`) with ABSENT verifier lists: no `schema` context means no session
 * schema document, and no `acc.receipts` means no receipt, whatever digest the PCActn names. The PCActn here names the
 * digest of an arbitrary non-document value (the string 'Stryker was here'): an absent list must never be replaced by a
 * list holding some value whose digest an agent can compute and claim.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { actionSchemaDigest } from './action-schema';
import { b64u } from './hash';
import { type AccumulatorDecl, accReceiptDigest } from './intent-acc';
import { type SessionRootBody, sessionRootDigest, signSessionRoot } from './intent-session';
import { decideIntentV2 } from './intent-v2';
import { publicKeyOf } from './keys';

const seed = (l: string) => new Uint8Array(createHash('sha256').update(`r13-g3-acc/${l}`).digest());
const dg = (l: string) => b64u(seed('dg/' + l));
const P = { sk: seed('principal'), pk: b64u(publicKeyOf(seed('principal'))) };
const SEQ_ROOT = b64u(publicKeyOf(seed('sequencer-root')));
const ARBITRARY = 'Stryker was here';
const NOW = 1_800_000_000_000;
const AUD = 'shop.example';

const rootWith = (acc: AccumulatorDecl) => {
  const body: SessionRootBody = {
    v: 1, kind: 'pca-intent-session', session: dg('session'), principals: [{ key: P.pk }], intent_ref: dg('ref'),
    schema: { aud: AUD, digest: dg('schema') }, layers: { task: { map_digest: dg('map') } }, accumulators: [acc], monitors: [],
    question_uri: 'https://principal.example/q', expires_at: NOW + 3_600_000,
  };
  return signSessionRoot(body, P.sk);
};
const accCheck = (acc: AccumulatorDecl, is: Record<string, unknown>, ctx: Record<string, unknown>) => {
  const S = rootWith(acc);
  const p = { aud: AUD, action: { verb: 'shop.buy', resource: 'r', params_digest: dg('pd') }, intent: { ref: dg('ref'), map_digest: dg('map') }, intent_session: { session: S.session, root: sessionRootDigest(S), seq: 0, ...is } };
  const d = decideIntentV2(p as never, { caveats: [] } as never, { session: { root: S }, ...ctx } as never, NOW);
  return d.checks.find((c) => c.name === 'accumulators');
};

describe('rule 15 with absent verifier lists', () => {
  it('no schema context: an accumulates_into selector has no session schema, even when intent_session.schema is the digest of some value', () => {
    const TRIP: AccumulatorDecl = { id: 'trip_spend', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } };
    const want = { name: 'accumulators', ok: false, reason: "accumulator 'trip_spend' selects by accumulates_into but the session schema is not available" };
    expect(accCheck(TRIP, { schema: actionSchemaDigest(ARBITRARY as never) }, {})).toEqual(want);
    expect(accCheck(TRIP, { schema: dg('other') }, {})).toEqual(want);
  });
  it('no presented receipts: a claim naming the digest of some value is "not presented"', () => {
    const N: AccumulatorDecl = { id: 'n', agg: 'count', sel: { verbs: ['shop.buy'] }, win: { kind: 'task' }, key: null, holder: { kind: 'sequenced', uri: 'https://seq.example', root: SEQ_ROOT } };
    const want = { name: 'accumulators', ok: false, reason: "the reservation receipt for 'n' was not presented" };
    expect(accCheck(N, { schema: dg('schema'), acc: [{ id: 'n', post: 1, receipt: accReceiptDigest(ARBITRARY as never) }] }, { params: {} })).toEqual(want);
    expect(accCheck(N, { schema: dg('schema'), acc: [{ id: 'n', post: 1, receipt: dg('rc') }] }, { params: {} })).toEqual(want);
  });
});
