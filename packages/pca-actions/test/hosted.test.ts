// The hosted action registry: the publish gate (signed packs, version order, semantic diff, widening blocked unless reviewed,
// deprecation), the verifier view (unknown / unconfirmed / deprecated verbs are maximally restrictive; confirmed defs supply
// provenance facts, the rule 22 floor, rules and undo eligibility), and the source sync.
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  CORE_REGISTRY, RULES_DOC_KIND, action, buildArtifacts, businessRulesDigest, confirmDef, defDigest, hostedCallContext, hostedView, p,
  packKeyOf, publishGate, rateKeysOf, signPack, signRulesReview, syncSource, type ActionDef, type BusinessRules, type HostedVersion, type ReviewerPins,
} from '../src';

const publisher = generateKeyPair();
const reviewer = generateKeyPair();
const importer = generateKeyPair();
const PUB = [packKeyOf('pub-1', publisher.secretKey)];
const PINS: ReviewerPins = { keys: [{ kid: 'rev-1', pk: b64u(reviewer.publicKey), roles: ['reviewer'] }, { kid: 'imp-1', pk: b64u(importer.publicKey), roles: ['importer'] }] };

const R = 'acme.payment:pm_*';
const payment = (desc = 'Pays a customer.', max = 100_000_000): ActionDef =>
  action('acme.payment.send', { title: 'Send a payment', description: desc, effects: ['pay'], resource: R, params: { amount: p.money('USD', { max }), customer: p.id('acme.customer') }, since: '0.1.0' });
const getOrder = (): ActionDef =>
  action('acme.order.get', { title: 'Get an order', description: 'Reads an order.', effects: ['read'], resource: 'acme.order:or_*', params: { order: p.id('acme.order') }, since: '0.1.0' });
const draftCreate = (): ActionDef =>
  action('acme.draft.create', { title: 'Create a draft', description: 'Saves a draft.', effects: ['create'], resource: 'acme.draft:dr_*', params: { box: p.text(40), body: p.message(500) }, reversibility: 'reversible', compensates: 'acme.draft.delete', since: '0.1.0' });
const draftDelete = (): ActionDef =>
  action('acme.draft.delete', { title: 'Delete a draft', description: 'Deletes a draft.', effects: ['delete'], resource: 'acme.draft:dr_*', params: { box: p.text(40), draft: p.id('acme.draft') }, since: '0.1.0' });

const confirm = (d: ActionDef, kid = 'rev-1', secret = reviewer.secretKey): ActionDef =>
  confirmDef(JSON.parse(JSON.stringify(d)) as ActionDef, { registry: CORE_REGISTRY, reviewer: { kid, secret }, pins: kid === 'rev-1' ? PINS : undefined, finalTraits: [...(d.traits ?? [])].filter((t) => t !== 'pca.unreviewed'), ts: 1_700_000_000 } as never);

const packOf = (defs: ActionDef[], version: string, secret = publisher.secretKey, kid = 'pub-1') =>
  signPack(buildArtifacts(defs, { ns: 'acme', version, stability: 'draft', site: 'https://acme.example.com', aud: 'acme-api' }, CORE_REGISTRY).pack, kid, secret, CORE_REGISTRY);
const rulesDoc = (rules: Record<string, BusinessRules>, reviews: Record<string, unknown> = {}) => ({ v: 1, kind: RULES_DOC_KIND, ns: 'acme', rules, ...(Object.keys(reviews).length ? { reviews } : {}) });
const publish = (defs: ActionDef[], version: string, current?: HostedVersion, rules?: unknown) =>
  publishGate({ ...(current ? { current } : {}), pack: packOf(defs, version), ...(rules !== undefined ? { rules } : {}), publisherKeys: PUB, pins: PINS });
const ok = (g: ReturnType<typeof publishGate>): HostedVersion => {
  if (!g.ok) throw new Error(`${g.code}: ${g.reason}`);
  return g.version;
};
const rulesReview = (d: ActionDef, rules: BusinessRules, kid = 'rev-1', secret = reviewer.secretKey) =>
  signRulesReview({ verb: d.verb, def_digest: defDigest(d), rules_digest: businessRulesDigest(d.verb, rules), reviewer_kid: kid, ts: 1_700_000_000 }, secret);
const GRANT = { caveats: ['amount_cap', 'count_cap', 'window', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap'], max_esc: 3, preauth_esc: 0 };

describe('publish gate', () => {
  it('a first publish of unconfirmed actions is accepted (they are strict); the pack must verify under a pinned publisher key', () => {
    const v = ok(publish([payment(), getOrder()], '0.1.0'));
    expect(v.changes.map((c) => [c.verb, c.class])).toEqual([['acme.order.get', 'added'], ['acme.payment.send', 'added']]);
    expect(v.prev).toBeNull();
    const rogue = generateKeyPair();
    expect(publishGate({ pack: packOf([getOrder()], '0.1.0', rogue.secretKey, 'pub-1'), publisherKeys: PUB, pins: PINS })).toMatchObject({ ok: false, code: 'bad_pack' });
    // a reviewer key is not a publisher key
    expect(publishGate({ pack: packOf([getOrder()], '0.1.0', reviewer.secretKey, 'rev-1'), publisherKeys: PUB, pins: PINS })).toMatchObject({ ok: false, code: 'bad_pack' });
    expect(publishGate({ pack: { ...packOf([getOrder()], '0.1.0'), defs: [payment()] }, publisherKeys: PUB, pins: PINS })).toMatchObject({ ok: false, code: 'bad_pack' });
  });
  it('versions only move forward; a pin may go back', () => {
    const v1 = ok(publish([getOrder()], '0.2.0'));
    expect(publish([getOrder()], '0.2.0', v1)).toMatchObject({ ok: false, code: 'not_newer' });
    expect(publish([getOrder()], '0.1.9', v1)).toMatchObject({ ok: false, code: 'not_newer' });
    expect(publishGate({ current: v1, pack: packOf([getOrder()], '0.1.0'), publisherKeys: PUB, pins: PINS, pin: true }).ok).toBe(true);
    expect(publish([getOrder()], '1.0.0-rc.1', v1)).toMatchObject({ ok: false, code: 'bad_version' });
  });
  it('an edit of a confirmed action counts only when a pinned reviewer confirmed the new definition; otherwise it is strict', () => {
    const v1 = ok(publish([confirm(payment())], '0.1.0'));
    expect(hostedView([v1], PINS).lookup('acme.payment.send').confirmed).toBe(true);
    const edited = payment('Pays a customer.', 900_000_000);
    // the gate compares what each version ENFORCES: an unconfirmed def is the strictest profile, so publishing it narrows
    const strictOf = (defs: ActionDef[]) => {
      const v = ok(publish(defs, '0.2.0', v1));
      expect(v.changes.find((c) => c.verb === 'acme.payment.send')?.class).not.toBe('widen');
      return hostedView([v], PINS).lookup('acme.payment.send');
    };
    expect(strictOf([edited])).toMatchObject({ confirmed: false, serverClass: 'irreversible' });
    // confirmed by a key in another role (an importer): not a confirmation
    expect(strictOf([confirm(edited, 'imp-1', importer.secretKey)])).toMatchObject({ confirmed: false, serverClass: 'irreversible' });
    // a tampered confirmed def (signature over the old one): not a confirmation
    expect(strictOf([{ ...confirm(payment()), params: edited.params }])).toMatchObject({ confirmed: false, serverClass: 'irreversible' });
    const v2 = ok(publish([confirm(edited)], '0.2.0', v1));
    expect(hostedView([v2], PINS).lookup('acme.payment.send').confirmed).toBe(true);
    expect(v2.prev).toBe(v1.digest);
  });
  it('a removed action is deprecated; adding it back is a new (strict unless confirmed) action', () => {
    const v1 = ok(publish([getOrder(), payment()], '0.1.0'));
    const v2 = ok(publish([payment()], '0.2.0', v1));
    expect(v2.deprecated).toEqual(['acme.order.get']);
    expect(v2.changes.find((c) => c.verb === 'acme.order.get')).toMatchObject({ class: 'deprecated' });
    const v3 = ok(publish([payment()], '0.3.0', v2));
    expect(v3.deprecated).toEqual(['acme.order.get']);
    const v4 = ok(publish([payment(), getOrder()], '0.4.0', v3));
    expect(v4.deprecated).toEqual([]);
    expect(v4.changes.find((c) => c.verb === 'acme.order.get')).toMatchObject({ class: 'added' });
  });
  it('business rules: tightening needs nothing; widening or removing needs a reviewer signature over the new rules', () => {
    const d = payment();
    const strict: BusinessRules = { amount: { max: { USD: '500.00' } } };
    const v1 = ok(publish([d], '0.1.0', undefined, rulesDoc({ [d.verb]: strict })));
    // narrower: accepted
    const v2 = ok(publish([d], '0.2.0', v1, rulesDoc({ [d.verb]: { amount: { max: { USD: '400.00' } } } })));
    expect(v2.changes.find((c) => c.verb === d.verb)?.rules?.class).toBe('narrow');
    const wide: BusinessRules = { amount: { max: { USD: '900.00' } } };
    expect(publish([d], '0.3.0', v2, rulesDoc({ [d.verb]: wide }))).toMatchObject({ ok: false, code: 'widen_unreviewed', verbs: [d.verb] });
    // removing the rules widens too (a refusal would become an allow)
    expect(publish([d], '0.3.0', v2)).toMatchObject({ ok: false, code: 'widen_unreviewed' });
    // a review by the importer key, by the publisher, over other rules, or over another def: refused
    expect(publish([d], '0.3.0', v2, rulesDoc({ [d.verb]: wide }, { [d.verb]: rulesReview(d, wide, 'imp-1', importer.secretKey) }))).toMatchObject({ ok: false, code: 'widen_unreviewed' });
    expect(publish([d], '0.3.0', v2, rulesDoc({ [d.verb]: wide }, { [d.verb]: rulesReview(d, wide, 'pub-1', publisher.secretKey) }))).toMatchObject({ ok: false, code: 'widen_unreviewed' });
    expect(publish([d], '0.3.0', v2, rulesDoc({ [d.verb]: wide }, { [d.verb]: rulesReview(d, { amount: { max: { USD: '800.00' } } }) }))).toMatchObject({ ok: false, code: 'widen_unreviewed' });
    expect(publish([d], '0.3.0', v2, rulesDoc({ [d.verb]: wide }, { [d.verb]: rulesReview(payment('Pays anyone.'), wide) }))).toMatchObject({ ok: false, code: 'widen_unreviewed' });
    const v3 = ok(publish([d], '0.3.0', v2, rulesDoc({ [d.verb]: wide }, { [d.verb]: rulesReview(d, wide) })));
    expect(v3.changes.find((c) => c.verb === d.verb)).toMatchObject({ reviewed: true, rules: { class: 'widen' } });
    // removal reviewed as the empty block
    expect(ok(publish([d], '0.4.0', v3, rulesDoc({}, { [d.verb]: rulesReview(d, {}) }))).rules.rules).toEqual({});
  });
  it('a malformed rules document is refused', () => {
    const d = payment();
    expect(publish([d], '0.1.0', undefined, rulesDoc({ [d.verb]: { nope: 1 } as never }))).toMatchObject({ ok: false, code: 'bad_rules' });
    expect(publish([d], '0.1.0', undefined, rulesDoc({ 'acme.other.verb': {} }))).toMatchObject({ ok: false, code: 'bad_rules' });
    expect(publish([d], '0.1.0', undefined, { v: 1, kind: 'wrong', ns: 'acme', rules: {} })).toMatchObject({ ok: false, code: 'bad_rules' });
  });
});

describe('verifier view (hosted adjudication facts)', () => {
  const v1 = ok(publish([confirm(getOrder()), payment(), confirm(draftCreate()), confirm(draftDelete())], '0.1.0', undefined, rulesDoc({ 'acme.payment.send': { amount: { max: { USD: '500.00' } }, rate: [{ max: 10, per: 'hour', by: 'org' }] } })));
  const view = hostedView([v1], PINS);

  it('an unknown verb is the most dangerous kind of action: no provenance facts, irreversible, never allowed by the floor', () => {
    const l = view.lookup('acme.nope.do');
    expect(l).toMatchObject({ known: false, confirmed: false, serverClass: 'irreversible' });
    expect(view.provenance({ verb: 'acme.nope.do' })).toBeUndefined();
    expect(view.floor('acme.nope.do', GRANT, ['fresh_revocation', 'idempotency'])).not.toBe('allow');
    expect(view.undo.plan({ verb: 'acme.nope.do', resource: 'x', params: {} } as never, { operationId: 'o' })).toBeNull();
  });
  it('an unconfirmed known verb is as strict as an unknown one, but its rules still apply', () => {
    const l = view.lookup('acme.payment.send');
    expect(l).toMatchObject({ known: true, confirmed: false, serverClass: 'irreversible' });
    expect(l.profile).toEqual(view.lookup('acme.nope.do').profile);
    expect(view.provenance({ verb: 'acme.payment.send' })).toBeUndefined();
    expect(l.rules?.tighten.map((t) => t.id)).toEqual(expect.arrayContaining(['amount_max_usd', 'rate_0']));
  });
  it('a confirmed read-only action yields read-only provenance facts and no escalation', () => {
    const l = view.lookup('acme.order.get');
    expect(l.confirmed).toBe(true);
    expect(l.serverClass).not.toBe('irreversible');
    expect(view.provenance({ verb: 'acme.order.get' })).toBeDefined();
    expect(view.floor('acme.order.get', GRANT, hostedCallContext(l, {}))).toBe('allow');
  });
  it('without reviewer pins nothing is confirmed', () => {
    const bare = hostedView([v1], undefined);
    expect(bare.lookup('acme.order.get').confirmed).toBe(false);
    expect(bare.provenance({ verb: 'acme.order.get' })).toBeUndefined();
  });
  it('undo eligibility comes only from confirmed reversible actions with a confirmed compensating action', () => {
    const plan = view.undo.plan({ verb: 'acme.draft.create', resource: 'acme.draft:dr_1', params: { box: 'inbox', body: 'hi', idempotency_key: 'k_12345678' } } as never, { operationId: 'o1' });
    expect(plan).not.toBeNull();
    expect((plan as { compensation: { verb: string } }).compensation.verb).toBe('acme.draft.delete');
    const unconf = hostedView([ok(publish([draftCreate(), confirm(draftDelete())], '0.1.0'))], PINS);
    expect(unconf.undo.plan({ verb: 'acme.draft.create', resource: 'acme.draft:dr_1', params: { box: 'inbox', body: 'hi' } } as never, { operationId: 'o1' })).toBeNull();
  });
  it('a deprecated action is treated as unknown', () => {
    const v2 = ok(publish([payment(), confirm(draftCreate()), confirm(draftDelete())], '0.2.0', v1, rulesDoc({ 'acme.payment.send': { amount: { max: { USD: '500.00' } }, rate: [{ max: 10, per: 'hour', by: 'org' }] } })));
    const after = hostedView([v2], PINS);
    expect(after.lookup('acme.order.get')).toMatchObject({ deprecated: true, known: false, confirmed: false, serverClass: 'irreversible' });
    expect(after.provenance({ verb: 'acme.order.get' })).toBeUndefined();
  });
  it('a version whose custom traits no longer load keeps registry mode and refuses its actions', () => {
    const broken: HostedVersion = { ...v1, traits: [{ id: 'pca.redefined' } as never] };
    const bv = hostedView([broken], PINS);
    expect(bv.versions).toEqual(['acme@0.1.0']);
    const l = bv.lookup('acme.order.get');
    expect(l).toMatchObject({ known: true, confirmed: false, serverClass: 'irreversible' });
    expect(l.rules?.tighten).toEqual([expect.objectContaining({ id: 'rules_broken', signal: 'deny' })]);
    expect(bv.provenance({ verb: 'acme.order.get' })).toBeUndefined();
    expect(bv.lookup('acme.nope.do').known).toBe(false);
  });
  it('rate keys: an unknown org leaves the count absent (the rule fires)', () => {
    const c = view.lookup('acme.payment.send').rules!;
    const keys = rateKeysOf(c, { principal: 'user:u_1' });
    expect(keys).toEqual([{ id: 'rate_0', ms: 3_600_000 }]);
    const withOrg = rateKeysOf(c, { principal: 'user:u_1', org: 'org_1' });
    expect(withOrg[0]!.key).toBe('acme.payment.send|3600000|org:org_1');
  });
});

describe('source sync', () => {
  const imported = [getOrder(), payment()];
  it('first sync adds everything unreviewed; an unchanged operation keeps its review', () => {
    const r1 = syncSource({ current: [], imported, specDigest: 'd1', now: 1 });
    expect(r1.entries.map((e) => e.change)).toEqual(['added', 'added']);
    expect(r1.needsReview).toBe(true);
    const reviewed = r1.defs.map((d) => (d.verb === 'acme.order.get' ? confirm(d) : d));
    const r2 = syncSource({ current: reviewed, imported, specDigest: 'd1', lock: r1.lock, now: 2 });
    expect(r2.entries.every((e) => e.change === 'unchanged')).toBe(true);
    expect(r2.needsReview).toBe(false);
    expect(r2.defs.find((d) => d.verb === 'acme.order.get')!.review.state).toBe('confirmed');
  });
  it('a changed operation replaces the reviewed def with the unreviewed import; a removed one is deprecated', () => {
    const r1 = syncSource({ current: [], imported, specDigest: 'd1', now: 1 });
    const reviewed = r1.defs.map((d) => confirm(d));
    // an import that arrives "confirmed" is never trusted as such
    const changed = confirm(payment('Pays a customer.', 900_000_000));
    const r2 = syncSource({ current: reviewed, imported: [changed], specDigest: 'd2', lock: r1.lock, now: 2 });
    expect(r2.entries).toEqual(expect.arrayContaining([expect.objectContaining({ verb: 'acme.payment.send', change: 'changed' }), { verb: 'acme.order.get', change: 'removed' }]));
    expect(r2.deprecated).toEqual(['acme.order.get']);
    expect(r2.defs.find((d) => d.verb === 'acme.payment.send')!.review.state).not.toBe('confirmed');
    expect(r2.needsReview).toBe(true);
  });
});
