// Oracle (python lane): @atlasauth/pca-actions hosted.ts. Writes out/ref-actions-hosted-py.json.gz.
// PORTING table: publishGate(input) hostedVersionDigest(version) rulesDocError(doc, ns, defs) registryOfTraits(traits) -> compare the registry digest
//   hostedView(versions, pins) -> {lookups[verb], provenance[verb], floors[...], undo[...]}: the wrapper in this file maps to HostedView.lookup / provenance / floor / undo_plan
//   grantFactsOf(grant) hostedCallContext(lookup, params) rateKeysOf(compiled, who)
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as BD0 from '../../../packages/pca-actions/src/build.ts';
import * as H0 from '../../../packages/pca-actions/src/hosted.ts';
import * as BR0 from '../../../packages/pca-actions/src/business-rules.ts';
import * as RV0 from '../../../packages/pca-actions/src/import/review.ts';
import * as EF0 from '../../../packages/pca-actions/src/effective.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as DG0 from '../../../packages/pca-actions/src/digest.ts';
import * as T0 from '../../../packages/pca-actions/src/traits.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), BD = un(BD0), H = un(H0), BR = un(BR0), RV = un(RV0), EF = un(EF0), CT = un(CT0), DG = un(DG0), T = un(T0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-hosted-py', 'tools/pca-audit/oracles/actions-hosted-py.mts', 'TS-reference oracle for pca-actions hosted registry (python lane).');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const PUB = seed('ref-actions-hosted-py/pub'), PUB2 = seed('ref-actions-hosted-py/pub2'), REV = seed('ref-actions-hosted-py/rev'), REV2 = seed('ref-actions-hosted-py/rev2');
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });
const PUBKEYS = [BD.packKeyOf('pub1', PUB)];
const PINS: any = { keys: [{ kid: 'rev1', pk: P.b64u(P.publicKeyOf(REV)), roles: ['reviewer'] }, { kid: 'imp1', pk: P.b64u(P.publicKeyOf(REV2)), roles: ['importer'] }] };
const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
const conf = (d: any, kid = 'rev1', sk = REV) => RV.confirmDef(d, { registry: CORE, reviewer: { kid, secret: sk }, finalTraits: EF.hintTraits(d), ts: 1000 });
const CFG = (ver: string, ns = 'acme') => ({ ns, version: ver, stability: 'beta', site: 'https://acme.example', aud: 'agents' });
const pack = (defs: any[], ver: string, ns = 'acme', reg: any = CORE, key = PUB) => BD.signPack(BD.buildArtifacts(defs, CFG(ver, ns), reg).pack, 'pub1', key, reg);
const doc = (rules: any, reviews?: any, ns = 'acme') => ({ v: 1, kind: 'pca-action-rules', ns, rules, ...(reviews ? { reviews } : {}) });
const gate = (x: any) => H.publishGate(x);
const G = (name: string, x: any) => o.run('publishGate', name, (i: any) => H.publishGate(i), [x]);

const D6 = ALL.slice(0, 6);
const C6 = D6.map((d) => conf(d));
const RULE_A = { 'stripe.charge': { amount: { max: { USD: 5000 } } } };
const RULE_B = { 'stripe.charge': { amount: { max: { USD: 6000 } } } };
const RULE_C = { 'stripe.charge': { amount: { max: { USD: 4000 } } } };
const base = { publisherKeys: PUBKEYS, pins: PINS };
const V1 = gate({ ...base, pack: pack(D6, '1.0.0'), rules: doc(RULE_A) }).version;
const V1c = gate({ ...base, pack: pack(C6, '1.0.0'), rules: doc(RULE_A) }).version;

// first publishes
await G('first unconfirmed', { ...base, pack: pack(D6, '1.0.0') });
await G('first confirmed', { ...base, pack: pack(C6, '1.0.0') });
await G('first no pins', { publisherKeys: PUBKEYS, pins: undefined, pack: pack(C6, '1.0.0') });
await G('first with rules', { ...base, pack: pack(D6, '1.0.0'), rules: doc(RULE_A) });
await G('first no keys', { ...base, publisherKeys: [], pack: pack(D6, '1.0.0') });
await G('first wrong key', { ...base, pack: pack(D6, '1.0.0', 'acme', CORE, PUB2) });
await G('first tampered', { ...base, pack: { ...pack(D6, '1.0.0'), version: '9.9.9' } });
await G('first bad version', { ...base, pack: pack(D6, '1.0') });
await G('first prerelease', { ...base, pack: pack(D6, '1.0.0-beta') });
await G('first null pack', { ...base, pack: null });
// traits
await G('traits not list', { ...base, pack: pack(D6, '1.0.0'), traits: 5 });
await G('traits empty', { ...base, pack: pack(D6, '1.0.0'), traits: [] });
const CUSTOM = [{ id: 'acme.extra', implies: ['pca.network_egress'], floor: T.profile({ risk: 2, rev: 'reversible', blast_ppm: 100000, esc: 1, caveats: ['amount_cap', 'recipient_scope'], context: [], prules: [] }), card_phrase: 'does extra things' }];
const CREG = T.extendRegistry(CORE, CUSTOM);
await G('traits custom', { ...base, pack: pack(D6, '1.0.0', 'acme', CREG), traits: CUSTOM });
await G('traits custom mismatch', { ...base, pack: pack(D6, '1.0.0'), traits: CUSTOM });
await G('traits bad', { ...base, pack: pack(D6, '1.0.0'), traits: [{ id: 'pca.x', implies: [], floor: T.BOTTOM, card_phrase: 'x' }] });
// version ordering / ns
await G('same version', { ...base, current: V1, pack: pack(D6, '1.0.0') });
await G('older version', { ...base, current: V1, pack: pack(D6, '0.9.0') });
await G('same version pin', { ...base, current: V1, pack: pack(D6, '1.0.0'), pin: true });
await G('newer equal', { ...base, current: V1, pack: pack(D6, '1.0.1'), rules: doc(RULE_A) });
await G('newer no rules arg', { ...base, current: V1, pack: pack(D6, '1.0.1') });
await G('ns mismatch', { ...base, current: V1, pack: pack(D6, '1.0.1', 'other'), rules: doc({}, undefined, 'other') });
await G('title change', { ...base, current: V1, pack: pack(D6.map((d, i) => (i === 0 ? mut(d, (x) => (x.title = 'New title')) : d)), '1.1.0'), rules: doc(RULE_A) });
await G('added verb', { ...base, current: V1, pack: pack([...D6, ALL[6]], '1.1.0'), rules: doc(RULE_A) });
await G('added verb confirmed', { ...base, current: V1, pack: pack([...D6, conf(ALL[6])], '1.1.0'), rules: doc(RULE_A) });
await G('removed verb', { ...base, current: V1, pack: pack(D6.slice(1), '1.1.0'), rules: doc({}) });
const V2 = gate({ ...base, current: V1, pack: pack(D6.slice(1), '1.1.0'), rules: doc({}) }).version;
await G('re-added verb', { ...base, current: V2, pack: pack(D6, '1.2.0'), rules: doc({}) });
await G('re-added dep list kept', { ...base, current: V2, pack: pack(D6.slice(1), '1.2.0'), rules: doc({}) });
// confirmation transitions
await G('unconfirmed to confirmed', { ...base, current: V1, pack: pack(C6, '1.1.0'), rules: doc(RULE_A) });
await G('confirmed to unconfirmed', { ...base, current: V1c, pack: pack(D6, '1.1.0'), rules: doc(RULE_A) });
await G('confirmed same', { ...base, current: V1c, pack: pack(C6, '1.1.0'), rules: doc(RULE_A) });
await G('confirmed widened traits', { ...base, current: V1c, pack: pack(C6.map((d, i) => (i === 0 ? conf(mut(D6[0], (x) => { x.effects = ['read']; x.params = { customer: x.params.customer }; x.idempotency = undefined; delete x.idempotency; })) : d)), '1.1.0'), rules: doc(RULE_A) });
await G('confirmed widened no pins', { publisherKeys: PUBKEYS, pins: undefined, current: V1c, pack: pack(C6, '1.1.0'), rules: doc(RULE_A) });
await G('confirmed by importer', { ...base, current: V1, pack: pack(D6.map((d) => conf(d, 'imp1', REV2)), '1.1.0'), rules: doc(RULE_A) });
// rules
await G('rules widen unreviewed', { ...base, current: V1, pack: pack(D6, '1.1.0'), rules: doc(RULE_B) });
const rr = (rules: any, kid = 'rev1', sk = REV, over: any = {}) => BR.signRulesReview({ verb: 'stripe.charge', def_digest: DG.defDigest(D6[0]), rules_digest: BR.businessRulesDigest('stripe.charge', rules), reviewer_kid: kid, ts: 1000, ...over }, sk);
await G('rules widen reviewed', { ...base, current: V1, pack: pack(D6, '1.1.0'), rules: doc(RULE_B, { 'stripe.charge': rr(RULE_B['stripe.charge']) }) });
await G('rules widen wrong review', { ...base, current: V1, pack: pack(D6, '1.1.0'), rules: doc(RULE_B, { 'stripe.charge': rr(RULE_A['stripe.charge']) }) });
await G('rules widen importer review', { ...base, current: V1, pack: pack(D6, '1.1.0'), rules: doc(RULE_B, { 'stripe.charge': rr(RULE_B['stripe.charge'], 'imp1', REV2) }) });
await G('rules tighten', { ...base, current: V1, pack: pack(D6, '1.1.0'), rules: doc(RULE_C) });
await G('rules dropped', { ...base, current: V1, pack: pack(D6, '1.1.0'), rules: doc({}) });
await G('rules dropped reviewed', { ...base, current: V1, pack: pack(D6, '1.1.0'), rules: doc({}, { 'stripe.charge': rr({}) }) });
await G('rules added', { ...base, current: V1, pack: pack(D6, '1.1.0'), rules: doc({ ...RULE_A, 'stripe.refund': { required: ['charge'] } }) });
await G('rules bad doc', { ...base, pack: pack(D6, '1.0.0'), rules: 5 });
await G('rules unknown member', { ...base, pack: pack(D6, '1.0.0'), rules: { ...doc({}), extra: 1 } });
await G('rules wrong ns', { ...base, pack: pack(D6, '1.0.0'), rules: doc({}, undefined, 'other') });
await G('rules unknown verb', { ...base, pack: pack(D6, '1.0.0'), rules: doc({ 'no.such': { required: ['x'] } }) });
await G('rules lint error', { ...base, pack: pack(D6, '1.0.0'), rules: doc({ 'stripe.charge': { amount: { max: { USD: -1 } } } }) });
await G('rules reviews unknown verb', { ...base, pack: pack(D6, '1.0.0'), rules: doc({}, { 'no.such': {} }) });
await G('rules reviews not obj', { ...base, pack: pack(D6, '1.0.0'), rules: { ...doc({}), reviews: 5 } });
await G('rules rules not obj', { ...base, pack: pack(D6, '1.0.0'), rules: { v: 1, kind: 'pca-action-rules', ns: 'acme', rules: [] } });
await G('rules v2', { ...base, pack: pack(D6, '1.0.0'), rules: { ...doc({}), v: 2 } });
// digest / rules doc / registry
for (const [n, v] of [['v1', V1], ['v1c', V1c], ['v2', V2]] as any[]) { await o.run('hostedVersionDigest', n, H.hostedVersionDigest, [v]); }
await o.run('rulesDocError', 'ok', H.rulesDocError, [doc(RULE_A), 'acme', D6]);
await o.run('rulesDocError', 'null', H.rulesDocError, [null, 'acme', D6]);
await o.run('registryOfTraits', 'empty', (t: any) => ({ digest: CT.CORE_REGISTRY && DG.traitsDigest(H.registryOfTraits(t)) }), [[]]);
await o.run('registryOfTraits', 'custom', (t: any) => ({ digest: DG.traitsDigest(H.registryOfTraits(t)) }), [CUSTOM]);
await o.run('registryOfTraits', 'bad', (t: any) => ({ digest: DG.traitsDigest(H.registryOfTraits(t)) }), [[{ id: 'pca.x', implies: [], floor: T.BOTTOM, card_phrase: 'x' }]]);

// hosted view
const sample = (d: any): any => { const out: any = {}; for (const [k, p] of Object.entries<any>(d.params)) { if (p.required === false) continue; out[k] = p.role?.startsWith('id.') ? 'abc12345' : p.type === 'integer' ? 7 : p.type === 'boolean' ? true : p.values ? p.values[0] : p.type === 'array' ? ['x'] : p.type === 'set' ? [] : p.type === 'datetime' ? '2030-01-01T00:00:00Z' : 'val'; } return out; };
const VERBS = [...D6.map((d) => d.verb), ALL[6].verb, 'unknown.verb'];
const GRANTS = [{ caveats: [], max_esc: 3, preauth_esc: 0 }, { caveats: ['amount_cap', 'window', 'bogus'], max_esc: 3, preauth_esc: 3 }, { caveats: ['amount_cap', 'count_cap', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap'], max_esc: 1, preauth_esc: 1 }, { caveats: [], max_esc: 0, preauth_esc: 0 }];
const CTXS = [[], ['fresh_revocation'], ['fresh_revocation', 'idempotency', 'approval_ref', 'revocable', 'dry_run_first']];
const viewProbe = (vs: any, pins: any) => {
  const v = H.hostedView(vs, pins);
  return {
    versions: v.versions, lookups: VERBS.map((x) => v.lookup(x)), prov: VERBS.map((x) => v.provenance({ verb: x }) ?? null),
    floors: VERBS.flatMap((x) => GRANTS.flatMap((g) => CTXS.map((c) => v.floor(x, g, c)))),
    undo: [...D6, ALL[6]].map((d) => v.undo.plan({ verb: d.verb, params: sample(d) }, { operationId: 'op1' }) ?? null),
  };
};
const VIEWS: [string, any[], any][] = [
  ['v1 unconfirmed', [V1], PINS], ['v1 confirmed', [V1c], PINS], ['v1c no pins', [V1c], undefined], ['v2 deprecated', [V2], PINS], ['v1c+v2', [V1c, V2], PINS], ['empty', [], PINS], ['v2 first', [V2, V1c], PINS],
  ['broken traits', [{ ...V1c, traits: [{ id: 'pca.x', implies: [], floor: T.BOTTOM, card_phrase: 'x' }] }], PINS],
  ['rules', [V1c], PINS],
];
for (const [n, vs, pins] of VIEWS) await o.run('hostedView', n, viewProbe, [vs, pins]);
const VC = gate({ ...base, pack: pack(C6, '1.0.0', 'acme', CREG), traits: CUSTOM, rules: doc(RULE_A) }).version;
await o.run('hostedView', 'custom registry', viewProbe, [[VC], PINS]);
await o.run('hostedView', 'custom + core', viewProbe, [[VC, V1c], PINS]);
const DRAFT = C6.find((d) => d.verb === 'gmail.draft');
// grant facts / call context / rate keys
const env = (actions: any, caveats: any = []) => ({ caveats: [{ type: 'envelope', goal_commit: 'g'.repeat(43), predicates: [], caveats, agent_binding: {}, risk_policy: { weights: { alpha: 1, beta: 1, gamma: 1, delta: 1, epsilon: 1, zeta: 1 }, theta1: 0.3, theta2: 0.6, kappa: 1000, lambda: 1, rho: 1, bMax: 1 }, actions }] });
const GF: [string, any][] = [['null', null], ['empty', {}], ['no env', { caveats: [{ type: 'other' }] }], ['env none', env(undefined)], ['env actions', env({ caveats: ['amount_cap', 5, 'window'], max_esc: 2, preauth_esc: 1 })], ['env tiers bad', env({ max_esc: 9, preauth_esc: -1 })], ['env tiers float', env({ max_esc: 1.5, preauth_esc: '1' })],
  ['env caveats mixed', env({ caveats: ['x'] }, [{ type: 'amount_cap' }, null, { type: 7 }])], ['env actions not obj', env(5)]];
for (const [n, g] of GF) await o.run('grantFactsOf', n, H.grantFactsOf, [g]);
for (const [l, p] of [[{ idempotency_param: 'idempotency_key' }, { idempotency_key: 'k' }], [{ idempotency_param: 'idempotency_key' }, { idempotency_key: '' }], [{ idempotency_param: 'idempotency_key' }, {}], [{ idempotency_param: 'idempotency_key' }, undefined], [{}, { a: 1 }], [undefined, undefined], [{ idempotency_param: 'k' }, { k: 5 }]] as any[]) await o.run('hostedCallContext', JSON.stringify([l, p]), H.hostedCallContext, [l, p]);
const RC = BR.compileBusinessRules(ALL[0], { rate: [{ max: 3, per: 'hour' }, { max: 9, per: 'day', by: 'org' }] });
for (const w of [{ principal: 'p1', org: 'o1' }, { principal: 'p1' }, { org: 'o1' }, {}, { principal: '', org: '' }, { principal: 5 }]) await o.run('rateKeysOf', JSON.stringify(w), H.rateKeysOf, [RC, w]);
await o.run('rateKeysOf', 'task window', H.rateKeysOf, [{ v: 1, verb: 'a.b', accumulators: [{ id: 'rate_0', scope: 'principal', win: { kind: 'task' } }, { id: 'rate_1', scope: 'org', win: { kind: 'sliding', ms: 5 } }] }, { principal: 'p', org: 'o' }]);
refWrite(o, 'actions-hosted-py');
