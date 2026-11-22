// Oracle: @atlasauth/pca-actions selector.ts + confirmation.ts. Writes out/ref-actions-sel-conf.json.gz.
// PORTING table: fn(args) -> native entry point, comparison rule
//   selectorMatches(sel, closure[])                       -> ActionSelectors.selectorMatches (boolean)
//   selectorMatchesFor(sel, mode, closure[], confirmed)   -> ActionSelectors.selectorMatchesFor
//   selectorHasNot(sel) / allowSelectorError(sel, pinned) -> same names (boolean / string|null)
//   policyDecision(policy, verb, closure[], confirmed)    -> ActionSelectors.policyDecision ('allow'|'deny'|'escalate')
//   blankReason(s)                                        -> ActionConfirmation.blankReason
//   reviewMessage(body)                                   -> ActionConfirmation.reviewMessage (bytes)
//   signReview(body, {$bytes: seed})                      -> ActionConfirmation.signReview (Ed25519 deterministic, compare as JSON)
//   verbConfirmationError(verb, regDefs|null, pins)       -> ActionConfirmation.verbConfirmationError; regDefs null = the core registry,
//                                                            else extendRegistry(core, regDefs)
import * as S0 from '../../../packages/pca-actions/src/selector.ts';
import * as C0 from '../../../packages/pca-actions/src/confirmation.ts';
import * as T0 from '../../../packages/pca-actions/src/traits.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as D0 from '../../../packages/pca-actions/src/digest.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, variants, seed, refWrite, clone } from './lib.mjs';

const un = (m: any) => (m.default && !m.selectorMatches && !m.reviewMessage && !m.extendRegistry && !m.CORE_REGISTRY && !m.traitsDigest ? m.default : m);
const A: any = { ...un(S0), ...un(C0), ...un(T0), ...un(CT0), ...un(D0) };
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const o = new Oracle('actions-sel-conf', 'tools/pca-audit/oracles/actions-sel-conf.mts', 'TS-reference oracle for pca-actions selectors and the signed confirmation.');
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });

// ---- selectors ----
const T = (id: string) => ({ k: 'trait', id });
const SELS: any[] = [T('pca.a'), T('pca.b'), { k: 'all_of', ids: ['pca.a', 'pca.b'] }, { k: 'all_of', ids: [] }, { k: 'any_of', ids: ['pca.a', 'pca.c'] }, { k: 'any_of', ids: [] },
  { k: 'not', s: T('pca.a') }, { k: 'and', a: T('pca.a'), b: T('pca.b') }, { k: 'and', a: { k: 'not', s: T('pca.a') }, b: T('pca.c') }, { k: 'and', a: { k: 'any_of', ids: ['pca.a'] }, b: T('pca.b') },
  { k: 'not', s: { k: 'not', s: T('pca.a') } }, { k: 'and', a: { k: 'and', a: T('pca.a'), b: { k: 'any_of', ids: ['pca.b'] } }, b: { k: 'not', s: T('pca.d') } }];
const CLOS: string[][] = [[], ['pca.a'], ['pca.b'], ['pca.a', 'pca.b'], ['pca.c'], ['pca.a', 'pca.b', 'pca.c', 'pca.d'], ['pca.d']];
for (const [si, s] of SELS.entries()) {
  await o.run('selectorHasNot', `s${si}`, A.selectorHasNot, [s]);
  for (const pinned of [true, false]) await o.run('allowSelectorError', `s${si} pinned=${pinned}`, A.allowSelectorError, [s, pinned]);
  for (const [ci, c] of CLOS.entries()) {
    await o.run('selectorMatches', `s${si} c${ci}`, (x: any, y: any) => A.selectorMatches(x, new Set(y)), [s, c]);
    for (const mode of ['allow', 'prohibit']) for (const conf of [true, false]) await o.run('selectorMatchesFor', `s${si} c${ci} ${mode} ${conf}`, (x: any, m: any, y: any, z: any) => A.selectorMatchesFor(x, m, new Set(y), z), [s, mode, c, conf]);
  }
}
const POLS: any[] = [
  { pinned: ['v.a'], allow: [T('pca.a')], prohibit: [] }, { pinned: ['v.a'], allow: [T('pca.a')], prohibit: [T('pca.b')] }, { pinned: ['v.a'], allow: [], prohibit: [] },
  { pinned: [], allow: [T('pca.a')], prohibit: [], on_new_action: 'escalate' }, { pinned: [], allow: [T('pca.a')], prohibit: [] }, { pinned: ['v.a'], allow: [T('pca.a')], prohibit: [{ k: 'not', s: T('pca.z') }] },
  { pinned: ['v.a', 'v.b'], allow: [{ k: 'any_of', ids: ['pca.a', 'pca.c'] }], prohibit: [T('pca.d')], on_new_action: 'deny' }, { pinned: ['v.a'], allow: [{ k: 'not', s: T('pca.a') }], prohibit: [] },
];
for (const [pi, p] of POLS.entries()) for (const verb of ['v.a', 'v.b', 'v.z']) for (const [ci, c] of CLOS.entries()) for (const conf of [true, false])
  await o.run('policyDecision', `p${pi} ${verb} c${ci} ${conf}`, (a: any, b: any, c2: any, d: any) => A.policyDecision(a, b, new Set(c2), d), [p, verb, c, conf]);

// ---- blankReason ----
for (const s of ['', ' ', '\t\n', '\u001c', '\u001f', ' ', ' ', ' ', '﻿', '᠎', '\u0085', 'a', ' a ', '​', '　 ', '\u000b\u000c\r', '\u001e x', '   ', '\u0000', '­'])
  await o.run('blankReason', JSON.stringify(s), A.blankReason, [s]);

// ---- confirmation ----
const key = (l: string) => { const sk = seed(`ref-actions-conf/${l}`); return { sk, pk: P.b64u(P.publicKeyOf(sk)) }; };
const REV = key('reviewer'), REV2 = key('reviewer2'), MACH = key('importer');
const PINS: any = { keys: [{ kid: 'rev1', pk: REV.pk, roles: ['reviewer'], not_before: 100, not_after: 2_000_000_000 }, { kid: 'imp1', pk: MACH.pk, roles: ['importer'] }, { kid: 'rev2', pk: REV2.pk, roles: ['reviewer', 'publisher'] }] };
const CORE = A.CORE_REGISTRY;
const TD = A.traitsDigest(CORE);
const VERB0: any = { verb: 'acme.invoice.pay', kind: 'write', title: 'Pay', params: [{ name: 'amount', role: 'money.amount' }], effects: ['pay'], reversibility: 'irreversible', description: 'Pays an invoice.' };
const mkVerb = (over: any = {}, body: any = {}, sk = REV.sk) => {
  const v: any = { ...clone(VERB0), def: 'D'.repeat(43), traits: ['pca.money_moving', 'pca.irreversible'], ...over };
  const b = { def_digest: v.def, traits_digest: TD, facts_digest: A.factsDigest(v), final_traits: ['pca.irreversible', 'pca.money_moving'], dismissed: [{ trait: 'pca.bulk', reason: 'one at a time' }], reviewer_kid: 'rev1', ts: 1000, ...body };
  v.confirmation = A.signReview(b, sk);
  return v;
};
const BODY: any = { def_digest: 'D'.repeat(43), traits_digest: TD, facts_digest: 'F'.repeat(43), final_traits: ['pca.z', 'pca.a', 'pca.z'], dismissed: [{ trait: 'pca.y', reason: 'r1' }, { trait: 'pca.b', reason: 'r2' }], reviewer_kid: 'rev1', ts: 1000 };
for (const [n, b] of Object.entries({ base: BODY, nodismissed: { ...BODY, dismissed: [] }, unsorted: { ...BODY, final_traits: ['b', 'a'] }, extra: { ...BODY, extra: 1 }, tsbig: { ...BODY, ts: 2 ** 53 - 1 }, unicode: { ...BODY, dismissed: [{ trait: 'é', reason: '😀' }, { trait: 'z', reason: 'q' }] } }) as [string, any][]) {
  await o.run('reviewMessage', n, A.reviewMessage, [b]);
  await o.run('signReview', n, (x: any, s: any) => A.signReview(x, Uint8Array.from(Buffer.from(s.$bytes, 'base64url'))), [b, bytes(REV.sk)]);
}
const CR = (n: string, v: any, regDefs: any = null, pins: any = PINS) => o.run('verbConfirmationError', n, (vv: any, rd: any, pp: any) => A.verbConfirmationError(vv, rd == null ? CORE : A.extendRegistry(CORE, rd), pp), [v, regDefs, pins]);
const GOOD = mkVerb();
await CR('good', GOOD);
await CR('good rev2', mkVerb({}, { reviewer_kid: 'rev2' }, REV2.sk));
await CR('no pins', GOOD, null, undefined);
await CR('bad pins', GOOD, null, { keys: 'x' });
await CR('pins extra digest', mkVerb({}, { traits_digest: 'X'.repeat(43) }), null, { ...PINS, traits_digests: ['X'.repeat(43)] });
await CR('wrong registry', mkVerb({}, { traits_digest: 'X'.repeat(43) }));
await CR('no confirmation', (() => { const v = clone(GOOD); delete v.confirmation; return v; })());
await CR('confirmation null', { ...clone(GOOD), confirmation: null });
await CR('confirmation string', { ...clone(GOOD), confirmation: 'x' });
await CR('unsigned', (() => { const v = clone(GOOD); delete v.confirmation.sig; return v; })());
await CR('other def', { ...clone(GOOD), def: 'E'.repeat(43) });
await CR('def missing', (() => { const v = clone(GOOD); delete v.def; return v; })());
await CR('facts differ', { ...clone(GOOD), title: 'Other' });
await CR('traits dropped', { ...clone(GOOD), traits: ['pca.money_moving'] });
await CR('traits extra', { ...clone(GOOD), traits: ['pca.money_moving', 'pca.irreversible', 'pca.bulk'] });
await CR('traits missing', (() => { const v = clone(GOOD); delete v.traits; return v; })());
await CR('dismissed also final', mkVerb({}, { dismissed: [{ trait: 'pca.money_moving', reason: 'x' }] }));
await CR('dismissed blank', mkVerb({}, { dismissed: [{ trait: 'pca.bulk', reason: '   ' }] }));
await CR('dismissed non-object', (() => { const v = clone(GOOD); v.confirmation.dismissed = [5]; return v; })());
await CR('unknown kid', mkVerb({}, { reviewer_kid: 'nobody' }));
await CR('importer kid', mkVerb({}, { reviewer_kid: 'imp1' }, MACH.sk));
await CR('ts before window', mkVerb({}, { ts: 99 }));
await CR('ts after window', mkVerb({}, { ts: 2_000_000_001 }));
await CR('ts at start', mkVerb({}, { ts: 100 }));
await CR('ts at end', mkVerb({}, { ts: 2_000_000_000 }));
await CR('ts -0', (() => { const v = clone(GOOD); v.confirmation.ts = -0; return v; })());
await CR('ts fraction', (() => { const v = clone(GOOD); v.confirmation.ts = 1.5; return v; })());
await CR('wrong signer', mkVerb({}, {}, REV2.sk));
await CR('bad sig', (() => { const v = clone(GOOD); v.confirmation.sig = 'A'.repeat(86); return v; })());
await CR('sig short', (() => { const v = clone(GOOD); v.confirmation.sig = 'AAAA'; return v; })());
await CR('custom registry', GOOD, [{ id: 'acme.extra', implies: ['pca.money_moving'], floor: { risk: 1, esc: 0, rev: 'reversible', blast: 0 }, card_phrase: 'x' }].slice(0, 0));
for (const [lbl, v] of variants(GOOD.confirmation, { maxPaths: 60, hostile: [null, true, 0, -0, 1.5, '', 'x', [], {}, ['x'], [null]] })) await CR(`conf ${lbl}`, { ...clone(GOOD), confirmation: v });
for (const [lbl, p] of variants(PINS, { maxPaths: 60, hostile: [null, true, 0, '', 'x', [], {}] })) await CR(`pins ${lbl}`, GOOD, null, p);
refWrite(o, 'actions-sel-conf');
