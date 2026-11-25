// Oracle: @atlasauth/pca-intent profiles (profile.ts). Ed25519 only; keys derive from fixed seeds; no clocks.
// Secrets cross the oracle as a b64u 32-byte seed string. Results that are a canonical-JSON "malformed profile: ..." message are
// dropped from the corpus (the strict-canonical error text is the core encoder's, tested elsewhere).
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value):
//   signIntentProfile(body, seedB64u)            IntentProfile.signIntentProfile(body, seed bytes) -> signed profile
//   intentProfileShapeError(p, signed?)          IntentProfile.intentProfileShapeError(p, signed); string or null
//   verifyIntentProfile(p) / profileUsable(p, c) {ok, reason?}
//   intentProfileDigest(p) / verifyProfileSuccession(prev, next)
//   profileApplies(p, u) / standingAdmits(p, u, action) / standingPermits(p, u, action)    boolean
//   profileVetoCells(p, omega)                   [{verb, cell}]
//   profileCeiling(p, u, vs, outcome)            profileCeiling(p, u).test(vs, outcome); boolean
import * as P0 from '../../../packages/pca-intent/src/profile';
import * as O0 from '../../../packages/pca-intent/src/omega';
import { Oracle, refWrite, seed, variants } from './lib.mjs';

const P: any = (P0 as any).default ?? P0;
const O: any = (O0 as any).default ?? O0;
const o = new Oracle('intent-profile', 'tools/pca-audit/oracles/intent-profile.mts', 'TS-reference oracle for intent profiles.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const unseed = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const SEED_A = Buffer.from(seed('intent-profile/a')).toString('base64url');
const SEED_B = Buffer.from(seed('intent-profile/b')).toString('base64url');
const runKeep = async (fn: string, f: any, args: any[]) => { try { const r = f(...JSON.parse(JSON.stringify(args))); if (JSON.stringify(r)?.includes('malformed profile')) return; } catch {} await run(fn, f, args); };

const sign = (b: any, s: string) => P.signIntentProfile(b, unseed(s));
const D32 = (c: string) => Buffer.from(seed('intent-profile/d' + c)).toString('base64url');
const body1: any = { v: 1, kind: 'pca-intent-profile', profile_id: 'travel', version: 1, scope: { sites: ['shop.example'], verbs: ['stripe.refund', 'stripe.charge'] },
  standing: { deny: [{ verb: 'stripe.charge', where: [{ field: 'action.params.amount', op: 'gt', value: 100 }] }], permit: [{ verb: 'stripe.refund', resource: '/acct/*' }] },
  prior: { observations: [{ verb: 'stripe.refund', values: { 'action.params.amount': 500 }, y: 0, at: 1700000000000 }, { verb: 'stripe.refund', values: { 'action.params.amount': 5 }, y: 1, at: 1700000000001 }], maps: [D32('1')] },
  expires_at: 1900000000000, revocation: { epoch_uri: 'https://x.example/epoch' } };
const p1 = sign(body1, SEED_A);
await run('signIntentProfile', (b: any, s: string) => sign(b, s), [body1, SEED_A]);
const body2 = { ...body1, version: 2, prev: P.intentProfileDigest(p1) };
const p2 = sign(body2, SEED_A);
await run('signIntentProfile', (b: any, s: string) => sign(b, s), [body2, SEED_A]);
await run('signIntentProfile', (b: any, s: string) => sign(b, s), [{ ...body1, owner: p1.owner }, SEED_A]);
await run('signIntentProfile', (b: any, s: string) => sign(b, s), [{ ...body1, owner: p1.owner }, SEED_B]);
await run('signIntentProfile', (b: any, s: string) => sign(b, s), [{ ...body1, extra: 1 }, SEED_A]);
await run('signIntentProfile', (b: any, s: string) => sign(b, s), [{ ...body1, version: 2 }, SEED_A]);
await run('signIntentProfile', (b: any, s: string) => sign(b, s), [{ ...body1, scope: {} , revocation: { epoch_uri: 'u', key: D32('k') } }, SEED_A]);
await run('signIntentProfile', (b: any, s: string) => sign(b, s), [{ ...body1, profile_id: 'bad id' }, SEED_A]);
const p3 = sign({ ...body1, profile_id: 'other', scope: {}, standing: { deny: [], permit: [] }, prior: { observations: [], maps: [] }, revocation: { epoch_uri: 'u', key: D32('k') } }, SEED_B);
const p1b = sign({ ...body1, profile_id: 'travel' }, SEED_B);

for (const p of [p1, p2, p3, p1b]) {
  await run('intentProfileDigest', P.intentProfileDigest, [p]);
  await run('verifyIntentProfile', P.verifyIntentProfile, [p]);
  await run('intentProfileShapeError', P.intentProfileShapeError, [p]);
  await run('intentProfileShapeError', P.intentProfileShapeError, [p, { signed: false }]);
}
for (const [name, v] of variants(p1, { hostile: [null, 0, 1, '', 'x', [], {}, true, -1], maxPaths: 400 })) {
  await runKeep('intentProfileShapeError', P.intentProfileShapeError, [v]);
  await runKeep('verifyIntentProfile', P.verifyIntentProfile, [v]);
}
for (const [name, v] of variants({ ...p1, version: 1 }, { hostile: [null, 'x'], maxPaths: 400 })) await runKeep('intentProfileShapeError', P.intentProfileShapeError, [v, { signed: false }]);
for (const bad of [null, 5, 'x', [], {}, { ...p1, alg: 'ml-dsa-65' }, { ...p1, alg: 'nope' }, { ...p1, alg: 5 }, { ...p1, alg: 'ed25519', pq_pk: 'x' }, { ...p1, sig: 5 }, { ...p1, sig: 'AAAA' }]) await runKeep('verifyIntentProfile', P.verifyIntentProfile, [bad]);
// succession
const rows: any[] = [[p1, p2], [p1, p1], [p2, p1], [p1, p3], [p1, p1b], [p1, { ...p2, prev: p2.prev.slice(0, -1) + 'A' }], [p1, { ...p2, sig: p1.sig }], [{ ...p1, sig: 'x' }, p2], [p1, null]];
for (const [a, b] of rows) await runKeep('verifyProfileSuccession', P.verifyProfileSuccession, [a, b]);
// uses
const us: any[] = [{ aud: 'shop.example', verb: 'stripe.refund', now: 1800000000000 }, { aud: 'shop.example', verb: 'stripe.charge', now: 1800000000000 }, { aud: 'other', verb: 'stripe.refund', now: 1800000000000 },
  { aud: 'shop.example', verb: 'gmail.send', now: 1800000000000 }, { aud: 'shop.example', verb: 'stripe.refund', now: 1900000000000 }, { aud: 'shop.example', verb: 'stripe.refund', now: 1899999999999 },
  { aud: 'shop.example', verb: 'stripe.refund', now: 0 }, { aud: 'shop.example', verb: 'stripe.refund', now: 1800000000000, semantics: ['x'] }];
const pScoped = sign({ ...body1, profile_id: 'sem', scope: { semantic_types: ['money', 'email'] } }, SEED_A);
const pAny = sign({ ...body1, profile_id: 'any', scope: {} }, SEED_A);
const act = (verb: string, amount: any, extra: any = {}) => ({ action: { verb, resource: '/acct/1', params: { amount } }, ...extra });
const actions = [act('stripe.charge', 500), act('stripe.charge', 50), act('stripe.charge', 100), act('stripe.refund', 5), act('gmail.send', 1), act('stripe.refund', 'x'), { action: { verb: 'stripe.refund', resource: '/other', params: {} } }];
for (const p of [p1, pScoped, pAny]) for (const u of [...us, { aud: 'a', verb: 'v', now: 1, semantics: ['money'] }, { aud: 'a', verb: 'v', now: 1, semantics: [] }, { aud: 'a', verb: 'v', now: 1, semantics: ['nope'] }]) {
  await run('profileApplies', P.profileApplies, [p, u]);
  for (const a of actions) { await run('standingAdmits', P.standingAdmits, [p, u, a]); await run('standingPermits', P.standingPermits, [p, u, a]); }
}
// veto cells + ceiling over a derived omega
const amtC = (op: string, v: number) => ({ field: 'action.params.amount', op, value: v });
const om = O.deriveOmega({ policies: [{ predicates: [{ verb: 'stripe.refund', where: [amtC('lte', 100), amtC('lte', 500)] }, { verb: 'stripe.charge', where: [amtC('gt', 100)] }] }] });
const pv = sign({ ...body1, profile_id: 'veto', prior: { observations: [
  { verb: 'stripe.refund', values: { 'action.params.amount': 500 }, y: 0, at: 1 }, { verb: 'stripe.refund', values: { 'action.params.amount': 501 }, y: 0, at: 2 }, { verb: 'stripe.refund', values: { 'action.params.amount': 600 }, y: 0, at: 3 },
  { verb: 'stripe.refund', values: { 'action.params.amount': 5 }, y: 1, at: 4 }, { verb: 'nope.verb', values: {}, y: 0, at: 5 }, { verb: 'stripe.charge', values: {}, y: 0, at: 6 }, { verb: 'stripe.charge', values: { 'action.params.amount': 'x' }, y: 0, at: 7 },
  { verb: 'stripe.charge', values: { 'action.params.amount': 101 }, y: 0, at: 8 }], maps: [] } }, SEED_A);
await run('profileVetoCells', P.profileVetoCells, [pv, om]);
await run('profileVetoCells', P.profileVetoCells, [p1, om]);
await run('profileVetoCells', P.profileVetoCells, [p3, om]);
for (const vs of om.verbs) {
  const total = O.verbCellCount(vs);
  for (let f = 0; f < total; f++) for (const p of [p1, pAny]) for (const u of [{ aud: 'shop.example', now: 1800000000000 }, { aud: 'x', now: 1800000000000 }, { aud: 'shop.example', now: 1950000000000 }]) {
    const ov = O.cellRep(vs, O.decodeCell(vs, f));
    await run('profileCeiling', (pp: any, uu: any, v: any, oo: any) => P.profileCeiling(pp, uu)(v, oo), [p, u, vs, ov]);
  }
}
// usable
const cs: any[] = [{ now: 1800000000000, maxAgeMs: 60000 }, { now: 1900000000000, maxAgeMs: 60000 }, { now: 1800000000000, maxAgeMs: -1 }, { now: 1800000000000, maxAgeMs: 60000, revocation: {} },
  { now: 1800000000000, maxAgeMs: 60000, revocation: 5 }, { now: 1800000000000, maxAgeMs: 60000, revocation: { epoch: null, revoked: [] } }, { now: 1.5, maxAgeMs: 60000 }, { now: 1800000000000, maxAgeMs: 60000, pin: {} }];
for (const p of [p1, p3, { ...p1, sig: 'AAAA' }]) for (const c of cs) await runKeep('profileUsable', P.profileUsable, [p, c]);
// No case above carries a revocation epoch the profile's authority signed, so profileUsable never got past the revocation step. These do: an
// epoch signed by the owner (or by the profile's dedicated revocation key), with the full revoked list, then each later refusal of the check.
const RV: any = await import('../../../packages/pca/src/revocation').then((m: any) => m.default ?? m);
const NOW = 1800000000000;
const ev = (profileId: string, sd: string, revoked: string[], over: any = {}) => {
  const list = [...revoked].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const body = { instance_id: 'ins_profile', grant_ref: `pca-intent-profile:${profileId}`, epoch: list.length, set_size: list.length, root: new RV.RevocationSet(list).root, issued_at: NOW - 1000, not_after: NOW + 600000, ...over };
  return { epoch: RV.signRevocationEpoch(unseed(sd), body), revoked: list };
};
const use = (c: any = {}) => ({ now: NOW, maxAgeMs: 60000, ...c });
const pKey = sign({ ...body1, profile_id: 'keyed', revocation: { epoch_uri: 'u', key: sign(body1, SEED_B).owner } }, SEED_A);
const id1 = 'pca-intent:profile:travel@1', id2 = 'pca-intent:profile:travel@2';
const usable: [any, any][] = [
  [p1, use({ revocation: ev('travel', SEED_A, []) })], [p1, use({ revocation: ev('travel', SEED_A, ['pca-intent:profile:other@1', id2]) })], [p2, use({ revocation: ev('travel', SEED_A, [id1]) })],
  [pKey, use({ revocation: ev('keyed', SEED_B, []) })], [p1, use({ revocation: ev('travel', SEED_A, ['pca-intent:map:x']), last: ev('travel', SEED_A, []) })], [p1, use({ maxAgeMs: 1000, revocation: ev('travel', SEED_A, []) })],
  [p1, use({ revocation: ev('travel', SEED_A, [id1]) })], [p2, use({ revocation: ev('travel', SEED_A, [id1, id2]) })], [pKey, use({ revocation: ev('keyed', SEED_A, []) })], [p1, use({ revocation: ev('travel', SEED_B, []) })],
  [p1, use({ revocation: ev('other', SEED_A, []) })], [p1, use({ maxAgeMs: 999, revocation: ev('travel', SEED_A, []) })], [p1, use({ revocation: ev('travel', SEED_A, [], { not_after: NOW - 1 }) })],
  [p1, use({ revocation: ev('travel', SEED_A, [], { issued_at: NOW + 60001 }) })], [p1, use({ revocation: ev('travel', SEED_A, [], { epoch: 1 }) })], [p1, use({ revocation: { ...ev('travel', SEED_A, ['a', 'b']), revoked: ['b', 'a'] } })],
  [p1, use({ revocation: { ...ev('travel', SEED_A, ['a']), revoked: ['b'] } })], [p1, use({ revocation: { ...ev('travel', SEED_A, []), extra: 1 } })], [p1, use({ revocation: ev('travel', SEED_A, []), last: ev('travel', SEED_A, ['pca-intent:map:x']) })],
  [p1, use({ revocation: ev('travel', SEED_A, ['pca-intent:map:y']), last: ev('travel', SEED_A, ['pca-intent:map:x']) })], [p1, use({ now: 1900000000000, revocation: ev('travel', SEED_A, []) })],
  [{ ...p1, sig: 'AAAA' }, use({ revocation: ev('travel', SEED_A, []) })], [p1, use({ revocation: { ...ev('travel', SEED_A, []), epoch: { ...ev('travel', SEED_A, []).epoch, sig: ev('travel', SEED_A, ['a']).epoch.sig } } })],
];
for (const [p, c] of usable) await runKeep('profileUsable', P.profileUsable, [p, c]);
refWrite(o, 'intent-profile');
