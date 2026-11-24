// Oracle (python lane): @atlasauth/pca-actions import/review.ts + transparency.ts. Writes out/ref-actions-review-py.json.gz.
// PORTING table: verifyAttestation(def, {pins, regDefs|null}) -> verify_attestation_verdict; reviewStatus / revertStale(def, pins, regDefs|null); reviewPriority / reviewQueueOrder(defs, regDefs|null);
//   prepareReview(def, regDefs|null, previous?); confirmDef(def, {pins?, finalTraits, dismissed?, ts, kid, seed: {$bytes}, regDefs|null}) (a throw is compared by code);
//   packStatementPayload(pack) / appendPackToLog(packs[], seedEd, seedReg, n) -> list of entries; verifyPackLogEntry(pack, entry, {registry: pub, log: pub}, treeRoot?)
import { createPrivateKey, createPublicKey } from 'node:crypto';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as BD0 from '../../../packages/pca-actions/src/build.ts';
import * as RV0 from '../../../packages/pca-actions/src/import/review.ts';
import * as TR0 from '../../../packages/pca-actions/src/transparency.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as T0 from '../../../packages/pca-actions/src/traits.ts';
import * as EF0 from '../../../packages/pca-actions/src/effective.ts';
import * as SC0 from '../../../packages/pca-scitt/src/index.ts';
import * as ST0 from '../../../packages/pca-scitt/src/testing.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, refWriteSubset, clone, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), BD = un(BD0), RV = un(RV0), TR = un(TR0), CT = un(CT0), T = un(T0), EF = un(EF0), SC: any = (SC0 as any).default ?? SC0, ST: any = (ST0 as any).default ?? ST0;
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-review-py', 'tools/pca-audit/oracles/actions-review-py.mts', 'TS-reference oracle for pca-actions review flow and pack transparency (python lane).');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });
const sk = (b: any) => Uint8Array.from(Buffer.from(b.$bytes, 'base64url'));
const REV = seed('ref-actions-review-py/rev'), REV2 = seed('ref-actions-review-py/rev2'), IMP = seed('ref-actions-review-py/imp');
const EXTRA = [{ id: 'acme.extra', implies: ['pca.network_egress'], floor: T.profile({ risk: 2, rev: 'reversible', blast_ppm: 100000, esc: 1, caveats: ['amount_cap', 'recipient_scope'], context: [], prules: [] }), card_phrase: 'does the acme thing' }];
const regOf = (rd: any) => (rd == null ? CORE : T.extendRegistry(CORE, rd));
const PINS: any = { keys: [{ kid: 'rev1', pk: P.b64u(P.publicKeyOf(REV)), roles: ['reviewer'], not_before: 100, not_after: 2_000_000_000 }, { kid: 'rev2', pk: P.b64u(P.publicKeyOf(REV2)), roles: ['reviewer'] }, { kid: 'imp1', pk: P.b64u(P.publicKeyOf(IMP)), roles: ['importer'] }] };
const conf = (d: any, over: any = {}) => RV.confirmDef(d, { registry: CORE, reviewer: { kid: 'rev1', secret: REV }, finalTraits: EF.hintTraits(d), ts: 1000, ...over });
const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };

// ---- verdicts
const D = ALL.slice(0, 8);
const C = D.map((d) => conf(d));
const att = (d: any, f: (a: any) => void) => mut(d, (x) => f(x.review.attestation));
const VER: [string, any, any, any][] = [];
for (const [i, c] of C.entries()) VER.push([`ok${i}`, c, PINS, null]);
VER.push(['unconfirmed', D[0], PINS, null], ['authored', D[1], PINS, null]);
VER.push(['tampered', mut(C[0], (x) => (x.title = 'Other')), PINS, null], ['traits edited', mut(C[0], (x) => (x.traits = [...(x.traits ?? []), 'pca.bulk'])), PINS, null]);
VER.push(['custom registry', C[0], PINS, EXTRA], ['custom accepted', C[0], { ...PINS, traits_digests: [(await import('../../../packages/pca-actions/src/digest.ts').then(un)).traitsDigest(CORE)] }, EXTRA]);
VER.push(['no sig', att(C[0], (a) => delete a.sig), PINS, null], ['facts num', att(C[0], (a) => (a.facts_digest = 5)), PINS, null], ['final not array', att(C[0], (a) => (a.final_traits = 'x')), PINS, null],
  ['dismissed bad', att(C[0], (a) => (a.dismissed = [5])), PINS, null], ['ts float', att(C[0], (a) => (a.ts = 1.5)), PINS, null], ['kid num', att(C[0], (a) => (a.reviewer_kid = 5)), PINS, null],
  ['dismissed conflict', att(C[0], (a) => { a.final_traits = ['pca.x']; a.dismissed = [{ trait: 'pca.x', reason: 'r' }]; }), PINS, null], ['blank dismissal', att(C[0], (a) => (a.dismissed = [{ trait: 'pca.q', reason: '  ' }])), PINS, null],
  ['unknown kid', att(C[0], (a) => (a.reviewer_kid = 'zzz')), PINS, null], ['importer kid', att(C[0], (a) => (a.reviewer_kid = 'imp1')), PINS, null], ['bad sig', att(C[0], (a) => (a.sig = 'A'.repeat(86))), PINS, null],
  ['late', att(C[0], (a) => (a.ts = 3_000_000_000)), PINS, null], ['early', att(C[0], (a) => (a.ts = 5)), PINS, null], ['no attestation', mut(C[0], (x) => delete x.review.attestation), PINS, null],
  ['attestation scalar', mut(C[0], (x) => (x.review.attestation = 5)), PINS, null], ['bad pins', C[0], { keys: 5 }, null], ['pins dup', C[0], { keys: [PINS.keys[0], PINS.keys[0]] }, null], ['other pins', C[0], { keys: [PINS.keys[1]] }, null]);
for (const [n, d, pins, rd] of VER) {
  await o.run('verifyAttestation', n, (x: any, p: any, r: any) => RV.verifyAttestation(x, { pins: p, registry: regOf(r) }), [d, pins, rd]);
  await o.run('reviewStatus', n, (x: any, p: any, r: any) => RV.reviewStatus(x, { pins: p, registry: regOf(r) }), [d, pins, rd]);
  await o.run('revertStale', n, (x: any, p: any, r: any) => RV.revertStale(x, { pins: p, registry: regOf(r) }), [d, pins, rd]);
}
// ---- queue / view
for (const d of ALL) await o.run('reviewPriority', d.verb, (x: any) => RV.reviewPriority(x, CORE), [d]);
await o.run('reviewQueueOrder', 'all', (ds: any) => RV.reviewQueueOrder(ds, CORE).map((d: any) => d.verb), [ALL]);
await o.run('reviewQueueOrder', 'empty', (ds: any) => RV.reviewQueueOrder(ds, CORE).map((d: any) => d.verb), [[]]);
for (const d of ALL.slice(0, 12)) {
  await o.run('prepareReview', d.verb, (x: any) => RV.prepareReview(x, CORE), [d]);
  await o.run('prepareReview', d.verb + ' prev', (x: any, p: any) => RV.prepareReview(x, CORE, { previous: p }), [mut(d, (x) => { x.title = 'Changed'; x.effects = [...x.effects, 'read']; x.since = '9'; x.review = { state: 'unreviewed' }; delete x.description; }), d]);
}
await o.run('prepareReview', 'suggested', (x: any) => RV.prepareReview(x, CORE), [mut(D[0], (x) => { x.review = { state: 'suggested', suggested_by: { added: { traits: ['pca.bulk'], roles: {}, tags: {} } } }; })]);
// ---- confirmDef
const CD = (n: string, d: any, over: any = {}) => o.run('confirmDef', n, (x: any, oo: any) => RV.confirmDef(x, { registry: regOf(oo.regDefs), reviewer: { kid: oo.kid ?? 'rev1', secret: sk(oo.seed) }, ...(oo.pins ? { pins: oo.pins } : {}), finalTraits: oo.finalTraits, ...(oo.dismissed ? { dismissed: oo.dismissed } : {}), ts: oo.ts, }),
  [d, { seed: bytes(REV), kid: 'rev1', finalTraits: EF.hintTraits(d), ts: 1000, regDefs: null, ...over }]);
for (const d of D) { await CD(`ok ${d.verb}`, d); await CD(`pins ${d.verb}`, d, { pins: PINS }); }
await CD('ts neg', D[0], { ts: -1 }); await CD('ts float', D[0], { ts: 1.5 }); await CD('ts zero', D[0], { ts: 0 });
await CD('dup final', D[0], { finalTraits: ['pca.bulk', 'pca.bulk'] }); await CD('unknown trait', D[0], { finalTraits: ['pca.nope'] }); await CD('bad id', D[0], { finalTraits: ['x'] }); await CD('unreviewed marker', D[0], { finalTraits: ['pca.unreviewed'] });
await CD('empty final', D[2], { finalTraits: [] });
await CD('undismissed', mut(D[0], (x) => { x.review = { state: 'suggested', suggested_by: { added: { traits: ['pca.bulk'], roles: {}, tags: {} } } }; }), { finalTraits: [] });
await CD('dismissed ok', mut(D[0], (x) => { x.review = { state: 'suggested', suggested_by: { added: { traits: ['pca.bulk'], roles: {}, tags: {} } } }; }), { finalTraits: [], dismissed: [{ trait: 'pca.bulk', reason: 'one at a time' }] });
await CD('dismissed blank', mut(D[0], (x) => { x.review = { state: 'suggested', suggested_by: { added: { traits: ['pca.bulk'], roles: {}, tags: {} } } }; }), { finalTraits: [], dismissed: [{ trait: 'pca.bulk', reason: '  ' }] });
await CD('dismissed long', D[0], { dismissed: [{ trait: 'pca.bulk', reason: 'x'.repeat(257) }] }); await CD('dismissed twice', D[0], { dismissed: [{ trait: 'pca.bulk', reason: 'r' }, { trait: 'pca.bulk', reason: 'r' }] });
await CD('dismissed final', D[0], { dismissed: [{ trait: EF.hintTraits(D[0])[0], reason: 'r' }] }); await CD('dismissed never suggested', D[0], { finalTraits: EF.hintTraits(D[0]), dismissed: [{ trait: 'pca.persistence', reason: 'r' }] });
await CD('pins wrong kid', D[0], { pins: PINS, kid: 'zzz' }); await CD('pins importer', D[0], { pins: PINS, kid: 'imp1', seed: bytes(IMP) }); await CD('pins wrong secret', D[0], { pins: PINS, seed: bytes(REV2) }); await CD('pins bad', D[0], { pins: { keys: 5 } });
await CD('custom registry', D[0], { regDefs: EXTRA, finalTraits: [...EF.hintTraits(D[0]), 'acme.extra'] });

// ---- transparency
const edPriv = (s: Uint8Array) => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(s)]), format: 'der', type: 'pkcs8' });
const edPub = (raw: Uint8Array) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw)]), format: 'der', type: 'spki' });
const pubOf = (s: Uint8Array) => Uint8Array.from(Buffer.from(P.publicKeyOf(s)));
const REG = seed('ref-actions-review-py/registry'), LOG = seed('ref-actions-review-py/log'), OTHER = seed('ref-actions-review-py/other');
const CFG = (v: string, ns = 'acme') => ({ ns, version: v, stability: 'beta', site: 'https://acme.example', aud: 'agents' });
const PACKS = [BD.signPack(BD.buildArtifacts(ALL.slice(0, 4), CFG('1.0.0'), CORE).pack, 'pub1', REG, CORE), BD.signPack(BD.buildArtifacts(ALL.slice(0, 6), CFG('1.1.0'), CORE).pack, 'pub1', REG, CORE), BD.signPack(BD.buildArtifacts(ALL.slice(0, 6), CFG('2.0.0', 'other'), CORE).pack, 'pub1', REG, CORE)];
for (const [i, p] of PACKS.entries()) await o.run('packStatementPayload', `p${i}`, TR.packStatementPayload, [p]);
await o.run('appendPackToLog', 'three', (ps: any, sr: any, sl: any) => { const svc = new ST.TransparencyService({ alg: 'EdDSA', key: edPriv(sk(sl)), issuer: 'ts' }); return ps.map((p: any) => TR.appendPackToLog(p, svc, { alg: 'EdDSA', key: edPriv(sk(sr)), issuer: 'registry' })); }, [PACKS, bytes(REG), bytes(LOG)]);
const logOf = () => { const svc = new ST.TransparencyService({ alg: 'EdDSA', key: edPriv(LOG), issuer: 'ts' }); return { svc, entries: PACKS.map((p: any) => TR.appendPackToLog(p, svc, { alg: 'EdDSA', key: edPriv(REG), issuer: 'registry' })) }; };
const { svc, entries } = logOf();
const ub = (v: any) => (v && typeof v === 'object' && v.$bytes !== undefined ? sk(v) : v);
const VE = (n: string, pack: any, entry: any, regPub: Uint8Array, logPub: Uint8Array, root?: string) => o.run('verifyPackLogEntry', n, (p: any, e: any, kr: any, kl: any, r: any) => TR.verifyPackLogEntry(p, { statement: ub(e.statement), receipt: ub(e.receipt) }, { registry: edPub(sk(kr)), log: edPub(sk(kl)) }, r ?? undefined), [pack, entry, bytes(regPub), bytes(logPub), root ?? null]);
for (const [i, p] of PACKS.entries()) {
  await VE(`ok${i}`, p, entries[i], pubOf(REG), pubOf(LOG));
  await VE(`ok root${i}`, p, entries[i], pubOf(REG), pubOf(LOG), entries[i].root);
  await VE(`wrong root${i}`, p, entries[i], pubOf(REG), pubOf(LOG), entries[(i + 1) % 3].root);
  await VE(`wrong registry key${i}`, p, entries[i], pubOf(OTHER), pubOf(LOG));
  await VE(`wrong log key${i}`, p, entries[i], pubOf(REG), pubOf(OTHER));
  await VE(`other pack${i}`, PACKS[(i + 1) % 3], entries[i], pubOf(REG), pubOf(LOG));
  await VE(`other statement${i}`, p, { statement: entries[(i + 1) % 3].statement, receipt: entries[i].receipt }, pubOf(REG), pubOf(LOG));
}
await VE('tampered pack', { ...PACKS[0], root: 'x'.repeat(43) }, entries[0], pubOf(REG), pubOf(LOG));
await VE('null entry', PACKS[0], { statement: null, receipt: null } as any, pubOf(REG), pubOf(LOG));
void svc;
refWrite(o, 'actions-review-py');
refWriteSubset(o, 'actions-review', ['verifyAttestation', 'reviewStatus', 'revertStale', 'reviewPriority', 'reviewQueueOrder', 'prepareReview', 'confirmDef'], 'the review flow without the pack transparency log');
