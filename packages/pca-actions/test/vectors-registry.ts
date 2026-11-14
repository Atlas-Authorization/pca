// vectors-registry.ts - shared vectors for rule 22 (floor integrity + FloorDecision), signed packs, evolution records, principal
// re-approvals, the grant pin, inclusion proofs and the rollback tracker (track A4). Natives (A7) verify signatures, digests and
// pins; they do not recompute the diff, so every vector here is decidable from the document alone. All keys are derived from fixed
// labels; Ed25519 signatures are deterministic, so the files are reproducible.
import { b64u, publicKeyOf, sha256, utf8 } from '@atlasauth/pca';
import { TEST_PINS, confirmed, testReview } from './reviewed';
import {
  EVOLUTION_RECORD_KIND, decidePin, evolutionDiffDigest, registryKeyOf, reapprovalValid, signEvolutionRecord, signReapproval, verifyEvolutionRecord, type ActionSchemaKey, type EvolutionRecord,
} from '@atlasauth/pca/ext/intent';
import {
  BUILTIN_DEFS, CORE_REGISTRY, PackTracker, RULE22_ENGINE, buildPack, defDigest, evolutionRecords, extendRegistry, packDigest, packProof, packRoot, profile, schemaFloorError, toSchemaDoc, toSchemaVerb, verifyActionPack as verifyPack, verifyPackProof,
  type ActionDef, type ActionPack, type PackShard, type TraitDef,
} from '../src';

export interface RCase { id: string; kind: string; input: unknown; expect: unknown }
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const seed = (l: string) => sha256(utf8(`atlas-pca-vectors/action-kit-registry/${l}`));
const REG = seed('registry');
const OTHER = seed('other-registry');
const PRINCIPAL = seed('principal');
export const REG_KEYS: ActionSchemaKey[] = [registryKeyOf('reg-1', REG)];
const SRC = { kind: 'hand', uri: 'internal://vectors', spec_digest: 'A'.repeat(43), licence: 'Apache-2.0', licence_notes: 'authored for the vectors' };
const patchDef = (d: ActionDef, f: (x: Record<string, any>) => void): ActionDef => { const c = clone(d) as unknown as Record<string, any>; f(c); return c as ActionDef; };

const CODES = ['schema_floor_forged', 'schema_traits_forged', 'unknown_trait', 'traits_digest_mismatch', 'bad_registry'];
const codeOf = (e: string | null): { ok: true } | { ok: false; code: string } => (e === null ? { ok: true } : { ok: false, code: CODES.find((c) => e.includes(c)) ?? 'unknown' });

export function replayRegistry(c: RCase): unknown {
  const i = c.input as Record<string, any>;
  switch (c.kind) {
    case 'rule22_schema': return codeOf(schemaFloorError(i.doc, i.pins));
    case 'rule22': {
      const integ = codeOf(schemaFloorError(i.doc, i.pins));
      if (!integ.ok) return { integrity: integ.code, decision: 'deny' };
      return { integrity: 'ok', decision: RULE22_ENGINE.decide({ doc: i.doc, verb: i.verb, grant: i.grant, context: i.context }) };
    }
    case 'pack_verify': {
      const v = verifyPack(i.pack, i.keys, i.shards ? { shards: i.shards as Record<string, PackShard> } : {});
      return v.ok ? { ok: true, digest: v.digest, defs: v.defs.length } : { ok: false };
    }
    case 'evolution_verify': return { ok: verifyEvolutionRecord(i.record, i.keys).ok, diff: (() => { try { return evolutionDiffDigest(i.record); } catch { return null; } })() };
    case 'reapproval_verify': return { ok: reapprovalValid(i.reapproval, i.grant.id, i.grant.issuer, i.verb, i.diff) };
    case 'pin': {
      const d = decidePin(i as never);
      return d.ok ? { ok: true, via: d.via } : { ok: false, code: d.code, escalate: d.escalate, ...(d.needs_reapproval !== undefined ? { needs_reapproval: d.needs_reapproval } : {}) };
    }
    case 'pack_proof_verify': return { ok: verifyPackProof(i.root, i.proof, i.digest) };
    case 'tracker': {
      const t = new PackTracker(i.keys);
      return (i.steps as Array<{ pack: ActionPack; shards?: Record<string, PackShard> }>).map((s) => { const r = t.accept(s.pack, s.shards); return r.ok ? { ok: true, status: r.status } : { ok: false, code: r.code }; });
    }
    default: throw new Error(`unknown vector kind ${c.kind}`);
  }
}
export const REGISTRY_KINDS: readonly string[] = ['rule22_schema', 'rule22', 'pack_verify', 'evolution_verify', 'reapproval_verify', 'pin', 'pack_proof_verify', 'tracker'];

export function registryCases(): RCase[] {
  const cases: RCase[] = [];
  const mk = (id: string, kind: string, input: unknown) => cases.push({ id, kind, input, expect: undefined as unknown });

  // ---- rule 22: floor integrity of a whole document, and the decision ---------------------------------------------------------
  const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
  const invoiceLike = BUILTIN_DEFS.find((d) => d.effects.includes('send')) ?? BUILTIN_DEFS[0]!;
  const honest = (defs: ActionDef[]) => toSchemaDoc(defs.map((d) => confirmed(d)), CORE_REGISTRY, { site: 'https://pay.example', aud: 'pay', version: '1' }, testReview()) as unknown as Record<string, any>;
  const strip = (doc: Record<string, any>) => { const d = clone(doc); delete d.sig; return d; };
  const docOk = honest([refund, invoiceLike]);
  const at = (d: Record<string, any>, verb: string): number => d.verbs.findIndex((v: any) => v.verb === verb);
  const iR = at(docOk, 'stripe.refund');
  const iO = at(docOk, invoiceLike.verb);
  const rs = (name: string, f: (d: Record<string, any>) => void) => { const d = clone(docOk); f(d); mk(`rule22-schema-${name}`, 'rule22_schema', { doc: d, pins: TEST_PINS }); };
  rs('honest', () => undefined);
  rs('floors-esc-lowered', (d) => { d.verbs[iR].floors.esc = 0; });
  rs('floors-caveats-dropped', (d) => { d.verbs[iR].floors.caveats = []; });
  rs('floors-rev-lowered', (d) => { d.verbs[iR].floors.rev = 'reversible'; });
  rs('floors-blast-lowered', (d) => { d.verbs[iR].floors.blast_ppm = 0; });
  rs('floors-context-dropped', (d) => { d.verbs[iR].floors.context = []; });
  rs('floors-prules-dropped', (d) => { d.verbs[iR].floors.prules = []; });
  rs('floors-risk-lowered', (d) => { d.verbs[iR].floors.risk = 0; });
  rs('trait-dropped', (d) => { d.verbs[iR].traits = d.verbs[iR].traits.filter((t: string) => t !== 'pca.money_moving'); });
  rs('trait-unknown', (d) => { d.verbs[iR].traits = [...d.verbs[iR].traits, 'pca.zzz']; });
  rs('second-verb-forged', (d) => { d.verbs[iO].floors = profile(); });
  rs('floors-raised-is-fine', (d) => { d.verbs[iR].floors.esc = 3; });
  rs('traits-digest-wrong', (d) => { d.traits_digest = 'A'.repeat(43); });
  rs('custom-trait-weakening-core', (d) => { d.trait_defs = [{ id: 'pca.money_moving', implies: [], floor: profile(), card_phrase: 'x' }]; });
  const mt = CORE_REGISTRY.traits.get('pca.money_moving')!;
  const custom: TraitDef = { id: 'acme.strict', implies: ['pca.money_moving'], floor: profile({ ...mt.floor, esc: 3 }), card_phrase: 'is stricter than money movement' };
  const regC = extendRegistry(CORE_REGISTRY, [custom]);
  const docC = toSchemaDoc([confirmed(patchDef(refund, (x) => { x.traits = ['acme.strict']; }), regC)], regC, { site: 'https://pay.example', aud: 'pay', version: '1' }, testReview(regC)) as unknown as Record<string, any>;
  mk('rule22-schema-custom-honest', 'rule22_schema', { doc: docC, pins: TEST_PINS });
  { const d = clone(docC); d.verbs[0].floors.esc = 2; mk('rule22-schema-custom-floor-lowered', 'rule22_schema', { doc: d, pins: TEST_PINS }); }
  { const d = clone(docC); d.trait_defs = []; mk('rule22-schema-custom-defs-missing', 'rule22_schema', { doc: d, pins: TEST_PINS }); }
  mk('rule22-schema-v1-verb', 'rule22_schema', { doc: { verbs: [{ verb: 'a.b.c', kind: 'write', params: {} }] }, pins: TEST_PINS });

  const eff = (d: Record<string, any>, verb = 'stripe.refund') => d.verbs[at(d, verb)].floors;
  const grantFor = (f: any, over: Record<string, any> = {}) => ({ caveats: f.caveats, max_esc: 3, preauth_esc: f.esc, ...over });
  const r22 = (name: string, doc: Record<string, any>, verb: string, grant: any, context: string[]) => mk(`rule22-${name}`, 'rule22', { doc, verb, grant, context, pins: TEST_PINS });
  r22('allow', docOk, 'stripe.refund', grantFor(eff(docOk)), eff(docOk).context);
  r22('missing-caveat', docOk, 'stripe.refund', grantFor(eff(docOk), { caveats: [] }), eff(docOk).context);
  r22('esc-above-preauth', docOk, 'stripe.refund', grantFor(eff(docOk), { preauth_esc: Math.max(0, eff(docOk).esc - 1) }), eff(docOk).context);
  r22('esc-above-max', docOk, 'stripe.refund', grantFor(eff(docOk), { max_esc: Math.max(0, eff(docOk).esc - 1), preauth_esc: 0 }), eff(docOk).context);
  r22('missing-context', docOk, 'stripe.refund', grantFor(eff(docOk)), []);
  r22('unknown-verb', docOk, 'nope.nothing.do', grantFor(eff(docOk)), []);
  { const d = clone(docOk); d.verbs[iR].floors.esc = 0; r22('forged-floors-denied', d, 'stripe.refund', { caveats: [], max_esc: 3, preauth_esc: 3 }, []); }
  { const d = clone(docOk); d.verbs[iR].traits = []; r22('dropped-traits-denied', d, 'stripe.refund', { caveats: [], max_esc: 3, preauth_esc: 3 }, []); }
  r22('custom-strict-needs-stepup', docC, 'stripe.refund', grantFor(eff(docC), { preauth_esc: 2 }), eff(docC).context);
  r22('custom-strict-allow', docC, 'stripe.refund', grantFor(eff(docC)), eff(docC).context);
  r22('second-verb-allow', docOk, invoiceLike.verb, grantFor(eff(docOk, invoiceLike.verb)), eff(docOk, invoiceLike.verb).context);
  void strip;

  // ---- signed packs ---------------------------------------------------------------------------------------------------------------
  const stripe = BUILTIN_DEFS.filter((d) => d.verb.startsWith('stripe.')).slice(0, 3);
  const bp = (defs: ActionDef[], version: string, prev?: ActionPack, extra: Record<string, unknown> = {}) =>
    buildPack({ ns: 'stripe', version, stability: 'stable', defs, source: SRC, kid: 'reg-1', secret: REG, ...(prev ? { prev: { pack: prev } } : {}), ...extra } as never);
  const p1 = bp(stripe, '1.0.0').pack;
  const pv = (name: string, f: (p: any) => void, keys: ActionSchemaKey[] = REG_KEYS) => { const p = clone(p1) as any; f(p); mk(`pack-verify-${name}`, 'pack_verify', { pack: p, keys }); };
  pv('honest', () => undefined);
  pv('def-title-changed', (p) => { p.defs[0].title = 'Changed'; });
  pv('def-removed', (p) => { p.defs.pop(); });
  pv('defs-reversed', (p) => { p.defs.reverse(); });
  pv('def-duplicated', (p) => { p.defs.push(clone(p.defs[0])); });
  pv('root-wrong', (p) => { p.root = 'B'.repeat(43); });
  pv('version-changed', (p) => { p.version = '1.0.1'; });
  pv('ns-changed', (p) => { p.ns = 'other'; });
  pv('stability-changed', (p) => { p.stability = 'draft'; });
  pv('source-changed', (p) => { p.source.licence = 'MIT'; });
  pv('prev-set', (p) => { p.prev = 'C'.repeat(43); });
  pv('unknown-member', (p) => { p.extra = 1; });
  pv('traits-digest-wrong', (p) => { p.traits_digest = 'D'.repeat(43); });
  pv('roles-digest-wrong', (p) => { p.roles_digest = 'D'.repeat(43); });
  pv('rules-digest-wrong', (p) => { p.rules_digest = 'D'.repeat(43); });
  pv('sig-alg-downgrade-claim', (p) => { p.sig.alg = 'hybrid-ed25519-ml-dsa-65'; });
  pv('sig-value-flipped', (p) => { p.sig.value = (p.sig.value[0] === 'A' ? 'B' : 'A') + p.sig.value.slice(1); });
  pv('sig-kid-unknown', (p) => { p.sig.kid = 'reg-9'; });
  pv('evolution-record-tampered', (p) => { p.evolution[0].class = 'equal'; });
  pv('evolution-record-dropped', (p) => { p.evolution.pop(); });
  pv('evolution-to-not-in-pack', (p) => { p.evolution[0].to = 'E'.repeat(43); });
  pv('no-keys', () => undefined, []);
  pv('wrong-key', () => undefined, [registryKeyOf('reg-1', OTHER)]);
  mk('pack-verify-resigned-by-other', 'pack_verify', { pack: buildPack({ ns: 'stripe', version: '1.0.0', stability: 'stable', defs: stripe, source: SRC, kid: 'reg-1', secret: OTHER }).pack, keys: REG_KEYS });
  // sharded
  const sh = bp(BUILTIN_DEFS.filter((d) => d.verb.startsWith('stripe.') || d.verb.startsWith('slack.')), '1.0.0', undefined, { shard: { max: 3 } });
  const names = Object.keys(sh.shards);
  mk('pack-verify-sharded-honest', 'pack_verify', { pack: sh.pack, keys: REG_KEYS, shards: sh.shards });
  mk('pack-verify-sharded-no-shards', 'pack_verify', { pack: sh.pack, keys: REG_KEYS });
  { const s = clone(sh.shards); delete s[names[0]!]; mk('pack-verify-sharded-missing-shard', 'pack_verify', { pack: sh.pack, keys: REG_KEYS, shards: s }); }
  { const s = clone(sh.shards); s[names[0]!]!.defs[0]!.title = 'Altered'; mk('pack-verify-sharded-altered-shard', 'pack_verify', { pack: sh.pack, keys: REG_KEYS, shards: s }); }
  { const s = clone(sh.shards); s[names[0]!]!.version = '9.9.9'; mk('pack-verify-sharded-foreign-shard', 'pack_verify', { pack: sh.pack, keys: REG_KEYS, shards: s }); }
  { const s = clone(sh.shards); s['extra']  = clone(s[names[0]!]!); mk('pack-verify-sharded-extra-shard-ignored', 'pack_verify', { pack: sh.pack, keys: REG_KEYS, shards: s }); }

  // ---- evolution records and re-approvals -----------------------------------------------------------------------------------
  const A = defDigest(refund);
  const widerRefund = patchDef(refund, (x) => { x.params.amount.max = 999_999_999_999; });
  const narrowRefund = patchDef(refund, (x) => { x.params.amount.max = 5000; });
  const widenRec = signEvolutionRecord(evolutionRecords('stripe', [refund], [widerRefund])[0]!, 'reg-1', REG);
  const narrowRec = signEvolutionRecord(evolutionRecords('stripe', [refund], [narrowRefund])[0]!, 'reg-1', REG);
  const ev = (name: string, record: unknown, keys: ActionSchemaKey[] = REG_KEYS) => mk(`evolution-${name}`, 'evolution_verify', { record, keys });
  ev('narrow-honest', narrowRec);
  ev('widen-honest', widenRec);
  ev('class-flipped', { ...narrowRec, class: 'widen' });
  ev('to-changed', { ...narrowRec, to: A });
  ev('reasons-changed', { ...narrowRec, reasons: [] });
  ev('wrong-key', narrowRec, [registryKeyOf('reg-1', OTHER)]);
  ev('no-keys', narrowRec, []);
  ev('unknown-member', { ...narrowRec, extra: 1 });
  ev('added-with-from', { ...narrowRec, class: 'added' });
  ev('bad-class', { ...narrowRec, class: 'sideways' });
  ev('added-honest', signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'stripe', verb: 'stripe.new.thing', from: null, to: A, class: 'added', reasons: [] }, 'reg-1', REG));
  ev('removed-honest', signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'stripe', verb: 'stripe.new.thing', from: A, to: null, class: 'removed', reasons: [] }, 'reg-1', REG));
  const GRANT = { id: 'G'.repeat(43), issuer: b64u(publicKeyOf(PRINCIPAL)) };
  const ra = signReapproval({ grantId: GRANT.id, record: widenRec, principalSecret: PRINCIPAL });
  const rv = (name: string, reapproval: unknown, over: Record<string, unknown> = {}) => mk(`reapproval-${name}`, 'reapproval_verify', { reapproval, grant: GRANT, verb: widenRec.verb, diff: evolutionDiffDigest(widenRec), ...over });
  rv('honest', ra);
  rv('other-grant', ra, { grant: { id: 'H'.repeat(43), issuer: GRANT.issuer } });
  rv('other-verb', ra, { verb: 'stripe.charge' });
  rv('other-diff', ra, { diff: evolutionDiffDigest(narrowRec) });
  rv('other-issuer', ra, { grant: { id: GRANT.id, issuer: b64u(publicKeyOf(OTHER)) } });
  rv('unknown-member', { ...ra, extra: 1 });
  rv('sig-flipped', { ...ra, sig: { alg: 'ed25519', value: (ra.sig.value[0] === 'A' ? 'B' : 'A') + ra.sig.value.slice(1) } });
  rv('sig-alg-claim', { ...ra, sig: { ...ra.sig, alg: 'ml-dsa-65' } });
  rv('null', null);

  // ---- the pin ---------------------------------------------------------------------------------------------------------------------
  const B = defDigest(narrowRefund), C = defDigest(widerRefund);
  const VERB = refund.verb;
  const PIN = { pack: { ns: 'stripe', root: 'R'.repeat(43) }, defs: { [VERB]: A }, on_new_action: 'deny' };
  const rec = (from: string, to: string, cls: string, over: Record<string, unknown> = {}, key = REG): EvolutionRecord =>
    signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'stripe', verb: VERB, from, to, class: cls as never, reasons: [], ...over }, 'reg-1', key);
  const doc = (def: string | undefined, pack: unknown = { ns: 'stripe', root: 'R'.repeat(43) }) => ({ pack, verbs: [{ verb: VERB, def }] });
  const pin = (name: string, over: Record<string, unknown>) => mk(`pin-${name}`, 'pin', { pin: PIN, doc: doc(A), verb: VERB, records: [], keys: REG_KEYS, reapprovals: [], grant: GRANT, ...over });
  pin('exact', {});
  pin('changed-no-chain', { doc: doc(B) });
  pin('narrow-chain', { doc: doc(B), records: [rec(A, B, 'narrow')] });
  pin('equal-chain', { doc: doc(B), records: [rec(A, B, 'equal')] });
  pin('two-hops', { doc: doc(C), records: [rec(A, B, 'narrow'), rec(B, C, 'equal')] });
  pin('missing-hop', { doc: doc(C), records: [rec(A, B, 'narrow')] });
  pin('widen-blocked', { doc: doc(B), records: [rec(A, B, 'widen')] });
  pin('incomparable-blocked', { doc: doc(B), records: [rec(A, B, 'incomparable')] });
  pin('widen-reapproved', { doc: doc(C), records: [widenRec], reapprovals: [ra] });
  pin('widen-reapproval-other-grant', { doc: doc(C), records: [widenRec], reapprovals: [signReapproval({ grantId: 'H'.repeat(43), record: widenRec, principalSecret: PRINCIPAL })] });
  pin('widen-reapproval-other-key', { doc: doc(C), records: [widenRec], reapprovals: [signReapproval({ grantId: GRANT.id, record: widenRec, principalSecret: OTHER })] });
  pin('unblocked-path-preferred', { doc: doc(C), records: [rec(A, C, 'widen'), rec(A, B, 'narrow'), rec(B, C, 'equal')] });
  pin('record-wrong-key', { doc: doc(B), records: [rec(A, B, 'narrow', {}, OTHER)] });
  pin('record-other-verb', { doc: doc(B), records: [rec(A, B, 'narrow', { verb: 'stripe.charge' })] });
  pin('record-other-ns', { doc: doc(B), records: [rec(A, B, 'narrow', { ns: 'other' })] });
  pin('record-backwards', { doc: doc(B), records: [rec(B, A, 'narrow')] });
  pin('cycle', { doc: doc(C), records: [rec(A, B, 'equal'), rec(B, A, 'equal')] });
  pin('new-verb-deny', { pin: { ...PIN, defs: { 'stripe.other.do': A } } });
  pin('new-verb-escalate', { pin: { ...PIN, defs: { 'stripe.other.do': A }, on_new_action: 'escalate' } });
  pin('pack-only-exact', { pin: { pack: PIN.pack, on_new_action: 'deny' } });
  pin('pack-only-root-differs', { pin: { pack: PIN.pack, on_new_action: 'deny' }, doc: doc(A, { ns: 'stripe', root: 'S'.repeat(43) }) });
  pin('pack-ns-differs', { doc: doc(A, { ns: 'other', root: 'R'.repeat(43) }) });
  pin('pack-missing', { doc: doc(A, null) });
  pin('def-missing', { doc: doc(undefined) });
  pin('verb-undeclared', { doc: { pack: PIN.pack, verbs: [] } });
  pin('pin-malformed', { pin: { ...PIN, on_new_action: 'maybe' } });
  pin('pin-unknown-member', { pin: { ...PIN, extra: 1 } });

  // ---- inclusion proofs ----------------------------------------------------------------------------------------------------------
  const digests = BUILTIN_DEFS.map(defDigest);
  const root = packRoot(digests);
  const proof = packProof(digests, digests[5]!);
  const pp = (name: string, input: Record<string, unknown>) => mk(`pack-proof-${name}`, 'pack_proof_verify', { root, proof, digest: digests[5], ...input });
  pp('honest', {});
  pp('first-leaf-honest', { proof: packProof(digests, digests[0]!), digest: digests[0] });
  pp('last-leaf-honest', { proof: packProof(digests, digests[digests.length - 1]!), digest: digests[digests.length - 1] });
  pp('other-digest', { digest: digests[6] });
  pp('other-root', { root: 'T'.repeat(43) });
  pp('proof-size-ignored', { proof: { ...proof, size: proof.size + 1 } });
  pp('path-truncated', { proof: { ...proof, path: proof.path.slice(0, -1) } });
  pp('index-changed', { proof: { ...proof, index: proof.index + 1 } });
  pp('sibling-flipped', { proof: { ...proof, path: proof.path.map((s, k) => (k === 0 ? { ...s, hash: 'U'.repeat(43) } : s)) } });

  // ---- rollback / replay / fork / chain gap -----------------------------------------------------------------------------------
  const p2 = bp([narrowRefund, ...stripe.filter((d) => d.verb !== VERB)], '1.1.0', p1).pack;
  const p3 = bp([patchDef(refund, (x) => { x.params.amount.max = 4000; }), ...stripe.filter((d) => d.verb !== VERB)], '1.2.0', p2).pack;
  const fork2 = bp([patchDef(refund, (x) => { x.params.amount.max = 4999; }), ...stripe.filter((d) => d.verb !== VERB)], '1.1.0', p1).pack;
  const forged2 = clone(p2) as any; forged2.defs[0].title = 'x';
  const tr = (name: string, steps: ActionPack[]) => mk(`tracker-${name}`, 'tracker', { keys: REG_KEYS, steps: steps.map((pack) => ({ pack })) });
  tr('upgrade-sequence', [p1, p2, p3]);
  tr('replay-same', [p1, p1, p2, p2]);
  tr('rollback', [p1, p2, p1]);
  tr('rollback-after-two', [p1, p2, p3, p2]);
  tr('fork-same-version', [p1, p2, fork2]);
  tr('chain-gap', [p1, p3]);
  tr('forged-pack', [p1, forged2]);
  tr('first-is-trusted-on-first-use', [p2, p3]);
  tr('after-refused-still-accepts-good', [p1, forged2, p2]);
  void packDigest; void toSchemaVerb;
  return cases.map((c) => ({ ...c, id: c.id }));
}
