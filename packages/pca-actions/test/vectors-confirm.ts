// vectors-confirm.ts - shared vectors for "unconfirmed means maximally dangerous" (track act-zero). Every case is decided by the
// reference implementation; natives must reproduce `expect`. Kinds reused: `effective` (def + the verifier's pinned reviewer keys),
// `schema_verb` (a v2 verb + pins), `rule22_schema` and `rule22` (a document + pins). With no pins, or without a valid signed
// confirmation by a PINNED key that covers THIS def digest and an accepted registry digest, a def's effective traits are the TOP
// of the registry and a verb must carry every trait. All keys are derived from fixed labels (Ed25519 is deterministic).
import { b64u, generateKeyPair, publicKeyOf, sha256, utf8 } from '@atlasauth/pca';
import {
  BUILTIN_DEFS, CORE_REGISTRY, defDigest, extendRegistry, floorOf, normalize, profile, signReview, factsDigest, toSchemaDoc, toSchemaVerb, topTraits, traitsDigest,
  type ActionDef, type PinnedKey, type ReviewRef, type ReviewerPins,
} from '../src';
import { TEST_PINS, TEST_REVIEWER, TEST_TS, confirmed, testReview } from './reviewed';

interface Case { id: string; kind: string; input: unknown; expect: unknown }
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const pad = (n: number) => String(n).padStart(3, '0');
const IMPORTER = sha256(utf8('atlas-pca-vectors/action-kit-confirm/importer'));
const OTHER = sha256(utf8('atlas-pca-vectors/action-kit-confirm/other-reviewer'));
const pk = (secret: Uint8Array): string => b64u(publicKeyOf(secret));

export function confirmationCases(defs: readonly ActionDef[]): Case[] {
  const cases: Case[] = [];
  const mk = (id: string, kind: string, input: unknown) => cases.push({ id, kind, input, expect: undefined as unknown });
  const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
  const read = BUILTIN_DEFS.find((d) => d.verb === 'github.read')!;

  // ---- effective: confirmed defs (exact), then every way of NOT being confirmed ---------------------------------------------------
  BUILTIN_DEFS.forEach((d, i) => mk(`effective-confirmed-builtin-${pad(i)}`, 'effective', { def: confirmed(d), pins: TEST_PINS }));
  defs.slice(0, 30).forEach((d, i) => mk(`effective-confirmed-gen-${pad(i)}`, 'effective', { def: confirmed(d), pins: TEST_PINS }));
  // machine-only claims of harmlessness never lower anything
  const quiet = (name: string, f: (d: Record<string, any>) => void) => { const d = clone(read) as unknown as Record<string, any>; f(d); mk(`effective-unconfirmed-${name}`, 'effective', { def: d, pins: TEST_PINS }); };
  quiet('read-no-machine-traits', () => undefined);
  quiet('state-suggested-empty', (d) => { d.review = { state: 'suggested', suggested_by: { added: { traits: [], roles: {}, tags: {} } } }; });
  quiet('state-unreviewed', (d) => { d.review = { state: 'unreviewed' }; });
  quiet('adjudicated-absent', (d) => { d.review = { state: 'authored', provenance: { adjudicated: ['pca.money_moving', 'pca.destructive', 'pca.external_communication'] } }; });
  quiet('declares-no-traits-explicitly', (d) => { d.traits = []; });
  quiet('state-confirmed-without-attestation', (d) => { d.review = { state: 'confirmed' }; });
  mk('effective-unconfirmed-no-pins', 'effective', { def: confirmed(refund) });
  mk('effective-unconfirmed-empty-pins', 'effective', { def: confirmed(refund), pins: { keys: [] } });

  // ---- forged / unpinned / stale confirmations -> top --------------------------------------------------------------------------------
  const body = (def: ActionDef, over: Record<string, unknown> = {}) => ({
    def_digest: defDigest(def), traits_digest: traitsDigest(CORE_REGISTRY), facts_digest: factsDigest(toSchemaVerb(def, CORE_REGISTRY).verb), final_traits: [...(def.traits ?? [])], dismissed: [] as { trait: string; reason: string }[],
    reviewer_kid: TEST_REVIEWER.kid, ts: TEST_TS, ...over,
  });
  const withAtt = (def: ActionDef, a: ReviewRef, state: string = 'confirmed'): ActionDef => ({ ...def, review: { state, attestation: a } } as ActionDef);
  const sign = (def: ActionDef, over: Record<string, unknown> = {}, secret: Uint8Array = TEST_REVIEWER.secret): ReviewRef => signReview(body(def, over) as never, secret);
  const adv = (name: string, def: ActionDef, pins: unknown = TEST_PINS) => mk(`effective-adv-${name}`, 'effective', { def, pins });
  adv('valid', withAtt(refund, sign(refund)));
  adv('signature-flipped', withAtt(refund, { ...sign(refund), sig: sign(refund).sig!.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) }));
  adv('def-edited-after-signing', { ...withAtt(refund, sign(refund)), title: 'Refund something else' });
  adv('param-edited-after-signing', (() => { const d = clone(withAtt(refund, sign(refund))) as unknown as Record<string, any>; d.params.amount.max = 999_999_999; return d as ActionDef; })());
  adv('traits-digest-of-another-registry', withAtt(refund, sign(refund, { traits_digest: 'A'.repeat(43) })));
  adv('final-traits-differ-from-declared', withAtt(refund, sign(refund, { final_traits: ['pca.bulk'] })));
  adv('unknown-reviewer-kid', withAtt(refund, sign(refund, { reviewer_kid: 'nobody' })));
  adv('dismissal-without-reason', withAtt(refund, sign(refund, { dismissed: [{ trait: 'pca.bulk', reason: '' }] })));
  adv('dismissal-of-a-final-trait', withAtt(refund, sign(refund, { final_traits: ['pca.bulk'], dismissed: [{ trait: 'pca.bulk', reason: 'x' }] })));
  adv('signed-by-unpinned-key', withAtt(refund, sign(refund, {}, OTHER)));
  adv('state-authored-with-attestation', withAtt(refund, sign(refund), 'authored'));
  adv('state-suggested-with-attestation', withAtt(refund, sign(refund), 'suggested'));
  adv('attestation-unsigned', withAtt(refund, (() => { const a = { ...sign(refund) } as Record<string, unknown>; delete a.sig; return a as unknown as ReviewRef; })()));
  adv('attestation-replayed-from-another-def', withAtt(refund, sign(BUILTIN_DEFS.find((d) => d.verb === 'stripe.charge')!)));
  const key = (over: Partial<PinnedKey>): PinnedKey => ({ kid: TEST_REVIEWER.kid, pk: pk(TEST_REVIEWER.secret), roles: ['reviewer'], ...over });
  adv('key-pinned-as-importer-only', withAtt(refund, sign(refund)), { keys: [key({ roles: ['importer'] })] });
  adv('key-pinned-as-reviewer-and-importer', withAtt(refund, sign(refund)), { keys: [key({ roles: ['reviewer', 'importer'] })] });
  adv('key-material-also-pinned-as-model-key', withAtt(refund, sign(refund)), { keys: [key({}), { kid: 'm', pk: pk(TEST_REVIEWER.secret), roles: ['model'] }] });
  adv('key-not-yet-valid', withAtt(refund, sign(refund)), { keys: [key({ not_before: TEST_TS + 1 })] });
  adv('key-expired', withAtt(refund, sign(refund)), { keys: [key({ not_after: TEST_TS - 1 })] });
  adv('key-valid-window-ok', withAtt(refund, sign(refund)), { keys: [key({ not_before: TEST_TS, not_after: TEST_TS })] });
  adv('pins-duplicate-kid', withAtt(refund, sign(refund)), { keys: [key({}), key({})] });
  adv('pins-bad-key-length', withAtt(refund, sign(refund)), { keys: [key({ pk: 'AAAA' })] });
  adv('previous-registry-digest-accepted', withAtt(refund, sign(refund, { traits_digest: 'P'.repeat(43) })), { keys: TEST_PINS.keys, traits_digests: ['P'.repeat(43)] });
  adv('second-reviewer-pinned-ok', withAtt(refund, sign(refund, { reviewer_kid: 'rev-2' }, OTHER)), { keys: [...TEST_PINS.keys, { kid: 'rev-2', pk: pk(OTHER), roles: ['reviewer'] }] });

  // ---- schema verbs: an unconfirmed verb must carry EVERY trait --------------------------------------------------------------------------
  const top = topTraits(CORE_REGISTRY);
  const verbOf = (d: ActionDef, opts = {}): Record<string, any> => clone(toSchemaVerb(d, CORE_REGISTRY, opts).verb) as unknown as Record<string, any>;
  const sv = (name: string, v: Record<string, any>, pins: unknown = TEST_PINS) => mk(`schema-verb-${name}`, 'schema_verb', { verb: v, ...(pins === null ? {} : { pins }) });
  const cv = (): Record<string, any> => verbOf(confirmed(refund), testReview());
  const uv = (): Record<string, any> => verbOf(refund);
  sv('conf-ok', cv());
  sv('conf-ok-read', verbOf(confirmed(read), testReview()));
  sv('conf-no-pins', cv(), null);
  sv('conf-empty-pins', cv(), { keys: [] });
  sv('conf-confirmation-dropped', (() => { const v = cv(); delete v.confirmation; return v; })());
  sv('conf-sig-forged', (() => { const v = cv(); v.confirmation.sig = 'A'.repeat(86); return v; })());
  sv('conf-def-digest-changed', (() => { const v = cv(); v.def = 'B'.repeat(43); return v; })());
  sv('conf-traits-digest-changed', (() => { const v = cv(); v.confirmation.traits_digest = 'C'.repeat(43); return v; })());
  sv('conf-final-trait-not-carried', (() => { const v = cv(); v.traits = v.traits.filter((t: string) => t !== 'pca.money_moving'); return v; })());
  sv('conf-extra-trait-is-fine', (() => { const v = cv(); v.traits = [...v.traits, 'pca.bulk'].sort(); v.floors = { ...floorOf(CORE_REGISTRY, v.traits) }; return v; })());
  // the confirmation signs the digest of the verb's own facts: any edit of what the verb says, or a claimed digest of another definition, is unconfirmed
  const edited = (name: string, f: (v: Record<string, any>) => void) => sv(`conf-facts-edited-${name}`, (() => { const v = cv(); f(v); return v; })());
  edited('param-max-raised', (v) => { v.params['action.params.amount'].max = 999_999_999_999; });
  edited('param-min-lowered', (v) => { v.params['action.params.amount'].min = 0; });
  edited('param-added', (v) => { v.params['action.params.note'] = { type: 'string', semantic: 'generic.string', sensitivity: 'free', max_len: 10 }; });
  edited('param-removed', (v) => { delete v.params['action.params.charge']; });
  edited('param-role-changed', (v) => { v.params['action.params.charge'].role = 'id.stripe.customer'; });
  edited('description-changed', (v) => { v.description = 'Harmless lookup.'; });
  edited('reversibility-changed', (v) => { v.reversibility = 'reversible'; });
  edited('effects-changed', (v) => { v.effects = ['pay', 'update']; });
  edited('verb-renamed', (v) => { v.verb = 'stripe.refund_all'; });
  edited('mcp-binding-added', (v) => { v.mcp = { tool: 'refund_everything' }; });
  sv('conf-facts-digest-claimed-facts-differ', (() => { const v = verbOf(BUILTIN_DEFS.find((d) => d.verb === 'stripe.charge')!); const c = cv(); v.def = c.def; v.confirmation = c.confirmation; v.traits = c.traits; v.floors = c.floors; return v; })());
  sv('conf-facts-digest-replaced-sig-stale', (() => { const v = cv(); v.params['action.params.amount'].max = 5; v.confirmation.facts_digest = factsDigest(v); return v; })());
  sv('conf-facts-unchanged-traits-floors-ignored', (() => { const v = cv(); v.traits = [...v.traits, 'pca.bulk'].sort(); v.floors = { ...floorOf(CORE_REGISTRY, v.traits) }; return v; })());
  sv('conf-unpinned-key', cv(), { keys: [{ kid: 'someone', pk: pk(OTHER), roles: ['reviewer'] }] });
  sv('conf-wrong-role', cv(), { keys: [key({ roles: ['publisher'] })] });
  sv('conf-lifted-from-another-verb', (() => { const v = verbOf(refund); const o = verbOf(confirmed(BUILTIN_DEFS.find((d) => d.verb === 'stripe.charge')!), testReview()); v.confirmation = o.confirmation; v.traits = cv().traits; v.floors = cv().floors; return v; })());
  sv('unconf-top-ok', uv());
  sv('unconf-top-ok-no-pins', uv(), null);
  sv('unconf-low-machine-traits', (() => { const v = uv(); v.traits = ['pca.irreversible', 'pca.money_moving']; v.floors = { ...floorOf(CORE_REGISTRY, v.traits) }; return v; })());
  sv('unconf-low-traits-with-top-floors', (() => { const v = uv(); v.traits = ['pca.irreversible', 'pca.money_moving']; return v; })());
  sv('unconf-empty-traits', (() => { const v = uv(); v.traits = []; return v; })());
  sv('unconf-top-but-floors-lowered', (() => { const v = uv(); v.floors = { ...v.floors, esc: 1 }; return v; })());
  for (const t of ['pca.unreviewed', 'pca.code_execution', 'pca.credential_access', 'pca.privilege_change', 'pca.public_exposure', 'pca.bulk', 'pca.financial_data_read']) {
    sv(`unconf-missing-${t.slice(4)}`, (() => { const v = uv(); v.traits = v.traits.filter((x: string) => x !== t); return v; })());
  }
  void top;

  // ---- documents and decisions through rule 22 ---------------------------------------------------------------------------------------------
  const meta = { site: 'https://pay.example', aud: 'pay', version: '1' };
  const docU = toSchemaDoc([refund], CORE_REGISTRY, meta) as unknown as Record<string, any>;
  const docC = toSchemaDoc([confirmed(refund)], CORE_REGISTRY, meta, testReview()) as unknown as Record<string, any>;
  const fl = (d: Record<string, any>) => d.verbs[0].floors;
  const grantFor = (f: any, over: Record<string, any> = {}) => ({ caveats: f.caveats, max_esc: 3, preauth_esc: f.esc, ...over });
  const r22 = (name: string, doc: Record<string, any>, grant: any, context: string[], pins: unknown = TEST_PINS) => mk(`rule22-${name}`, 'rule22', { doc, verb: 'stripe.refund', grant, context, ...(pins === null ? {} : { pins }) });
  r22('conf-allow', docC, grantFor(fl(docC)), fl(docC).context);
  r22('conf-without-pins-denied', docC, grantFor(fl(docC)), fl(docC).context, null);
  r22('unconf-with-reviewed-grant-escalates', docU, grantFor(fl(docC)), fl(docC).context);
  r22('unconf-with-top-grant-allows', docU, grantFor(fl(docU)), fl(docU).context);
  r22('unconf-with-top-grant-but-low-max-esc-denies', docU, grantFor(fl(docU), { max_esc: 2 }), fl(docU).context);
  r22('unconf-claiming-reviewed-traits-denied', (() => { const d = clone(docC); delete d.verbs[0].confirmation; return d; })(), grantFor(fl(docC)), fl(docC).context);
  r22('unconf-claiming-reviewed-floors-denied', (() => { const d = clone(docU); d.verbs[0].floors = clone(fl(docC)); return d; })(), grantFor(fl(docC)), fl(docC).context);
  r22('unconf-claiming-reviewed-traits-and-floors-denied', (() => { const d = clone(docU); d.verbs[0].traits = clone(docC.verbs[0].traits); d.verbs[0].floors = clone(fl(docC)); return d; })(), grantFor(fl(docC)), fl(docC).context);
  const rs = (name: string, doc: Record<string, any>, pins: unknown = TEST_PINS) => mk(`rule22-schema-${name}`, 'rule22_schema', { doc, ...(pins === null ? {} : { pins }) });
  rs('conf-ok', docC);
  rs('conf-no-pins', docC, null);
  rs('unconf-top-ok', docU);
  rs('mixed-two-verbs', toSchemaDoc([confirmed(refund), read], CORE_REGISTRY, meta, testReview()) as unknown as Record<string, any>);
  rs('mixed-second-verb-low-traits', (() => { const d = toSchemaDoc([confirmed(refund), read], CORE_REGISTRY, meta, testReview()) as unknown as Record<string, any>; const i = d.verbs.findIndex((v: any) => v.verb === read.verb); d.verbs[i].traits = d.verbs[i].traits.filter((t: string) => t === 'pca.network_egress'); return d; })());
  // a custom trait is part of the top
  const custom = { id: 'acme.strict', implies: ['pca.money_moving'], floor: profile({ ...CORE_REGISTRY.traits.get('pca.money_moving')!.floor, esc: 3 }), card_phrase: 'is stricter than money movement' };
  const docX = toSchemaDoc([refund], extendRegistry(CORE_REGISTRY, [custom]), meta) as unknown as Record<string, any>;
  rs('unconf-custom-trait-in-top', docX);
  rs('unconf-custom-trait-dropped', (() => { const d = clone(docX); d.verbs[0].traits = d.verbs[0].traits.filter((t: string) => t !== 'acme.strict'); return d; })());
  // ---- schema shape: the `confirmation` member of a v2 verb (ok / not ok; natives report the boolean) ---------------------------------
  const sh = (name: string, f: (d: Record<string, any>) => void) => { const d = clone(docC); f(d); mk(`schema-shape-conf-${name}`, 'schema_shape', { doc: d }); };
  sh('valid', () => undefined);
  sh('absent', (d) => { delete d.verbs[0].confirmation; });
  sh('not-an-object', (d) => { d.verbs[0].confirmation = 'x'; });
  sh('array', (d) => { d.verbs[0].confirmation = []; });
  sh('unknown-member', (d) => { d.verbs[0].confirmation.extra = 1; });
  sh('missing-member', (d) => { delete d.verbs[0].confirmation.sig; });
  sh('def-digest-not-base64url', (d) => { d.verbs[0].confirmation.def_digest = 'not a digest'; });
  sh('facts-digest-short', (d) => { d.verbs[0].confirmation.facts_digest = 'AAAA'; });
  sh('facts-digest-missing', (d) => { delete d.verbs[0].confirmation.facts_digest; });
  sh('traits-digest-short', (d) => { d.verbs[0].confirmation.traits_digest = 'AAAA'; });
  sh('sig-wrong-length', (d) => { d.verbs[0].confirmation.sig = 'A'.repeat(43); });
  sh('final-traits-unsorted', (d) => { d.verbs[0].confirmation.final_traits = ['pca.money_moving', 'pca.irreversible']; });
  sh('final-traits-duplicate', (d) => { d.verbs[0].confirmation.final_traits = ['pca.irreversible', 'pca.irreversible']; });
  sh('final-traits-not-ids', (d) => { d.verbs[0].confirmation.final_traits = ['Not A Trait']; });
  sh('dismissed-not-array', (d) => { d.verbs[0].confirmation.dismissed = {}; });
  sh('dismissed-entry-extra-member', (d) => { d.verbs[0].confirmation.dismissed = [{ trait: 'pca.bulk', reason: 'r', x: 1 }]; });
  sh('dismissed-reason-empty', (d) => { d.verbs[0].confirmation.dismissed = [{ trait: 'pca.bulk', reason: '' }]; });
  sh('dismissed-ok', (d) => { d.verbs[0].confirmation.dismissed = [{ trait: 'pca.bulk', reason: 'not bulk: one item' }]; });
  sh('kid-empty', (d) => { d.verbs[0].confirmation.reviewer_kid = ''; });
  sh('ts-negative', (d) => { d.verbs[0].confirmation.ts = -1; });
  sh('ts-float', (d) => { d.verbs[0].confirmation.ts = 1.5; });
  sh('ts-string', (d) => { d.verbs[0].confirmation.ts = '1'; });
  sh('on-v1-document', (d) => { d.v = 1; });
  void normalize;
  void generateKeyPair;
  return cases as Case[];
}
