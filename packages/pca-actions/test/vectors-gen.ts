// vectors-gen.ts - deterministic generator and reference replay for the shared action-kit conformance vectors
// (packages/pca-conformance/vectors/actions/*.json). One JSON per case: {id, kind, input, expect}. The reference replay is
// the TypeScript implementation; every native must reproduce `expect` exactly (digests byte for byte).
import { actionSchemaShapeError, conformAction, type ActionVerbDecl } from '@atlasauth/pca/ext/intent';
import {
  BUILTIN_DEFS, CAVEAT_KINDS, CONTEXT_KEYS, CORE_REGISTRY, CORE_TRAIT_IDS, EFFECTS, REVERSIBILITY, defDigest, effective, extendRegistry, floorDecision, floorOf, closure, normalize, packProof, packRoot,
  profile, schemaVerbFloorError, toSchemaVerb, validateDef, type ActionDef, type CaveatKind, type ParamDef, type Profile, type TraitDef,
} from '../src';

import { REGISTRY_KINDS, registryCases, replayRegistry } from './vectors-registry';
import { confirmationCases } from './vectors-confirm';
import { APPROVAL_KINDS, APPROVAL_PROFILE_KINDS, approvalCases, approvalProfileCases, replayApproval } from './vectors-approval';
import { attestationVerifier, type ReviewerPins } from '../src';

export interface VectorCase { id: string; kind: string; input: unknown; expect: unknown }

// ---- seeded randomness (mulberry32) ----------------------------------------------------------------------------------------
export function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (lo: number, hi: number) => lo + Math.floor(next() * (hi - lo + 1));
  const pick = <T>(xs: readonly T[]): T => xs[int(0, xs.length - 1)]!;
  const sub = <T>(xs: readonly T[], max = xs.length): T[] => xs.filter(() => next() < 0.35).slice(0, max);
  return { next, int, pick, sub };
}
export type R = ReturnType<typeof rng>;

function genParam(r: R): ParamDef {
  switch (r.int(0, 5)) {
    case 0: return { type: 'integer', min: 0, max: r.pick([100, 10_000, 1_000_000]), ...(r.next() < 0.5 ? { role: 'money.amount', unit: { kind: 'money', ccy: r.pick(['USD', 'EUR', 'JPY']), exp: r.pick([0, 2]) } } as Partial<ParamDef> : {}) };
    case 1: return { type: 'string', max_len: r.pick([16, 256, 4096]), role: r.pick(['contact.email', 'party.payee', 'text.message', 'path.fs', 'credential.secret']), ...(r.next() < 0.5 ? { tags: r.sub(['pii', 'secret', 'free_text_outbound', 'phi'] as const) } : {}) };
    case 2: return { type: 'array', items: 'string', ...(r.next() < 0.6 ? { max_items: r.pick([4, 16, 64]) } : {}) };
    case 3: return { type: 'boolean', required: r.next() < 0.5 };
    case 4: return { type: 'string', values: r.sub(['a', 'b', 'c', 'd'], 4).concat(['z']), sensitivity: r.pick(['free', 'material', 'critical']) };
    default: return { type: 'datetime' };
  }
}

export function genDef(r: R, n: number): ActionDef {
  const params: Record<string, ParamDef> = {};
  const count = r.int(0, 4);
  for (let i = 0; i < count; i++) {
    const p = genParam(r);
    // keep the unit/role pairing legal: a string with credential/contact roles only
    params[`p${i}`] = p;
  }
  const effects = r.sub(EFFECTS);
  if (effects.length === 0) effects.push(r.pick(EFFECTS));
  const d: Record<string, unknown> = {
    v: 1, kind: 'pca-action-def', verb: `gen${n}.item.act${r.int(0, 9)}`, title: `Generated action ${n}`, effects,
    resource: { type: 'gen.item', id: r.pick<unknown>(['*', { exact: 'only' }, { prefix: 'g_', class: r.pick(['alnum', 'hex', 'slug', 'any_safe']), len: [4, r.pick([8, 32])] }]), scope: r.pick(['one', 'set', 'tenant', 'global']) },
    params,
    review: { state: r.pick(['authored', 'unreviewed', 'suggested', 'confirmed']) },
  };
  if (r.next() < 0.5) d.reversibility = r.pick(REVERSIBILITY);
  if (r.next() < 0.4) d.blast = { radius: r.pick(['one', 'bounded', 'tenant', 'global']), ...(r.next() < 0.5 ? { ppm: r.int(0, 1_000_000) } : {}) };
  if (r.next() < 0.4) d.context = r.sub(CONTEXT_KEYS, 3);
  if (r.next() < 0.5) d.traits = r.sub(CORE_TRAIT_IDS, 3);
  if (r.next() < 0.3) d.aliases = [`alias_${n}`, `other_${n}`];
  return d as unknown as ActionDef;
}

function genProfile(r: R): Profile {
  return profile({ risk: r.int(0, 3), rev: r.pick(REVERSIBILITY), blast_ppm: r.pick([0, 50_000, 300_000, 700_000, 1_000_000, r.int(0, 1_000_000)]), esc: r.int(0, 3), caveats: r.sub(CAVEAT_KINDS), context: r.sub(CONTEXT_KEYS), prules: [] });
}

// ---- the reference replay ---------------------------------------------------------------------------------------------------
const codeOf = (e: string | null): { ok: boolean; code?: string } => (e === null ? { ok: true } : { ok: false, code: e.split(':')[0]!.split(' ')[0]! });

export function replay(c: VectorCase): unknown {
  const i = c.input as Record<string, any>;
  switch (c.kind) {
    case 'parse': return { ok: validateDef(i.def) === null };
    case 'digest': return { digest: defDigest(i.def), normalized: normalize(i.def) };
    case 'effective': {
      // `pins` = the verifier's pinned reviewer keys; without them (or without a valid signed confirmation) the def is UNCONFIRMED
      const o = i.pins ? { attestationVerified: attestationVerifier({ pins: i.pins as ReviewerPins, registry: CORE_REGISTRY }) } : {};
      const e = effective(i.def, CORE_REGISTRY, o);
      return { confirmed: e.confirmed, traits: e.traits, closure: e.closure, eff: e.eff };
    }
    case 'expand': {
      try {
        const reg = i.custom_traits ? extendRegistry(CORE_REGISTRY, i.custom_traits as TraitDef[]) : CORE_REGISTRY;
        return { closure: closure(reg, i.traits), floor: floorOf(reg, i.traits) };
      } catch { return { error: true }; }
    }
    case 'floor': return { decision: floorDecision(i.grant, i.call, i.profile) };
    case 'conform': { const r = conformAction(i.schema, i.verb, i.params); return r.ok ? { ok: true } : { ok: false, code: r.code }; }
    case 'pack': { const ds = i.digests as string[]; return { root: packRoot(ds), proof: packProof(ds, ds[i.index]!) }; }
    case 'schema_verb': {
      try {
        const reg = i.custom_traits ? extendRegistry(CORE_REGISTRY, i.custom_traits as TraitDef[]) : CORE_REGISTRY;
        return codeOf(schemaVerbFloorError(i.verb as ActionVerbDecl, reg, i.pins as ReviewerPins | undefined));
      } catch { return { error: true }; }
    }
    case 'schema_shape': return { ok: actionSchemaShapeError(i.doc, { signed: false }) === null };
    default:
      if (REGISTRY_KINDS.includes(c.kind)) return replayRegistry(c);
      if (APPROVAL_KINDS.includes(c.kind) || APPROVAL_PROFILE_KINDS.includes(c.kind)) return replayApproval(c);
      throw new Error(`unknown vector kind ${c.kind}`);
  }
}

const mk = (id: string, kind: string, input: unknown): VectorCase => ({ id, kind, input, expect: undefined as unknown });
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const pad = (n: number) => String(n).padStart(3, '0');

export function generate(): VectorCase[] {
  const cases: VectorCase[] = [];
  const r = rng(0xac7101);
  // generated, valid defs: digest / parse / effective
  const defs: ActionDef[] = [];
  while (defs.length < 60) {
    const d = genDef(r, defs.length);
    if (validateDef(d) === null) defs.push(d);
  }
  defs.forEach((d, i) => { cases.push(mk(`digest-gen-${pad(i)}`, 'digest', { def: d })); });
  defs.slice(0, 40).forEach((d, i) => { cases.push(mk(`effective-gen-${pad(i)}`, 'effective', { def: d })); });
  BUILTIN_DEFS.forEach((d, i) => { cases.push(mk(`digest-builtin-${pad(i)}`, 'digest', { def: d })); cases.push(mk(`effective-builtin-${pad(i)}`, 'effective', { def: d })); });
  // parse: valid defs and single mutations (some valid, most not)
  defs.slice(0, 30).forEach((d, i) => cases.push(mk(`parse-gen-${pad(i)}`, 'parse', { def: d })));
  for (let i = 0; i < 40; i++) {
    const d = clone(defs[i % defs.length]!) as unknown as Record<string, any>;
    switch (i % 8) {
      case 0: d.unknown_member = 1; break;
      case 1: d.verb = 'Bad'; break;
      case 2: d.effects = []; break;
      case 3: d.title = ''; break;
      case 4: d.resource.scope = 'galaxy'; break;
      case 5: d.params.zz = { type: 'integer', min: 5, max: 1 }; break;
      case 6: d.review = { state: 'nope' }; break;
      default: d.reversibility = 'sometimes';
    }
    cases.push(mk(`parse-mut-${pad(i)}`, 'parse', { def: d }));
  }
  // expand: random core subsets, and subsets with generated custom traits
  for (let i = 0; i < 40; i++) cases.push(mk(`expand-gen-${pad(i)}`, 'expand', { traits: r.sub(CORE_TRAIT_IDS, 6) }));
  for (let i = 0; i < 20; i++) {
    const base = r.sub(CORE_TRAIT_IDS, 2);
    const f = floorOf(CORE_REGISTRY, base);
    const custom: TraitDef = { id: `acme.t${i}`, implies: base, floor: profile({ ...f, risk: Math.min(3, f.risk + r.int(0, 1)), esc: Math.min(3, f.esc + r.int(0, 1)), caveats: [...f.caveats, ...r.sub(CAVEAT_KINDS, 2)] as CaveatKind[] }), card_phrase: `custom ${i}` };
    cases.push(mk(`expand-custom-${pad(i)}`, 'expand', { custom_traits: [custom], traits: [custom.id, ...r.sub(CORE_TRAIT_IDS, 2)] }));
  }
  // floor decisions
  for (let i = 0; i < 60; i++) cases.push(mk(`floor-gen-${pad(i)}`, 'floor', { grant: { caveats: r.sub(CAVEAT_KINDS), max_esc: r.int(0, 3), preauth_esc: r.int(0, 3) }, call: { context: r.sub(CONTEXT_KEYS) }, profile: genProfile(r) }));
  // conform against derived schema verbs
  const verbs = defs.slice(0, 20).map((d) => toSchemaVerb(d, CORE_REGISTRY).verb);
  verbs.forEach((v, i) => {
    const d = defs[i]!;
    const params: Record<string, unknown> = {};
    for (const [name, p] of Object.entries(normalize(d).params)) {
      if (!p.required && r.next() < 0.5) continue;
      params[name] = p.type === 'integer' ? r.int(p.min ?? 0, Math.min(p.max ?? 10, 1000)) : p.type === 'boolean' ? r.next() < 0.5 : p.type === 'array' ? ['x'] : p.type === 'datetime' ? '2026-10-26T10:00:00Z' : p.values ? p.values[0] : p.role === 'contact.email' ? 'a@b.com' : 'v';
    }
    const m = clone(params) as Record<string, unknown>;
    const keys = Object.keys(m);
    if (i % 3 === 1 && keys.length) m[keys[0]!] = { not: 'a scalar' };
    if (i % 3 === 2) m['undeclared_x'] = 1;
    cases.push(mk(`conform-gen-${pad(i)}`, 'conform', { schema: { verbs: [v] }, verb: d.verb, params: i % 3 === 0 ? params : m }));
  });
  // packs
  for (let i = 0; i < 12; i++) {
    const n = r.int(1, 17);
    const digests = Array.from({ length: n }, (_, k) => defDigest(genDef(rng(9000 + i * 100 + k), 500 + i * 100 + k)));
    const uniq = [...new Set(digests)];
    cases.push(mk(`pack-gen-${pad(i)}`, 'pack', { digests: uniq, index: r.int(0, uniq.length - 1) }));
  }
  cases.push(mk('pack-builtin', 'pack', { digests: BUILTIN_DEFS.map(defDigest), index: 7 }));
  // schema_verb (rule 22 integrity) from derived verbs, honest
  verbs.slice(0, 10).forEach((v, i) => cases.push(mk(`schema-verb-ok-${pad(i)}`, 'schema_verb', { verb: v })));

  // ---- adversarial, hand written ------------------------------------------------------------------------------------------
  const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
  const bad = (name: string, f: (d: Record<string, any>) => void) => { const d = clone(refund) as unknown as Record<string, any>; f(d); cases.push(mk(`parse-adv-${name}`, 'parse', { def: d })); };
  bad('unknown-member', (d) => { d.world = []; });
  bad('float-default', (d) => { d.params.amount.default = 0.5; });
  bad('huge-exponent-number', (d) => { d.params.amount.default = 1e30; });
  bad('lone-surrogate', (d) => { d.title = 'x\ud800'; });
  bad('not-nfc', (d) => { d.title = 'é'; });
  bad('param-depth-4', (d) => { d.params['a.b.c.d'] = { type: 'boolean' }; });
  bad('param-parent-and-leaf', (d) => { d.params.x = { type: 'boolean' }; d.params['x.y'] = { type: 'boolean' }; });
  bad('huge-param-count', (d) => { for (let i = 0; i < 70; i++) d.params[`q${i}`] = { type: 'boolean' }; });
  bad('proto-param', (d) => { d.params.constructor = { type: 'boolean' }; });
  bad('uuid-with-prefix', (d) => { d.resource.id = { prefix: 'x', class: 'uuid', len: [36, 36] }; });
  bad('role-money-on-string', (d) => { d.params.charge.role = 'money.amount'; });
  bad('idempotency-param-missing', (d) => { d.idempotency.param = 'nope'; });
  bad('ccy-ref-missing', (d) => { d.params.amount.unit = { kind: 'money', ccy: { from: 'nope' }, exp: 2 }; });
  cases.push(mk('digest-adv-key-order-and-defaults', 'digest', { def: { review: { state: 'authored' }, params: refund.params, effects: ['pay'], resource: refund.resource, title: refund.title, verb: refund.verb, kind: 'pca-action-def', v: 1, reversibility: 'irreversible', idempotency: refund.idempotency, aliases: [...(refund.aliases ?? [])].reverse() } }));
  cases.push(mk('digest-adv-review-excluded', 'digest', { def: { ...clone(refund), review: { state: 'unreviewed' }, since: '9.9.9', examples: [{ params: {}, expect: 'deny' }] } }));
  const mkT = (id: string, implies: string[], f: Partial<Profile>): TraitDef => ({ id, implies, floor: profile(f), card_phrase: id });
  const mm = CORE_REGISTRY.traits.get('pca.money_moving')!;
  const ex = (name: string, custom: TraitDef[] | undefined, traits: string[]) => cases.push(mk(`expand-adv-${name}`, 'expand', { ...(custom ? { custom_traits: custom } : {}), traits }));
  ex('unknown-trait', undefined, ['pca.nope']);
  ex('duplicates-and-order', undefined, ['pca.money_moving', 'pca.bulk', 'pca.money_moving', 'pca.destructive']);
  ex('impersonation-implies-communication', undefined, ['pca.impersonation']);
  ex('custom-weakening', [mkT('acme.weak', ['pca.money_moving'], { risk: 1 })], ['acme.weak']);
  ex('custom-extends', [mkT('acme.strong', ['pca.money_moving'], { ...mm.floor, esc: 3 })], ['acme.strong']);
  ex('custom-reuses-pca', [mkT('pca.money_moving', [], {})], ['pca.money_moving']);
  ex('custom-pca-new', [mkT('pca.fresh', [], {})], ['pca.fresh']);
  ex('custom-cycle', [mkT('acme.a', ['acme.b'], {}), mkT('acme.b', ['acme.a'], {})], ['acme.a']);
  ex('custom-unknown-implies', [mkT('acme.a', ['acme.zzz'], {})], ['acme.a']);
  ex('custom-duplicate', [mkT('acme.a', [], {}), mkT('acme.a', [], {})], ['acme.a']);
  ex('custom-depth-9', Array.from({ length: 9 }, (_, i) => mkT(`acme.c${i}`, i < 8 ? [`acme.c${i + 1}`] : [], {})), ['acme.c0']);
  ex('custom-depth-8', Array.from({ length: 8 }, (_, i) => mkT(`acme.c${i}`, i < 7 ? [`acme.c${i + 1}`] : [], {})), ['acme.c0']);
  ex('empty', undefined, []);
  const g = (name: string, grant: any, call: any, prof: Profile) => cases.push(mk(`floor-adv-${name}`, 'floor', { grant, call, profile: prof }));
  const need = profile({ risk: 3, rev: 'rate_limited', blast_ppm: 700_000, esc: 2, caveats: ['amount_cap', 'count_cap', 'window'], context: ['idempotency'] });
  g('exact-grant', { caveats: ['amount_cap', 'count_cap', 'window'], max_esc: 3, preauth_esc: 2 }, { context: ['idempotency'] }, need);
  g('esc-above-max', { caveats: ['amount_cap', 'count_cap', 'window'], max_esc: 1, preauth_esc: 1 }, { context: ['idempotency'] }, need);
  g('esc-above-preauth', { caveats: ['amount_cap', 'count_cap', 'window'], max_esc: 3, preauth_esc: 1 }, { context: ['idempotency'] }, need);
  g('missing-caveat', { caveats: ['amount_cap'], max_esc: 3, preauth_esc: 3 }, { context: ['idempotency'] }, need);
  g('missing-context', { caveats: ['amount_cap', 'count_cap', 'window'], max_esc: 3, preauth_esc: 3 }, { context: [] }, need);
  g('bottom', { caveats: [], max_esc: 0, preauth_esc: 0 }, { context: [] }, profile());
  const sv = (name: string, f: (v: Record<string, any>) => void) => { const v = clone(toSchemaVerb(refund, CORE_REGISTRY).verb) as unknown as Record<string, any>; f(v); cases.push(mk(`schema-verb-adv-${name}`, 'schema_verb', { verb: v })); };
  sv('honest', () => undefined);
  sv('esc-lowered', (v) => { v.floors.esc = 0; });
  sv('blast-lowered', (v) => { v.floors.blast_ppm = 0; });
  sv('caveat-dropped', (v) => { v.floors.caveats = ['amount_cap']; });
  sv('rev-lowered', (v) => { v.floors.rev = 'reversible'; });
  sv('implied-trait-dropped', (v) => { v.traits = v.traits.filter((t: string) => t !== 'pca.money_moving'); });
  sv('unknown-trait', (v) => { v.traits = [...v.traits, 'pca.zzz']; });
  sv('v1-verb', (v) => { delete v.floors; delete v.traits; });
  // conform adversarial
  const cv = toSchemaVerb(refund, CORE_REGISTRY).verb;
  const cf = (name: string, params: unknown) => cases.push(mk(`conform-adv-${name}`, 'conform', { schema: { verbs: [cv] }, verb: 'stripe.refund', params }));
  cf('ok', { amount: 100, charge: 'ch_12345678', idempotency_key: 'k' });
  cf('float-amount', { amount: 1.5, charge: 'ch_12345678', idempotency_key: 'k' });
  cf('below-min', { amount: 0, charge: 'ch_12345678', idempotency_key: 'k' });
  cf('missing-key', { amount: 100, charge: 'ch_12345678' });
  cf('extra', { amount: 100, charge: 'ch_12345678', idempotency_key: 'k', x: 1 });
  cf('params-array', [1]);
  // v2 value domains (A7): every string format, datetime, duration, object_ref and a dotted parameter, good and bad values.
  // The schema is hand-written (conformAction does not validate the document shape); the replay is the TypeScript reference.
  const fmt = (name: string, decl: Record<string, unknown>, value: unknown) => {
    const verbDecl = { verb: 'fmt.item.check', kind: 'write', params: { 'action.params.x': { semantic: 'generic.string', sensitivity: 'free', ...decl } }, effects: ['update'] };
    cases.push(mk(`conform-fmt-${name}`, 'conform', { schema: { verbs: [verbDecl] }, verb: 'fmt.item.check', params: { x: value } }));
  };
  const S = (format: string) => ({ type: 'string', format });
  const NBSP = String.fromCharCode(0xa0);
  const formats: [string, string, unknown][] = [
    ['email-ok', 'email', 'a.b+c@example.co.uk'], ['email-no-tld', 'email', 'a@b'], ['email-long', 'email', 'a'.repeat(65) + '@example.com'], ['email-space', 'email', 'a b@example.com'],
    ['url-ok', 'url', 'ftp://host.example/path?q=1#f'], ['url-space', 'url', 'https://a b'], ['url-nbsp', 'url', `https://a${NBSP}b`], ['url-no-scheme', 'url', '//host/x'], ['url-empty-host', 'url', 'https:///x'],
    ['https-ok', 'uri_https', 'https://example.com/a'], ['https-http', 'uri_https', 'http://example.com'], ['https-upper', 'uri_https', 'HTTPS://example.com'],
    ['uuid-ok', 'uuid', '123e4567-e89b-12d3-a456-426614174000'], ['uuid-upper', 'uuid', '123E4567-E89B-12D3-A456-426614174000'], ['uuid-short', 'uuid', '123e4567-e89b-12d3-a456-42661417400'],
    ['iban-ok', 'iban', 'GB82WEST12345698765432'], ['iban-checksum', 'iban', 'GB82WEST12345698765433'], ['iban-lower', 'iban', 'gb82west12345698765432'], ['iban-de', 'iban', 'DE89370400440532013000'],
    ['phone-ok', 'phone_e164', '+14155552671'], ['phone-no-plus', 'phone_e164', '14155552671'], ['phone-leading-zero', 'phone_e164', '+0155552671'], ['phone-short', 'phone_e164', '+12345'],
    ['cidr4-ok', 'cidr', '10.0.0.0/8'], ['cidr4-octet', 'cidr', '256.0.0.0/8'], ['cidr4-prefix', 'cidr', '10.0.0.0/33'], ['cidr4-leading-zero', 'cidr', '01.2.3.4/8'], ['cidr4-prefix-zero', 'cidr', '10.0.0.0/08'],
    ['cidr6-ok', 'cidr', '2001:db8::/32'], ['cidr6-prefix', 'cidr', '2001:db8::/129'], ['cidr6-colons', 'cidr', '2001:::/32'], ['cidr-bare', 'cidr', '10.0.0.0'],
    ['country-ok', 'iso_country', 'DE'], ['country-lower', 'iso_country', 'de'], ['country-three', 'iso_country', 'DEU'],
    ['currency-ok', 'iso_currency', 'EUR'], ['currency-lower', 'iso_currency', 'eur'], ['currency-two', 'iso_currency', 'EU'],
    ['semver-ok', 'semver', '1.2.3-rc.1+build.5'], ['semver-leading-zero', 'semver', '01.2.3'], ['semver-short', 'semver', '1.2'], ['semver-arabic-digit', 'semver', '\u0663.0.0'],
    ['sha256-ok', 'sha256', 'a'.repeat(64)], ['sha256-upper', 'sha256', 'A'.repeat(64)], ['sha256-short', 'sha256', 'a'.repeat(63)],
    ['id-ok', 'id:stripe.charge', 'ch_12345678'], ['id-bad-char', 'id:stripe.charge', 'ch 1'], ['id-empty', 'id:stripe.charge', ''], ['id-long', 'id:stripe.charge', 'a'.repeat(129)],
    ['unknown', 'nope', 'x'],
  ];
  for (const [n, f, v] of formats) fmt(n, S(f), v);
  const NUM = (type: string, extra: Record<string, unknown> = {}) => ({ type, ...extra });
  fmt('datetime-ok', NUM('datetime'), '2026-10-26T12:30:45Z'); fmt('datetime-millis', NUM('datetime'), '2026-10-26T12:30:45.123Z');
  fmt('datetime-no-z', NUM('datetime'), '2026-10-26T12:30:45'); fmt('datetime-offset', NUM('datetime'), '2026-10-26T12:30:45+00:00'); fmt('datetime-feb30', NUM('datetime'), '2026-02-30T00:00:00Z');
  fmt('datetime-hour24', NUM('datetime'), '2026-10-26T24:00:00Z'); fmt('datetime-leap-ok', NUM('datetime'), '2028-02-29T00:00:00Z'); fmt('datetime-nonleap', NUM('datetime'), '2027-02-29T00:00:00Z');
  fmt('datetime-number', NUM('datetime'), 5); fmt('datetime-four-fraction', NUM('datetime'), '2026-10-26T12:30:45.1234Z');
  fmt('duration-ok', NUM('duration', { min: 1, max: 100 }), 50); fmt('duration-negative', NUM('duration'), -1); fmt('duration-below-min', NUM('duration', { min: 10 }), 5);
  fmt('duration-above-max', NUM('duration', { max: 10 }), 11); fmt('duration-float', NUM('duration'), 1.5); fmt('duration-string', NUM('duration'), '5');
  fmt('ref-ok', NUM('object_ref', { max_len: 16, format: 'id:crm.contact' }), 'c_1'); fmt('ref-empty', NUM('object_ref'), ''); fmt('ref-too-long', NUM('object_ref', { max_len: 4 }), 'abcde');
  fmt('ref-number', NUM('object_ref'), 7); fmt('ref-bad-format', NUM('object_ref', { format: 'id:crm.contact' }), 'a b');
  fmt('string-values-then-format', { type: 'string', values: ['a@b.co'], format: 'email' }, 'x@y.co');
  fmt('unknown-type', NUM('timestamp'), 1);
  cases.push(...confirmationCases(defs));
  cases.push(...registryCases());
  cases.push(...approvalCases());
  return cases.map((c) => ({ ...c, expect: replay(c) }));
}

/** The approval profile vectors (packages/pca-conformance/vectors/approval-profiles): PSD2 linking and the batch commitment. */
export function generateProfiles(): VectorCase[] {
  return approvalProfileCases().map((c) => ({ ...c, expect: replay(c) }));
}
