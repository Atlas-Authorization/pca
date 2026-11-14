// test-runner.ts - `pca actions test` (spec section 6.3): run every def's executable examples through the real pipeline in
// process (derive the schema, conform the params, expand the floors, decide), plus the generic property checks of the pack:
// T2 monotonicity over trait additions and subsets, digest stability across the YAML/JSON forms, and the schema round trip
// (the example conforms; every mutation of it is refused).
//
// The example policy (`under`) is a small allow selector evaluated here: {allow: {trait|verb, where?, caveats?, context?}}.
// It stands in for the Goal compiler (policy integration, track A5) and is deliberately weaker: it can only pre-authorize.

import { stringify } from 'yaml';
import { conformAction } from '@atlasauth/pca/ext/intent';
import { CAVEAT_KINDS, type ActionDef, type CaveatKind, type ParamDef } from './def';
import { CORE_TRAIT_IDS } from './core-traits';
import { flattenParams, operationOf, toSchemaDoc } from './derive';
import { defDigest } from './digest';
import { effWithTrait, effective, type Effective } from './effective';
import { loadActionsText } from './author';
import { floorDecision, floorOf, leq, type Decision, type Registry } from './traits';
/** Examples and property checks describe the action AS REVIEWED (its hint view): they are authoring tests, not enforcement. */
const hintOf = (d: ActionDef, reg: Registry): Effective => {
  const e = effective(d, reg);
  return { ...e, ...e.hint, confirmed: true };
};

export interface ExampleResult { verb: string; index: number; expect: Decision; got: Decision; ok: boolean; why: string }
export interface PropResult { verb: string; name: string; ok: boolean; detail: string }
export interface TestReport { examples: ExampleResult[]; props: PropResult[]; ok: boolean }

type Cond = string[] | { max?: number; min?: number };
interface Sel { trait?: string; verb?: string; where?: Record<string, Cond>; caveats?: CaveatKind[]; context?: string[] }

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

function parseUnder(under: unknown): Sel[] | string {
  if (under === undefined) return [];
  if (!isObj(under) || Object.keys(under).some((k) => k !== 'allow')) return "under must be {allow: selector | [selector]}";
  const list = Array.isArray(under.allow) ? under.allow : [under.allow];
  const out: Sel[] = [];
  for (const s of list) {
    if (!isObj(s) || Object.keys(s).some((k) => !['trait', 'verb', 'where', 'caveats', 'context'].includes(k))) return 'an allow selector has trait, verb, where, caveats, context';
    if ((s.trait === undefined) === (s.verb === undefined)) return 'an allow selector names exactly one of trait and verb';
    if (s.where !== undefined && !isObj(s.where)) return 'where must be an object';
    if (s.caveats !== undefined && (!Array.isArray(s.caveats) || !s.caveats.every((c) => (CAVEAT_KINDS as readonly unknown[]).includes(c)))) return 'caveats must be known caveat kinds';
    out.push(s as Sel);
  }
  return out;
}

const domainOf = (v: string): string => v.slice(v.lastIndexOf('@') + 1).toLowerCase();

/** The grant a matching allow selector stands for, or null when it does not match this call. */
function grantOf(sel: Sel, d: ActionDef, flat: Record<string, unknown>, eff: Effective): { caveats: CaveatKind[] } | null {
  if (sel.trait !== undefined && !eff.closure.includes(sel.trait.includes('.') ? sel.trait : `pca.${sel.trait}`)) return null;
  if (sel.verb !== undefined && sel.verb !== d.verb) return null;
  const caveats = new Set<CaveatKind>(sel.caveats ?? []);
  for (const [key, cond] of Object.entries(sel.where ?? {})) {
    const dom = key.endsWith('.domain');
    const name = dom ? key.slice(0, -'.domain'.length) : key;
    const pd: ParamDef | undefined = d.params[name];
    if (!pd) return null;
    const v = flat[name];
    if (v === undefined) return null;
    if (Array.isArray(cond)) {
      if (typeof v !== 'string' || !cond.includes(dom ? domainOf(v) : v)) return null;
    } else if (isObj(cond)) {
      if (typeof v !== 'number' || (cond.max !== undefined && v > cond.max) || (cond.min !== undefined && v < cond.min)) return null;
    } else return null;
    const role = pd.role ?? '';
    if (role.startsWith('contact.') || role === 'party.payee') caveats.add('recipient_scope');
    else if (role === 'money.amount') caveats.add('amount_cap');
    else if (role === 'count.limit') caveats.add('count_cap');
    else if (role.startsWith('id.')) caveats.add('resource_scope');
  }
  return { caveats: [...caveats] };
}

/** Decide one example. */
export function decideExample(d: ActionDef, ex: NonNullable<ActionDef['examples']>[number], reg: Registry, defs: readonly ActionDef[]): { got: Decision; why: string } {
  const doc = toSchemaDoc(defs, reg, { site: 'https://example.invalid', aud: 'example', version: '0' });
  const flat = flattenParams(ex.params);
  const c = conformAction(doc, d.verb, flat);
  if (!c.ok) return { got: 'deny', why: `schema_violation ${c.code}${c.path ? ` (${c.path})` : ''}` };
  const op = operationOf(d, { params: ex.params });
  if (!op.ok) return { got: 'deny', why: op.reason };
  const sels = parseUnder(ex.under);
  if (typeof sels === 'string') return { got: 'deny', why: `bad example policy: ${sels}` };
  const eff = hintOf(d, reg);
  const callCtx = new Set<string>();
  if (d.idempotency && d.idempotency.mode === 'natural') callCtx.add('idempotency');
  if (d.idempotency?.mode === 'key_param' && d.idempotency.param !== undefined && flat[d.idempotency.param] !== undefined) callCtx.add('idempotency');
  let grantCaveats: CaveatKind[] = [];
  let pre = 0;
  for (const s of sels) {
    const g = grantOf(s, d, flat, eff);
    if (!g) continue;
    pre = 3;
    grantCaveats = [...new Set([...grantCaveats, ...g.caveats])];
    for (const k of s.context ?? []) callCtx.add(k);
  }
  const got = floorDecision({ caveats: grantCaveats, max_esc: 3, preauth_esc: pre }, { context: [...callCtx] }, eff.eff);
  const why = got === 'allow' ? 'floor satisfied' : `floor needs ${[...eff.eff.caveats.filter((k) => !grantCaveats.includes(k)), ...eff.eff.context.filter((k) => !callCtx.has(k))].join(', ') || `escalation tier ${eff.eff.esc}`}`;
  return { got, why };
}

// ---- mutations of a conforming example ---------------------------------------------------------------------------------

function mutations(d: ActionDef, flat: Record<string, unknown>): { name: string; params: Record<string, unknown> }[] {
  const out: { name: string; params: Record<string, unknown> }[] = [];
  const without = (k: string): Record<string, unknown> => { const c = { ...flat }; delete c[k]; return c; };
  out.push({ name: 'extra param', params: { ...flat, zz_undeclared: 'x' } });
  for (const k of Object.keys(flat).sort()) {
    const pd = d.params[k];
    if (!pd) continue;
    if (pd.required !== false) out.push({ name: `missing ${k}`, params: without(k) });
    const v = flat[k];
    out.push({ name: `type swap ${k}`, params: { ...flat, [k]: typeof v === 'string' ? 12345 : typeof v === 'number' || typeof v === 'boolean' ? 'x' : {} } });
    if (typeof v === 'number' && pd.type === 'integer') {
      if (pd.max !== undefined) out.push({ name: `above max ${k}`, params: { ...flat, [k]: pd.max + 1 } });
      if (pd.min !== undefined) out.push({ name: `below min ${k}`, params: { ...flat, [k]: pd.min - 1 } });
    }
    if (typeof v === 'string' && pd.type === 'string') {
      if (pd.values) out.push({ name: `outside values ${k}`, params: { ...flat, [k]: 'not_a_listed_value_zz' } });
      if (pd.max_len !== undefined) out.push({ name: `too long ${k}`, params: { ...flat, [k]: 'x'.repeat(pd.max_len + 1) } });
    }
  }
  return out;
}

/** Run examples and property checks for a set of defs (one pack). `propLimit` bounds the trait subsets tried per def. */
export function runDefTests(defs: readonly ActionDef[], reg: Registry, opts: { propLimit?: number } = {}): TestReport {
  const examples: ExampleResult[] = [];
  const props: PropResult[] = [];
  const limit = opts.propLimit ?? 256;
  for (const d of defs) {
    (d.examples ?? []).forEach((ex, index) => {
      const r = decideExample(d, ex, reg, defs);
      examples.push({ verb: d.verb, index, expect: ex.expect, got: r.got, ok: r.got === ex.expect, why: r.why });
    });

    // T2: adding any core trait never lowers the effective profile
    const eff = hintOf(d, reg);
    const lowered = CORE_TRAIT_IDS.filter((t) => !leq(eff.eff, effWithTrait(d, t, reg)));
    props.push({ verb: d.verb, name: 'adding a trait never lowers the profile', ok: lowered.length === 0, detail: lowered.join(', ') });

    // T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
    const ts = eff.traits;
    let bad = 0;
    const total = Math.min(2 ** Math.min(ts.length, 20), limit);
    const top = floorOf(reg, ts);
    for (let mask = 0; mask < total; mask++) {
      const sub = ts.filter((_, i) => (mask >> i) & 1);
      if (!leq(floorOf(reg, sub), top)) bad++;
    }
    props.push({ verb: d.verb, name: 'floors are monotone over trait subsets', ok: bad === 0, detail: `${total} subsets, ${bad} violations` });

    // one digest across the JSON and YAML forms
    const want = defDigest(d);
    const viaJson = loadActionsText(JSON.stringify(d), 'json');
    const viaYaml = loadActionsText(stringify({ ns: d.verb.split('.')[0], actions: [d] }), 'yaml');
    const okJ = viaJson.errors.length === 0 && viaJson.defs[0] !== undefined && defDigest(viaJson.defs[0]) === want;
    const okY = viaYaml.errors.length === 0 && viaYaml.defs[0] !== undefined && defDigest(viaYaml.defs[0]) === want;
    props.push({ verb: d.verb, name: 'one digest across JSON and YAML forms', ok: okJ && okY, detail: okJ && okY ? '' : `json ${okJ ? 'ok' : (viaJson.errors[0]?.message ?? 'digest differs')}; yaml ${okY ? 'ok' : (viaYaml.errors[0]?.message ?? 'digest differs')}` });

    // schema round trip: each example conforms, every mutation is refused
    if ((d.examples ?? []).length === 0) {
      props.push({ verb: d.verb, name: 'schema round trip', ok: true, detail: 'skipped: no examples' });
      continue;
    }
    const doc = toSchemaDoc(defs, reg, { site: 'https://example.invalid', aud: 'example', version: '0' });
    const accepted: string[] = [];
    let tried = 0;
    for (const ex of d.examples ?? []) {
      const flat = flattenParams(ex.params);
      if (!conformAction(doc, d.verb, flat).ok) continue; // a deliberately non-conforming example is a deny example
      for (const m of mutations(d, flat)) {
        tried++;
        if (conformAction(doc, d.verb, m.params).ok) accepted.push(m.name);
      }
    }
    props.push({ verb: d.verb, name: 'schema round trip', ok: accepted.length === 0, detail: accepted.length === 0 ? `${tried} mutations refused` : `accepted: ${[...new Set(accepted)].join(', ')}` });
  }
  return { examples, props, ok: examples.every((e) => e.ok) && props.every((q) => q.ok) };
}

export function testText(r: TestReport): string {
  const lines: string[] = [];
  for (const e of r.examples) lines.push(`${e.ok ? 'PASS' : 'FAIL'}  ${e.verb} example ${e.index + 1}: expected ${e.expect}, got ${e.got} (${e.why})`);
  for (const q of r.props) lines.push(`${q.ok ? 'PASS' : 'FAIL'}  ${q.verb} ${q.name}${q.detail ? `: ${q.detail}` : ''}`);
  const f = lines.filter((l) => l.startsWith('FAIL')).length;
  lines.push(`${lines.length - f} passed, ${f} failed`);
  return lines.join('\n');
}
