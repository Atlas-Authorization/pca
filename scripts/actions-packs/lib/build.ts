// build.ts - RawOp -> ActionDef. Applies the classifier, the per-pack reviewed overrides, parameter roles/tags/formats,
// and repairs only what can be repaired honestly (bounds the model requires). Anything else is skipped and counted.
import { CORE_REGISTRY, effective, floorDecision, requiredPrulesViolated, validateDef, type ActionDef, type Effect, type ParamDef, type Rev } from '@atlasauth/pca-actions';
import { classify } from './classify';
import { unionHighRisk } from './union';
import type { RawOp, RawParam, Verdict } from './types';

type Patch = Partial<Pick<Verdict, 'effects' | 'rev' | 'scope' | 'traits' | 'recipient'>> & { sure?: boolean };

export interface BuildOpts {
  ns: string;
  /** Pack name (for the adjudication exemptions); defaults to the namespace. */
  pack?: string;
  /** Use the vendor's short summary as the title (permissive licences); else a generated title. */
  vendorTitles: boolean;
  /** Reviewed overrides keyed by verb (after naming). */
  overrides?: Record<string, Patch>;
  /** Reviewed rules over `${METHOD} ${httpPath}` or the verb; the first match wins. */
  rules?: { re: RegExp; on?: 'verb' | 'http'; patch: Patch }[];
  /** Extra declared traits, e.g. infra_mutation for a cloud pack. */
  declare?: (v: Verdict, op: RawOp, verb: string) => string[];
  /** Fixed currency for money amounts when the op has no currency param. */
  currency?: { code: string; exp: number };
  /** Currency-looking param names for this API. */
  maxParams?: number;
}

export interface Built { def?: ActionDef; verb: string; verdict: Verdict; skip?: string; dropped: number }

const MAX_PARAMS = 64;
const anyId = { prefix: '', class: 'any_safe' as const, len: [1, 128] as [number, number] };
const clean = (s: string): string => s.replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 64);
const cleanName = (n: string): string => n.split('.').map(clean).filter(Boolean).slice(0, 3).join('.');
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);

const RE_EMAIL = /e-?mail(_?address(es)?)?$/i;
const RE_PHONE = /(^|_)(phone|mobile|msisdn|telephone)(_number)?$/i;
const RE_SECRET = /(password|passwd|secret|api_?key|private_?key|passphrase|access_?token|refresh_?token|bearer|auth_?token|client_?secret)/i;
const RE_URL = /(^|_)(url|uri|callback_url|webhook_url|redirect_uri|target_url|endpoint)$/i;
const RE_NAME = /^(first_name|last_name|full_name|given_name|family_name|display_name)$/i;
const RE_DOB = /^(birth_?date|date_of_birth|dob|birthday)$/i;
const RE_NATID = /^(ssn|national_id|social_security_number|tax_id|ssn_last_4)$/i;
const RE_AMOUNT = /^(amount|total|total_amount|amount_cents|amount_total|amount_to_capture|value)$/i;
const RE_CCY = /^(currency|currency_code)$/i;
const RE_RECIP = /^(to|recipient|recipients|recipient_id|channel|channel_id|channels|chat_id|user|user_id|users|email|emails|phone|phone_number|destination|address|number|reply_to|cc|bcc|attendees|invitees|emails_to_invite)$/i;
const RE_TEXT = /^(text|body|message|content|comment|subject|html|markdown|description|title|caption|note|blocks)$/i;
const RE_LIMIT = /^(limit|per_page|page_size|pagesize|max_results|maxresults|count|top|take|size|maxitems|max_items)$/i;

function paramDef(p: RawParam, ctx: { effects: Effect[]; ns: string; hasCcy: boolean; ccyName?: string; fixedCcy?: BuildOpts['currency']; idRole?: string; recipName?: string }): ParamDef {
  const leaf = p.name.split('.').pop()!;
  const d: ParamDef = { type: 'string' };
  if (p.type === 'integer') d.type = 'integer';
  else if (p.type === 'boolean') d.type = 'boolean';
  else if (p.type === 'array') d.type = 'array';
  else if (p.type === 'object') d.type = 'object_ref';
  else if (p.format === 'date') d.type = 'date';
  else if (p.format === 'date-time') d.type = 'datetime';
  if (!p.required) d.required = false;
  if (d.type === 'string') {
    if (p.values && p.values.length > 0 && p.values.length <= 64 && new Set(p.values).size === p.values.length) d.values = p.values;
    if (p.maxLength !== undefined && p.maxLength > 0 && p.maxLength <= 16_777_216) d.max_len = p.maxLength;
    if (p.format === 'uuid') d.format = 'uuid';
    else if (p.format === 'email') d.format = 'email';
    else if (p.format === 'uri' || p.format === 'url') d.format = 'url';
  }
  if (d.type === 'integer') {
    if (p.min !== undefined) d.min = p.min;
    if (p.max !== undefined) d.max = p.max;
  }
  if (d.type === 'array') {
    d.items = p.items ?? 'string';
    d.max_items = p.maxItems ?? 1000; // shortcut: the model requires bounded arrays (rule array_bounded); 1000 when the API states no bound
  }
  if (d.type === 'object_ref') d.max_len = 262_144;
  const sendLike = ctx.effects.includes('send');
  const publishLike = ctx.effects.includes('publish');
  // roles, by the parameter's leaf name (and, for ids, the path position)
  if (ctx.recipName === p.name && sendLike && d.type !== 'integer' && !RE_EMAIL.test(leaf) && !RE_PHONE.test(leaf)) { d.role = 'contact.address'; }
  else if (p.where === 'path' && ctx.idRole) { d.role = ctx.idRole; if (d.type !== 'string') { /* ids are strings or integers */ } }
  else if (d.type === 'string' || d.type === 'object_ref' || d.type === 'array') {
    if (RE_SECRET.test(leaf) && d.type === 'string') { d.role = 'credential.secret'; d.tags = ['secret']; }
    else if (RE_EMAIL.test(leaf) && d.type !== 'object_ref') { d.role = 'contact.email'; if (d.type === 'string') d.format = 'email'; d.tags = ['pii']; }
    else if (RE_PHONE.test(leaf) && d.type === 'string') { d.role = 'contact.phone'; d.tags = ['pii']; }
    else if (RE_NAME.test(leaf) && d.type === 'string') { d.role = 'person.name'; d.tags = ['pii']; }
    else if (RE_DOB.test(leaf)) { d.role = 'person.dob'; d.tags = ['pii']; }
    else if (RE_NATID.test(leaf) && d.type === 'string') { d.role = 'person.national_id'; d.tags = ['pii']; }
    else if (RE_CCY.test(leaf) && d.type === 'string' && ctx.ccyName === p.name) { d.role = 'money.currency'; d.format = 'iso_currency'; delete d.values; }
    else if (RE_URL.test(leaf) && d.type === 'string') { d.role = 'url.target'; if (!d.format) d.format = 'url'; }
    else if ((sendLike || publishLike) && RE_TEXT.test(leaf) && d.type === 'string') { d.role = sendLike ? 'text.message' : 'text.public'; d.tags = ['free_text_outbound']; }
  }
  if (d.type === 'integer' && ctx.effects.includes('pay') && RE_AMOUNT.test(leaf) && (ctx.hasCcy || ctx.fixedCcy)) {
    d.role = 'money.amount';
    d.min = Math.max(0, d.min ?? 0);
    d.max = d.max ?? 99_999_999_999;
    d.unit = { kind: 'money', ccy: ctx.hasCcy ? { from: ctx.ccyName! } : ctx.fixedCcy!.code, exp: ctx.fixedCcy?.exp ?? 2 };
  }
  if (d.type === 'integer' && !d.role && RE_LIMIT.test(leaf)) { d.role = 'count.limit'; d.min = Math.max(0, d.min ?? 0); d.max = p.max ?? 10_000; }
  if (['money.amount', 'party.payee', 'credential.secret', 'credential.token', 'credential.key', 'person.national_id', 'code.command', 'query.sql'].includes(d.role ?? '')) d.provenance_min = 'tool';
  if (d.type === 'integer') {
    // lint LD-003: numeric params are bounded. shortcut: 0..2^53-1 when the API states no bounds (ids, offsets, epoch millis fit); a negative value is denied
    d.min = d.min ?? 0;
    d.max = d.max ?? Number.MAX_SAFE_INTEGER;
  }
  if (d.type === 'string' && d.max_len === undefined && d.values === undefined && !d.format) d.max_len = d.role === 'text.message' || d.role === 'text.public' ? 100_000 : 4096;
  return d;
}

function describe(op: RawOp, v: Verdict): string {
  const where = op.method && op.httpPath ? `${op.method} ${op.httpPath}` : op.kind ? `${op.kind} ${op.path.join('.')}` : op.path.join('.');
  return `${where}. Effects: ${v.effects.join(', ')}.`.slice(0, 380);
}

const HUMAN = (s: string): string => s.replace(/_/g, ' ');
function titleOf(op: RawOp, vendor: boolean, ns: string): string {
  let t = vendor ? op.summary.replace(/\s+/g, ' ').trim().replace(/[.:;]+$/, '') : '';
  if (!t) {
    const a = op.path[op.path.length - 1]!;
    t = `${HUMAN(a)} ${HUMAN(op.path.slice(0, -1).join(' '))}`.trim();
    t = `${t.charAt(0).toUpperCase()}${t.slice(1)} (${ns})`;
  }
  const enc = new TextEncoder();
  while (enc.encode(t).length > 120) t = t.slice(0, -2);
  return t;
}

/** Build one def. A def whose reviewed or inferred effects cannot satisfy a required parameter rule (an inferred `send` with no recipient, an
 *  `export` with no bound) is not dropped and not shipped with a weaker floor: it falls back to the plain classification, left `unreviewed`
 *  (the maximal floor), because the evidence said something more is going on than the plain verb. */
export function build(op: RawOp, verb: string, o: BuildOpts): Built {
  const b = buildOnce(op, verb, o, true);
  if (b.def || !b.skip?.startsWith('prules')) return b;
  const f = buildOnce(op, verb, o, false);
  return f.def ? f : b;
}

function buildOnce(op: RawOp, verb: string, o: BuildOpts, first: boolean): Built {
  const soft = first;
  let v = classify(op, { soft });
  // the degraded pass cannot keep an `export` it has no bound for; the def stays unreviewed, which is the maximal floor anyway
  if (!first) v = { ...v, effects: v.effects.map((e) => (e === 'export' ? (op.method === 'GET' ? 'read' : 'create') : e)), sure: false, why: `${v.why}; degraded to unreviewed (a required parameter rule cannot be met)` };
  const key = `${op.method ?? ''} ${op.httpPath ?? ''}`;
  if (first) for (const r of o.rules ?? []) if (r.re.test(r.on === 'verb' ? verb : key)) { v = { ...v, ...r.patch, sure: r.patch.sure ?? true, why: `${v.why}; rule ${r.re}`, ...(r.patch.effects ? { inferred: undefined } : {}) }; break; }
  const ov = first ? o.overrides?.[verb] : undefined;
  if (ov) v = { ...v, ...ov, sure: ov.sure ?? true, why: `${v.why}; override`, ...(ov.effects ? { inferred: undefined } : {}) };

  // parameters: names, dedup, order (required first, then path/query/body as given), cap
  let raws = op.params.map((p) => ({ ...p, name: cleanName(p.name) })).filter((p) => p.name && !p.name.split('.').some((s) => RESERVED.has(s)));
  const names = new Set<string>();
  raws = raws.filter((p) => (names.has(p.name) ? false : (names.add(p.name), true)));
  // a dotted name may not also be a leaf and an ancestor
  raws = raws.filter((p) => !raws.some((q) => q !== p && q.name.startsWith(`${p.name}.`)));
  const order = (p: RawParam) => (p.required ? 0 : 1);
  raws = [...raws].sort((a, b) => order(a) - order(b));
  const dropped = Math.max(0, raws.length - (o.maxParams ?? MAX_PARAMS));
  raws = raws.slice(0, o.maxParams ?? MAX_PARAMS);

  // recipient requirement of external_communication: a send with no recipient-ish param is a publish
  let effects = v.effects;
  const recipOk = (p: RawParam) => RE_RECIP.test(p.name.split('.').pop()!) && (p.type === 'string' || p.type === 'array');
  const recip = (v.recipient ? raws.find((p) => p.name === v.recipient) : undefined) ?? raws.find((p) => recipOk(p) && /e?mail|phone/i.test(p.name)) ?? raws.find(recipOk);
  if (effects.includes('send') && !recip && v.inferred?.includes('send')) return { verb, verdict: v, skip: 'prules: recipient_param_declared', dropped };
  if (effects.includes('send') && !recip) {
    effects = [...effects.filter((e) => e !== 'send'), 'publish'];
    v = { ...v, effects, why: `${v.why}; no recipient param, so publish rather than send` };
  }
  // currency
  const ccy = raws.find((p) => RE_CCY.test(p.name.split('.').pop()!) && p.type === 'string');
  const ctx = { effects, ns: o.ns, hasCcy: !!ccy, ccyName: ccy?.name, fixedCcy: o.currency, recipName: recip?.name };

  // resource: type from the noun path, id from the last path param
  const nouns = op.path.slice(0, -1).slice(-3);
  const type = [o.ns, ...(nouns.length ? nouns : ['api'])].join('.');
  const pathParams = raws.filter((p) => p.where === 'path');
  const lastPath = pathParams[pathParams.length - 1];
  const params: Record<string, ParamDef> = {};
  for (const p of raws) {
    const idRole = p.where === 'path' ? (p === lastPath ? `id.${type}` : `id.${o.ns}.${clean(p.name).toLowerCase().replace(/_id$|id$/, '').slice(0, 32) || 'parent'}`) : undefined;
    const safeRole = idRole && /^id\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$/.test(idRole) ? idRole : undefined;
    const d = paramDef(p, { ...ctx, idRole: safeRole });
    if (recip && p.name === recip.name && v.recipient && d.type === 'string' && d.max_len !== undefined && d.max_len < 10_000_000) d.max_len = 10_000_000; // an opaque payload (raw RFC 822 message)
    if (p.where === 'path') { d.type = d.type === 'integer' ? 'integer' : 'string'; delete d.required; if (d.type === 'string' && d.max_len === undefined) d.max_len = 256; }
    params[p.name] = d;
  }
  // a path param of integer type cannot carry an id role in the def model (id roles are string ids)
  for (const [k, d] of Object.entries(params)) if (d.role?.startsWith('id.') && d.type === 'integer') { d.type = 'string'; d.max_len = 40; delete d.min; delete d.max; void k; }

  const pay = effects.includes('pay');
  let idem: ActionDef['idempotency'];
  if (pay) {
    if (!params.idempotency_key) params.idempotency_key = { type: 'string', max_len: 255, required: false };
    idem = { mode: 'key_param', param: 'idempotency_key' };
  } else if (params.idempotency_key) idem = { mode: 'key_param', param: 'idempotency_key' };
  else if (effects.every((e) => e === 'read') || op.method === 'PUT' || op.method === 'DELETE') idem = { mode: 'natural' };

  const traits = [...v.traits];
  for (const t of o.declare?.(v, op, verb) ?? []) if (!traits.includes(t)) traits.push(t);
  // an endpoint with no id in its path either acts on the caller's own singleton ('self': /user, /me, /account) or on a set
  const selfy = !lastPath && /^\/(user|users\/me|me|account|app|viewer|self)(\/|$)/.test(op.httpPath ?? '') && !/\/(repos|orgs|teams)\b/.test(op.httpPath ?? '');
  const resourceId: ActionDef['resource']['id'] = lastPath && lastPath.type !== 'object' ? anyId : selfy ? { exact: 'self' } : '*';
  const scope = resourceId === '*' && v.scope === 'one' ? 'set' : selfy ? 'one' : v.scope;
  const def0: ActionDef = {
    v: 1, kind: 'pca-action-def', verb,
    title: titleOf(op, o.vendorTitles, o.ns),
    description: describe(op, v),
    effects: [...new Set(effects)].sort() as Effect[],
    resource: { type, id: resourceId, scope },
    params,
    reversibility: (v.sure ? v.rev : 'irreversible') as Rev, // an unreviewed def declares what its floor makes true (lint LD-006)
    ...(idem ? { idempotency: idem } : {}),
    ...(traits.length ? { traits: [...new Set(traits)].sort() } : {}),
    ...(op.bindings ? { bindings: op.bindings } : {}),
    review: { state: v.sure ? 'authored' : 'unreviewed' },
    since: '0.5.0',
  };
  const def = unionHighRisk(o.pack ?? o.ns, def0);
  const err = validateDef(def);
  if (err) return { verb, verdict: v, skip: `invalid: ${err}`, dropped };
  const eff = effective(def, CORE_REGISTRY);
  const bad = requiredPrulesViolated(def, eff.eff);
  if (bad.length) return { verb, verdict: v, skip: `prules: ${bad.join(',')}`, dropped };
  return { def, verb, verdict: v, dropped };
}

// ---- post-pass over a whole pack -------------------------------------------------------------------------------------

const valueFor = (p: ParamDef): unknown => {
  if (p.values?.length) return p.values[0];
  switch (p.type) {
    case 'integer': return p.min ?? 0;
    case 'boolean': return true;
    case 'date': return '2000-01-01';
    case 'datetime': return '2000-01-01T00:00:00Z';
    case 'duration': return 1;
    case 'array': return [];
    case 'set': return [];
    case 'object_ref': return {};
    default:
      if (p.format === 'email') return 'a@example.com';
      if (p.format === 'uuid') return '00000000-0000-4000-8000-000000000000';
      if (p.format === 'url' || p.format === 'uri_https') return 'https://example.com/x';
      if (p.format === 'iso_currency') return 'USD';
      return 'x1234567';
  }
};

/** Lint LW-009: an executable example for money-moving / destructive / privilege-changing defs. The expectation is computed with the
 *  trait algebra's own floor decision against an empty grant, so it is what the pipeline decides, not a guess. */
export function addExamples(defs: ActionDef[]): void {
  const grant = { caveats: [] as never[], max_esc: 3, preauth_esc: 0 };
  for (const d of defs) {
    const eff = effective(d, CORE_REGISTRY);
    const hot = ['pca.money_moving', 'pca.destructive', 'pca.privilege_change'].some((t) => eff.closure.includes(t));
    if (!hot) continue;
    const params: Record<string, unknown> = {};
    for (const [k, p] of Object.entries(d.params)) if (p.required !== false) params[k] = valueFor(p);
    d.examples = [{ params, expect: floorDecision(grant, { context: [] }, eff.eff) }];
  }
}

/** Lint LD-010: a write declared `reversible` names the verb that undoes it, else it is `rate_limited`. */
export function linkCompensation(defs: ActionDef[]): void {
  const byVerb = new Map(defs.map((d) => [d.verb, d]));
  for (const d of defs) {
    if (d.reversibility !== 'reversible' || d.effects.every((e) => e === 'read')) continue;
    const parts = d.verb.split('.');
    const del = [...parts.slice(0, -1), 'delete'].join('.');
    if (d.effects.includes('create') && byVerb.has(del) && del !== d.verb) d.compensates = del;
    else d.reversibility = 'rate_limited';
  }
}

/** Lint LD-006: a declared class below the trait floor is a lie; declare what the floor makes true. */
export function settleClamps(defs: ActionDef[]): void {
  for (const d of defs) {
    for (const c of effective(d, CORE_REGISTRY).clamps) if (c.field === 'rev') d.reversibility = c.floor as Rev;
  }
}
