// hand.ts - a compact DSL for the hand-written packs (core, db, payments-rails, travel). Every def written here is `authored`:
// a person chose its effects, reversibility, scope and traits. The same post-pass (compensation, floors, examples) and the
// same structural checks as generated packs apply.
import { CORE_REGISTRY, effective, requiredPrulesViolated, validateDef, type ActionDef, type Effect, type IdPattern, type ParamDef, type Rev } from '@atlasauth/pca-actions';
import type { Built } from './build';
import { addExamples, linkCompensation, settleClamps } from './build';
import type { PackDef } from './pack';
import { infer, wordsOf } from './infer';
import { unionHighRisk } from './union';
import type { Verdict } from './types';

export const anyId: IdPattern = { prefix: '', class: 'any_safe', len: [1, 128] };
type Ex = Partial<ParamDef>;

export const P = {
  str: (max = 4096, x: Ex = {}): ParamDef => ({ type: 'string', max_len: max, ...x }),
  opt: (d: ParamDef): ParamDef => ({ ...d, required: false }),
  int: (min: number, max: number, x: Ex = {}): ParamDef => ({ type: 'integer', min, max, ...x }),
  bool: (x: Ex = {}): ParamDef => ({ type: 'boolean', ...x }),
  enum: (values: string[], x: Ex = {}): ParamDef => ({ type: 'string', values, ...x }),
  arr: (items: 'string' | 'integer' | 'boolean', max = 100, x: Ex = {}): ParamDef => ({ type: 'array', items, max_items: max, ...x }),
  obj: (max = 262_144, x: Ex = {}): ParamDef => ({ type: 'object_ref', max_len: max, ...x }),
  path: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 4096, role: 'path.fs', tags: ['path'], ...x }),
  cmd: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 65_536, role: 'code.command', tags: ['code'], provenance_min: 'tool', ...x }),
  code: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 1_000_000, role: 'code.source', tags: ['code'], ...x }),
  sql: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 100_000, role: 'query.sql', tags: ['sql'], provenance_min: 'tool', ...x }),
  url: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 2048, role: 'url.target', format: 'url', ...x }),
  email: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 254, role: 'contact.email', format: 'email', tags: ['pii'], ...x }),
  phone: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 32, role: 'contact.phone', tags: ['pii'], ...x }),
  to: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 256, role: 'contact.address', ...x }),
  secret: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 4096, role: 'credential.secret', tags: ['secret'], provenance_min: 'tool', ...x }),
  text: (max = 50_000, x: Ex = {}): ParamDef => ({ type: 'string', max_len: max, role: 'text.message', tags: ['free_text_outbound'], ...x }),
  pub: (max = 50_000, x: Ex = {}): ParamDef => ({ type: 'string', max_len: max, role: 'text.public', tags: ['free_text_outbound'], ...x }),
  id: (type: string, x: Ex = {}): ParamDef => ({ type: 'string', max_len: 128, role: `id.${type}`, ...x }),
  limit: (max = 1000, x: Ex = {}): ParamDef => ({ type: 'integer', min: 1, max, role: 'count.limit', required: false, ...x }),
  ccy: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 3, role: 'money.currency', format: 'iso_currency', ...x }),
  /** Money in minor units; `ccy` names the currency param (default `currency`). */
  money: (max = 100_000_000_00, ccyParam = 'currency', exp = 2, x: Ex = {}): ParamDef => ({
    type: 'integer', min: 1, max, role: 'money.amount', unit: { kind: 'money', ccy: { from: ccyParam }, exp }, provenance_min: 'tool', ...x,
  }),
  payee: (x: Ex = {}): ParamDef => ({ type: 'string', max_len: 256, role: 'party.payee', provenance_min: 'tool', ...x }),
  dt: (x: Ex = {}): ParamDef => ({ type: 'datetime', ...x }),
  date: (x: Ex = {}): ParamDef => ({ type: 'date', ...x }),
};

export interface H {
  verb: string;
  title: string;
  description: string;
  effects: Effect[];
  rev?: Rev;
  /** [resource type, scope, id pattern]; default: one resource named by the first id.<type> param. */
  res: [string, ('one' | 'set' | 'tenant' | 'global')?, IdPattern?];
  params: Record<string, ParamDef>;
  idem?: 'key' | 'natural';
  traits?: string[];
  aliases?: string[];
  context?: string[];
  blast?: ActionDef['blast'];
  compensates?: string;
}

export function def(h: H): ActionDef {
  const params = { ...h.params };
  if (h.idem === 'key' && !params.idempotency_key) params.idempotency_key = { type: 'string', max_len: 128, required: false };
  const scope = h.res[1] ?? 'one';
  const id = h.res[2] ?? (scope === 'one' ? anyId : '*');
  return {
    v: 1, kind: 'pca-action-def', verb: h.verb,
    ...(h.aliases ? { aliases: h.aliases } : {}),
    title: h.title, description: h.description, effects: h.effects,
    resource: { type: h.res[0], id, scope },
    params,
    reversibility: h.rev ?? (h.effects.every((e) => e === 'read') ? 'reversible' : 'irreversible'),
    ...(h.blast ? { blast: h.blast } : {}),
    ...(h.idem === 'key' ? { idempotency: { mode: 'key_param' as const, param: 'idempotency_key' } } : h.idem === 'natural' ? { idempotency: { mode: 'natural' as const } } : {}),
    ...(h.context ? { context: h.context } : {}),
    ...(h.traits ? { traits: h.traits } : {}),
    ...(h.compensates ? { compensates: h.compensates } : {}),
    review: { state: 'authored' },
    since: '0.5.0',
  };
}

/** Apply the shared noun/parameter inference to a hand-written def (only ever adds). An addition that would break a required parameter rule
 *  is dropped and the def is left `unreviewed` instead. */
export function inferHand(d: ActionDef): ActionDef {
  const last = d.verb.split('.').pop()!;
  const inf = infer(wordsOf(d.verb.replace(/\./g, ' '), d.resource.type.replace(/\./g, ' ')), d.effects, Object.keys(d.params).map((k) => k.split('.').pop()!), last.split('_')[0]!);
  if (inf.effects.length === 0 && inf.traits.length === 0) return d;
  const next: ActionDef = { ...d, effects: [...new Set([...d.effects, ...inf.effects])].sort() as Effect[], ...(inf.traits.length || d.traits ? { traits: [...new Set([...(d.traits ?? []), ...inf.traits])].sort() } : {}) };
  const ok = validateDef(next) === null && requiredPrulesViolated(next, effective(next, CORE_REGISTRY).hint.eff).length === 0;
  return ok ? next : { ...d, reversibility: 'irreversible', review: { state: 'unreviewed' } };
}

export function handPack(opts: {
  name: string; licence_notes: string; config_file: string; defs: ActionDef[]; sourceUri: string;
}): PackDef {
  return {
    name: opts.name, version: '0.5.0', redistribution: 'ours', licence_notes: opts.licence_notes, config_file: opts.config_file,
    sources: [{ id: 'table', kind: 'table', url: opts.sourceUri, sha256: '', licence: 'MIT (in-house)', licence_url: '' }],
    generate() {
      const defs = opts.defs.map((d) => unionHighRisk(opts.name, inferHand(structuredClone(d))));
      linkCompensation(defs);
      settleClamps(defs);
      addExamples(defs);
      const errs: string[] = [];
      const built = defs.map((d): Built => {
        const verdict: Verdict = { effects: d.effects, rev: 'irreversible', scope: 'one', traits: [], sure: true, why: 'hand-written' };
        const err = validateDef(d);
        if (err) errs.push(`${d.verb}: ${err}`);
        else {
          const bad = requiredPrulesViolated(d, effective(d, CORE_REGISTRY).hint.eff);
          if (bad.length) errs.push(`${d.verb}: prules ${bad.join(',')}`);
        }
        return { def: d, verb: d.verb, verdict, dropped: 0 };
      });
      if (errs.length) throw new Error(errs.join('\n'));
      return built;
    },
  };
}

export interface Entity {
  name: string; // snake_case noun, e.g. 'contact'
  title: string; // human noun, e.g. 'contact'
  /** Parameters accepted on create/update (all optional on update). */
  fields?: Record<string, ParamDef>;
  pii?: boolean;
  /** Which of get/list/search/create/update/delete/archive to emit (default: all but archive). */
  ops?: ('get' | 'list' | 'search' | 'create' | 'update' | 'delete' | 'archive')[];
  /** Deleting is recoverable from a bin/trash. */
  trash?: boolean;
  /** Suffix for the resource type; default the entity name. */
  noun?: string;
}

/** Standard CRUD defs for entities of a product. */
export function crud(ns: string, entities: Entity[]): H[] {
  const out: H[] = [];
  for (const e of entities) {
    const type = `${ns}.${e.noun ?? e.name}`;
    const ops = e.ops ?? ['get', 'list', 'search', 'create', 'update', 'delete'];
    const idp = { [e.name]: P.id(type) };
    const pii: ('pca.pii_access')[] = e.pii ? ['pca.pii_access'] : [];
    const fields = e.fields ?? {};
    const optFields = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, { ...v, required: false }]));
    const t = e.title;
    if (ops.includes('get')) out.push({ verb: `${ns}.${e.name}.get`, title: `Read a ${t}`, description: `Reads one ${t}.`, effects: ['read'], traits: pii, res: [type, 'one'], params: idp });
    if (ops.includes('list')) out.push({ verb: `${ns}.${e.name}.list`, title: `List ${t}s`, description: `Lists ${t}s, page by page.`, effects: ['read'], traits: pii, res: [type, 'set'], params: { limit: P.limit(1000), cursor: P.opt(P.str(1024)) } });
    if (ops.includes('search')) out.push({ verb: `${ns}.${e.name}.search`, title: `Search ${t}s`, description: `Searches ${t}s by a query.`, effects: ['read'], traits: pii, res: [type, 'set'], params: { query: P.str(2048, { role: 'query.search' }), limit: P.limit(1000) } });
    if (ops.includes('create')) out.push({ verb: `${ns}.${e.name}.create`, title: `Create a ${t}`, description: `Creates a ${t}.`, effects: ['create'], rev: 'reversible', idem: 'key', traits: pii, res: [type, 'set'], params: fields, compensates: ops.includes('delete') ? `${ns}.${e.name}.delete` : undefined });
    if (ops.includes('update')) out.push({ verb: `${ns}.${e.name}.update`, title: `Update a ${t}`, description: `Changes fields of a ${t}.`, effects: ['update'], rev: 'rate_limited', traits: pii, res: [type, 'one'], params: { ...idp, ...optFields } });
    if (ops.includes('archive')) out.push({ verb: `${ns}.${e.name}.archive`, title: `Archive a ${t}`, description: `Archives a ${t}; it can be restored.`, effects: ['update'], rev: 'rate_limited', res: [type, 'one'], params: idp });
    if (ops.includes('delete')) out.push({ verb: `${ns}.${e.name}.delete`, title: `Delete a ${t}`, description: e.trash ? `Moves a ${t} to the trash, where it can be restored for a limited time.` : `Deletes a ${t} permanently.`, effects: ['delete'], rev: e.trash ? 'rate_limited' : 'irreversible', res: [type, 'one'], params: idp });
  }
  return out;
}
