// eval.ts - measure the suggestion rules against a labeled corpus (spec section 6.4). Every corpus entry is turned into a
// source document of its own kind, run through the REAL importer and the REAL suggestion engine, and the traits the system
// flags are compared with the labels. Precision and recall per trait, with an exact Clopper-Pearson bound on each.
// These are heuristic numbers on a reviewed corpus. They are published as what they are, never as a safety guarantee.

import { clopperPearsonUpper } from '@atlasauth/pca-intent';
import { CORE_REGISTRY } from '../core-traits';
import type { ActionDef } from '../def';
import { closure, type Registry } from '../traits';
import { hintTraits } from '../effective';
import { importActions } from './pipeline';
import { DEFAULT_RULES } from './rules';
import { applySuggestion, suggestWithRules, type SuggestRules } from './suggest';
import type { ImportKind } from './common';

export interface CorpusEntry {
  id: string;
  src: 'hand' | 'syn' | 'real';
  /** The public specification a `real` entry was read from (one importer document per spec). */
  spec?: string;
  kind: ImportKind & ('openapi' | 'mcp' | 'graphql' | 'grpc' | 'asyncapi');
  name: string;
  method?: string;
  path?: string;
  /** `name:type[:format]` */
  params: string[];
  /** trait names without the `pca.` prefix */
  labels: string[];
  description: string;
}

export const LABEL_SHORT: Readonly<Record<string, string>> = {
  money: 'money_moving', destr: 'destructive', comm: 'external_communication', priv: 'privilege_change', exp: 'data_export', exec: 'code_execution',
  cred: 'credential_access', bulk: 'bulk', pii: 'pii_access', pub: 'public_exposure', pers: 'persistence', infra: 'infra_mutation', cost: 'cost_incurring',
  legal: 'legal_binding', imp: 'impersonation', egress: 'network_egress', fin: 'financial_data_read', reg: 'regulated_data', sched: 'scheduled', spawn: 'agent_spawning',
};

export function parseHandTsv(text: string): CorpusEntry[] {
  const out: CorpusEntry[] = [];
  let n = 0;
  for (const line of text.split('\n')) {
    if (line.trim().length === 0 || line.startsWith('#')) continue;
    const c = line.split('\t');
    if (c.length < 6) throw new Error(`hand corpus line needs 6 columns: ${line.slice(0, 80)}`);
    const [kind, name, loc, params, labels, description] = c as [string, string, string, string, string, string];
    const e: CorpusEntry = {
      id: `hand-${String(++n).padStart(4, '0')}`, src: 'hand', kind: kind as CorpusEntry['kind'], name,
      params: params === '-' ? [] : params.split(','),
      labels: labels === '-' ? [] : labels.split(',').map((l) => LABEL_SHORT[l] ?? l),
      description,
    };
    if (kind === 'openapi') { const [m, ...p] = loc.split(' '); e.method = m!; e.path = p.join(' '); }
    for (const l of e.labels) if (!Object.values(LABEL_SHORT).includes(l)) throw new Error(`unknown label '${l}' in ${name}`);
    out.push(e);
  }
  return out;
}

export function parseCorpusJsonl(text: string): CorpusEntry[] {
  return text.split('\n').filter((l) => l.trim().length > 0).map((l) => JSON.parse(l) as CorpusEntry);
}

// ---- entries -> source documents ---------------------------------------------------------------------------------------

const schemaOf = (spec: string): Record<string, unknown> => {
  const [, type, format] = /^[^:]+:([a-z]+)(?::(.+))?$/.exec(spec) ?? [];
  if (type === 'array') return { type: 'array', items: { type: 'string' } };
  return { type: type === 'number' ? 'number' : (type ?? 'string'), ...(format ? { format } : {}) };
};
const pname = (spec: string): string => spec.slice(0, spec.indexOf(':'));
const READ_FIRST = new Set(['get', 'list', 'find', 'search', 'count', 'describe', 'show', 'lookup', 'check', 'validate', 'preview', 'calculate', 'estimate', 'convert', 'format', 'compare', 'summarize', 'sort', 'filter', 'read', 'fetch', 'query', 'view', 'browse', 'open']);
const firstWord = (n: string): string => (/^[A-Za-z][a-z0-9]*/.exec(n)?.[0] ?? n).toLowerCase();

function openapiDoc(es: CorpusEntry[]): unknown {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const e of es) {
    const method = (e.method ?? 'get').toLowerCase();
    const body = ['post', 'put', 'patch'].includes(method);
    const props: Record<string, unknown> = {};
    for (const p of e.params) props[pname(p)] = schemaOf(p);
    const pathParams = [...(e.path ?? '').matchAll(/\{([^}]+)\}/g)].map((m) => ({ name: m[1]!, in: 'path', required: true, schema: { type: 'string' } }));
    const op: Record<string, unknown> = {
      ...(e.name ? { operationId: e.name } : {}), ...(e.description ? { summary: e.description } : {}),
      parameters: [...pathParams, ...(body ? [] : e.params.filter((p) => !pathParams.some((q) => q.name === pname(p))).map((p) => ({ name: pname(p), in: 'query', schema: schemaOf(p) })))],
      ...(body && e.params.length > 0 ? { requestBody: { content: { 'application/json': { schema: { type: 'object', properties: props, required: [] } } } } } : {}),
    };
    (paths[e.path!] ??= {})[method] = op;
  }
  return { openapi: '3.0.3', info: { title: 'corpus', version: '1' }, paths };
}

const gqlType = (spec: string): string => ({ string: 'String', integer: 'Int', boolean: 'Boolean', array: '[String]' } as Record<string, string>)[/^[^:]+:([a-z]+)/.exec(spec)?.[1] ?? 'string'] ?? 'String';
function graphqlSdl(es: CorpusEntry[]): string {
  const q: string[] = [], m: string[] = [];
  for (const e of es) {
    const args = e.params.length > 0 ? `(${e.params.map((p) => `${pname(p)}: ${gqlType(p)}`).join(', ')})` : '';
    (READ_FIRST.has(firstWord(e.name)) || /^[a-z]+s?$/.test(e.name) ? q : m).push(`  "${e.description.replace(/"/g, "'")}"\n  ${e.name}${args}: String`);
  }
  return `${q.length ? `type Query {\n${q.join('\n')}\n}\n` : ''}${m.length ? `type Mutation {\n${m.join('\n')}\n}\n` : ''}`;
}

const protoType = (spec: string): string => ({ string: 'string', integer: 'int64', boolean: 'bool', array: 'repeated string' } as Record<string, string>)[/^[^:]+:([a-z]+)/.exec(spec)?.[1] ?? 'string'] ?? 'string';
function protoText(es: CorpusEntry[]): string {
  const svcs = new Map<string, CorpusEntry[]>();
  for (const e of es) { const s = e.name.split('/')[0]!; (svcs.get(s) ?? svcs.set(s, []).get(s)!).push(e); }
  const msgs: string[] = ['message Empty {}'];
  const out: string[] = [];
  for (const [s, list] of svcs) {
    const rpcs = list.map((e) => {
      const m = e.name.split('/')[1]!;
      msgs.push(`message ${m}Request {\n${e.params.map((p, i) => `  ${protoType(p)} ${pname(p)} = ${i + 1};`).join('\n')}\n}`);
      return `  rpc ${m}(${m}Request) returns (Empty);`;
    });
    out.push(`service ${s} {\n${rpcs.join('\n')}\n}`);
  }
  return `syntax = "proto3";\npackage corpus;\n${msgs.join('\n')}\n${out.join('\n')}\n`;
}

function asyncDoc(es: CorpusEntry[]): unknown {
  const channels: Record<string, unknown> = {};
  for (const e of es) {
    const props: Record<string, unknown> = {};
    for (const p of e.params) props[pname(p)] = schemaOf(p);
    channels[e.name] = { publish: { summary: e.description, message: { payload: { type: 'object', properties: props } } } };
  }
  return { asyncapi: '2.6.0', info: { title: 'corpus', version: '1' }, channels };
}

const mcpDoc = (es: CorpusEntry[]): unknown => es.map((e) => {
  const props: Record<string, unknown> = {};
  for (const p of e.params) props[pname(p)] = schemaOf(p);
  return { name: e.name, description: e.description, inputSchema: { type: 'object', properties: props } };
});

const keyOf = (e: CorpusEntry): string => (e.kind === 'openapi' ? `${(e.method ?? 'GET').toUpperCase()} ${e.path}` : e.name);
const defKey = (d: ActionDef): string => (d.bindings?.openapi?.path ? `${d.bindings.openapi.method} ${d.bindings.openapi.path}` : undefined) ?? d.bindings?.openapi?.operationId ?? d.bindings?.mcp?.tool ?? d.bindings?.graphql?.field ?? (d.bindings?.grpc ? `${d.bindings.grpc.service.split('.').pop()}/${d.bindings.grpc.method}` : undefined) ?? d.bindings?.asyncapi?.channel ?? '';

/** Import every entry with the real importer of its kind. Returns the drafts by entry id (an entry whose def was not emitted is absent). */
export function importCorpus(entries: readonly CorpusEntry[]): { defs: Map<string, ActionDef>; todo: number } {
  const defs = new Map<string, ActionDef>();
  let todo = 0;
  const groups = new Map<string, CorpusEntry[]>();
  for (const e of entries) {
    const g = `${e.kind}|${e.spec ?? ''}`;
    groups.set(g, [...(groups.get(g) ?? []), e]);
  }
  for (const [g, es] of groups) {
    const kind = g.split('|')[0] as CorpusEntry['kind'];
    const src = kind === 'openapi' ? openapiDoc(es) : kind === 'mcp' ? mcpDoc(es) : kind === 'graphql' ? graphqlSdl(es) : kind === 'grpc' ? protoText(es) : asyncDoc(es);
    const r = importActions(kind, src, { ns: 'corpus', limits: { max_ops: 50_000, max_nodes: 20_000_000, max_bytes: 200_000_000 } });
    todo += r.todo.length;
    const byKey = new Map(r.defs.map((d) => [defKey(d), d]));
    for (const e of es) {
      const d = byKey.get(keyOf(e));
      if (d) defs.set(e.id, d);
    }
  }
  return { defs, todo };
}

// ---- scoring ---------------------------------------------------------------------------------------------------------------

export interface TraitStat {
  trait: string;
  positives: number;
  predicted: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  /** One-sided exact Clopper-Pearson lower bound on recall (1 - upper bound on the miss rate) at `alpha`. */
  recall_lower: number | null;
  precision_lower: number | null;
}

export interface EvalReport {
  alpha: number;
  entries: number;
  mapped: number;
  rules_version: string;
  /** What the system flags (importer facts + suggestion), the set a reviewer sees. */
  flagged: TraitStat[];
  /** Only what the suggestion engine ADDED (rules), for tuning the rules themselves. */
  suggested: TraitStat[];
  by_source: Record<string, { entries: number; flagged: TraitStat[] }>;
}

/** Deterministic split of the real corpus by specification: rules are tuned on `tune` specs only; `holdout` specs are never looked at when editing rules. */
export function realSplit(spec: string | undefined): 'tune' | 'holdout' {
  let h = 2166136261;
  for (const ch of spec ?? '') h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
  return (h >>> 7) % 2 === 0 ? 'tune' : 'holdout';
}
const sourceOf = (e: CorpusEntry): string => (e.src === 'real' ? `real/${realSplit(e.spec)}` : e.src);

const stat = (trait: string, rows: { actual: boolean; predicted: boolean }[], alpha: number): TraitStat => {
  let tp = 0, fp = 0, fn = 0;
  for (const r of rows) { if (r.actual && r.predicted) tp++; else if (r.predicted) fp++; else if (r.actual) fn++; }
  const pos = tp + fn, pred = tp + fp;
  return {
    trait, positives: pos, predicted: pred, tp, fp, fn,
    precision: pred === 0 ? null : tp / pred,
    recall: pos === 0 ? null : tp / pos,
    recall_lower: pos === 0 ? null : 1 - clopperPearsonUpper(fn, pos, alpha),
    // the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
    precision_lower: pred === 0 || pred > 600 ? null : 1 - clopperPearsonUpper(fp, pred, alpha),
  };
};

export function evalSuggest(entries: readonly CorpusEntry[], o: { rules?: SuggestRules; registry?: Registry; alpha?: number } = {}): EvalReport {
  const rules = o.rules ?? DEFAULT_RULES;
  const registry = o.registry ?? CORE_REGISTRY;
  const alpha = o.alpha ?? 0.05;
  const { defs } = importCorpus(entries);
  const traitNames = [...registry.traits.keys()].filter((t) => t !== 'pca.unreviewed' && t !== 'pca.irreversible').map((t) => t.replace(/^pca\./, '')).sort();
  const flagged = new Map<string, Set<string>>();
  const added = new Map<string, Set<string>>();
  for (const e of entries) {
    const d = defs.get(e.id);
    if (!d) continue;
    const s = suggestWithRules(d, rules, registry);
    const sd = applySuggestion(d, s, { rules: { version: rules.version, digest: '', fired: s.fired } });
    // the set a reviewer sees: the closure of everything the def now declares or implies
    flagged.set(e.id, new Set(closure(registry, hintTraits(sd)).filter((t) => t !== 'pca.unreviewed').map((t) => t.replace(/^pca\./, ''))));
    added.set(e.id, new Set(s.traits.map((t) => t.replace(/^pca\./, ''))));
  }
  const score = (es: readonly CorpusEntry[], pred: Map<string, Set<string>>): TraitStat[] =>
    traitNames
      .map((t) => stat(t, es.map((e) => ({ actual: e.labels.includes(t), predicted: pred.get(e.id)?.has(t) ?? false })), alpha))
      .filter((s) => s.positives > 0 || s.predicted > 0);
  const sources = [...new Set(entries.map(sourceOf)), ...(entries.some((e) => e.src === 'real') ? ['real'] : [])].sort();
  return {
    alpha, entries: entries.length, mapped: defs.size, rules_version: rules.version,
    flagged: score(entries, flagged), suggested: score(entries, added),
    by_source: Object.fromEntries(sources.map((s) => { const es = entries.filter((e) => (s === 'real' ? e.src === 'real' : sourceOf(e) === s)); return [s, { entries: es.length, flagged: score(es, flagged) }]; })),
  };
}

const pct = (x: number | null): string => (x === null ? '-' : (x * 100).toFixed(1) + '%');
export function renderEvalMarkdown(r: EvalReport): string {
  const table = (stats: TraitStat[]) => ['| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |', '|---|---:|---:|---:|---:|---:|---:|---:|',
    ...stats.map((s) => `| ${s.trait} | ${s.positives} | ${s.predicted} | ${pct(s.recall)} | ${pct(s.recall_lower)} | ${pct(s.precision)} | ${s.fn} | ${s.fp} |`)].join('\n');
  return [
    `# Suggestion rules ${r.rules_version}: measured on a labeled corpus`,
    '',
    `${r.entries} labeled operations (${r.mapped} imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = ${r.alpha}.`,
    'These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.',
    '',
    '## What a reviewer is shown (importer facts plus suggestions)', '', table(r.flagged), '',
    '## What the suggestion rules added', '', table(r.suggested), '',
    ...Object.entries(r.by_source).flatMap(([s, v]) => [`## Source: ${s} (${v.entries} operations)`, '', table(v.flagged), '']),
  ].join('\n');
}

export interface Floors {
  v: 2;
  alpha: number;
  /** Floors for the REAL-spec subset (operations read from public specifications and labeled by a person from what each does). */
  real: {
    /** Fewest labeled real operations the corpus may have. */
    min_entries: number;
    /** Fewest labeled positives each floored trait must have, so a floor is never set on a handful of cases. */
    min_positives: Record<string, number>;
    /** Lower bound on recall each trait must keep. */
    recall_lower: Record<string, number>;
  };
  /** The generated corpus is a REGRESSION set only: recall may not fall below what it was when the floors were recorded. */
  regression: { recall_lower: Record<string, number> };
}

/** Empty when the report meets the floors; else one line per failure. */
export function floorFailures(r: EvalReport, f: Floors): string[] {
  const out: string[] = [];
  const real = r.by_source['real/holdout'];
  if (!real || real.entries < f.real.min_entries) out.push(`the real-spec hold-out has ${real?.entries ?? 0} operations, fewer than the required ${f.real.min_entries}`);
  if (r.mapped < r.entries) out.push(`${r.entries - r.mapped} corpus operations were not imported`);
  for (const [t, floor] of Object.entries(f.real.recall_lower)) {
    const s = real?.flagged.find((x) => x.trait === t);
    const need = f.real.min_positives[t] ?? 0;
    if (!s || s.positives < need) out.push(`${t}: ${s?.positives ?? 0} real labeled positives, fewer than the ${need} the floor needs`);
    else if (s.recall_lower === null || s.recall_lower < floor) out.push(`${t}: hold-out recall lower bound ${pct(s.recall_lower)} is below the recorded floor ${pct(floor)}`);
  }
  const syn = r.by_source['syn'];
  for (const [t, floor] of Object.entries(f.regression.recall_lower)) {
    const s = syn?.flagged.find((x) => x.trait === t);
    if (!s || s.recall_lower === null || s.recall_lower < floor) out.push(`${t}: regression-set recall lower bound ${pct(s?.recall_lower ?? null)} is below ${pct(floor)}`);
  }
  return out;
}
