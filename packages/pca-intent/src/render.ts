import { isGroupCondition, isLeafCondition, type Caveat, type Condition, type Predicate } from '@atlasauth/pca';
import { DEFAULT_CATALOG, type Catalog } from '@atlasauth/pca/ext/research';
import { cellRep, decodeCell, numCells, verbCellCount, type Dim, type Omega, type VerbSpace } from './omega';
import { admitter, normalizePolicy, type PolicyInput } from './policy';
import { slotsToPolicy, type IntentSlots } from './slots';

/**
 * DETERMINISTIC PLAIN-LANGUAGE RENDERING + BACK-TRANSLATION DIFF (spec §3.2b). No language model anywhere:
 * every sentence is a fixed template over the grant's own data, so the same grant always renders the same text
 * and the renderer cannot be prompt-injected. Anything the templates do not know is rendered as an explicit
 * "not understood" line, never silently dropped.
 */

export function labelOf(path: string): string {
  if (path === 'action.resource') return 'resource';
  const last = path.split('.').pop() ?? path;
  return last.replace(/_/g, ' ');
}

const fmt = (v: unknown): string => (typeof v === 'string' ? `"${v}"` : Array.isArray(v) ? v.map(fmt).join(', ') : String(v));

export function renderCondition(c: Condition): string {
  if (c === null || typeof c !== 'object') return 'an unreadable condition (not understood)';
  if (isGroupCondition(c)) {
    if ('all_of' in c) return `all of: ${(c.all_of ?? []).map(renderCondition).map((s) => `(${s})`).join(' and ')}`;
    if ('any_of' in c) return `either ${(c.any_of ?? []).map(renderCondition).map((s) => `(${s})`).join(' or ')}`;
    return `it is not the case that ${renderCondition(c.not)}`;
  }
  if (!isLeafCondition(c)) return 'an unreadable condition (not understood)';
  const L = `the ${labelOf(c.field)}`;
  const V = c.ref !== undefined ? `the ${labelOf(c.ref)}` : fmt(c.value);
  switch (c.op) {
    case 'eq': return `${L} is ${V}`;
    case 'ne': return `${L} is not ${V}`;
    case 'in': return `${L} is one of ${V}`;
    case 'nin': return `${L} is none of ${V}`;
    case 'lt': return `${L} is less than ${V}`;
    case 'lte': return `${L} is at most ${V}`;
    case 'gt': return `${L} is more than ${V}`;
    case 'gte': return `${L} is at least ${V}`;
    case 'prefix': return `${L} starts with ${V}`;
    case 'exists': return c.value === false ? `${L} is absent` : `${L} is present`;
    case 'like': return `${L} matches the pattern ${V}`;
    case 'matches': return `${L} matches the regular expression ${V}`;
    case 'is_a': return `${L} is of type ${V}`;
    case 'member_of': return `${L} belongs to ${V}`;
    default: return `${L} has an unrecognised test "${String(c.op)}" (not understood)`;
  }
}

function renderResource(r: unknown): string {
  if (r === undefined || r === '*') return 'on any resource';
  if (typeof r !== 'string') return 'on an unreadable resource matcher (not understood)';
  if (r.startsWith('re:')) return `on resources matching the regular expression "${r.slice(3)}"`;
  if (r.endsWith('*')) return `on resources under "${r.slice(0, -1)}"`;
  return `only on resource "${r}"`;
}

function renderVerb(v: Predicate['verb'], catalog: Catalog): string {
  const one = (x: string) => {
    if (x === '*') return 'ANY action of any connector';
    const s = catalog.get(x);
    return s ? `${s.description.replace(/\.$/, '').replace(/^./, (ch) => ch.toLowerCase())} [${x}, ${s.reversibility.replace('_', '-')}]` : `"${x}" [uncatalogued: treated as irreversible]`;
  };
  return Array.isArray(v) ? v.map((x) => one(String(x))).join('; or ') : one(String(v));
}

export function renderCaveat(c: Caveat): string {
  switch (c?.type) {
    case 'expires': return `The grant expires at ${new Date(Number(c.at)).toISOString()}.`;
    case 'not_before': return `The grant is not valid before ${new Date(Number(c.at)).toISOString()}.`;
    case 'rate': return `At most ${String(c.max)} actions in any ${String(c.per_secs)} seconds.`;
    case 'max_blast_radius': return `No action whose blast radius exceeds ${String(c.max)} (on a 0–1 scale).`;
    case 'reversibility_max': return `Nothing more severe than "${String(c.class).replace('_', '-')}" (reversible < rate-limited < irreversible).`;
    case 'delegation_depth': return `It may be re-delegated at most ${String(c.max)} level(s) deep.`;
    case 'budget_alloc': return `A trust-budget allocation of ${String(c.limit)} is carried for sub-delegation.`;
    default: return `An unrecognised constraint of type "${String(c?.type)}" (NOT UNDERSTOOD: do not rely on this grant until it is explained).`;
  }
}

/** Render a grant as numbered plain-language sentences. Deterministic: same grant, same text. */
export function renderGrant(policy: PolicyInput, catalog: Catalog = DEFAULT_CATALOG): string {
  const { predicates, caveats } = normalizePolicy(policy);
  if (predicates.length === 0) return 'This grant allows nothing.';
  const lines = ['The agent may do the following, and nothing else:'];
  predicates.forEach((p, i) => {
    const conds = (p.where ?? []).map(renderCondition);
    lines.push(`${i + 1}. ${renderVerb(p.verb, catalog)}, ${renderResource(p.resource)}${conds.length ? `, only when ${conds.join(', and ')}` : ''}.`);
  });
  if (caveats.length) {
    lines.push('Limits that apply to everything above:');
    for (const c of caveats) lines.push(`- ${renderCaveat(c)}`);
  }
  return lines.join('\n');
}

// ---- outcome / question rendering -------------------------------------------------------------------

function renderDimCell(d: Dim, i: number): string {
  const L = labelOf(d.path);
  if (d.kind === 'num') {
    // Questions are about the WHOLE cell ("any amount from 201 to 99999"), illustrated by the boundary witness.
    // A "yes" means every value in the range is acceptable; that is what makes a box-shaped intent realizable
    // in Θ even when its thresholds are not among the cuts (spec §4.3).
    const c = numCells(d)[i]!;
    if (c.lo === c.hi) return `${L} exactly ${c.lo}`;
    return `any ${L} from ${c.lo} to ${c.hi} (e.g. ${i > 0 ? c.lo : c.hi})`;
  }
  const v = d.values[i]!;
  if (v.kind === 'exact') return `${L} "${v.value}"`;
  if (v.kind === 'prefix') return `a ${L} under "${v.value}" (not otherwise named)`;
  return `a ${L} not named anywhere in the grant or your request`;
}

/** "Should the agent be allowed to: <verb description>, with amount 201 and recipient "bob"?" */
export function renderQuestion(vs: VerbSpace, cell: readonly number[], catalog: Catalog = DEFAULT_CATALOG): string {
  const s = catalog.get(vs.verb);
  const what = s ? `${s.description.replace(/\.$/, '')} [${vs.verb}]` : `perform "${vs.verb}"`;
  const parts = vs.dims.map((d, k) => renderDimCell(d, cell[k]!));
  return `Should the agent be allowed to: ${what}${parts.length ? `, with ${parts.join(', ')}` : ''}?`;
}

// ---- back-translation diff ----------------------------------------------------------------------------

export interface DimClaim {
  path: string;
  /** numeric: [min, max] of accepted values (projection); categorical: accepted value labels. */
  range?: [number, number];
  values?: string[];
  /** true when this dimension does not restrict the verb at all. */
  any: boolean;
}

export interface VerbClaim {
  verb: string;
  allowed: boolean;
  /** true when the accepted region is exactly the product of the per-dimension projections. */
  boxShaped: boolean;
  dims: DimClaim[];
}

/** The claim IR of a policy over Ω: what the rendering asserts, verb by verb and dimension by dimension. */
export function claimsOf(policy: PolicyInput, omega: Omega): VerbClaim[] {
  const a = admitter(policy);
  return omega.verbs.map((vs) => {
    const n = verbCellCount(vs);
    const acc: number[][] = [];
    for (let c = 0; c < n; c++) {
      const idx = decodeCell(vs, c);
      if (a.admits(vs, cellRep(vs, idx))) acc.push(idx);
    }
    const proj = vs.dims.map((_, k) => new Set(acc.map((x) => x[k]!)));
    const boxCount = proj.reduce((m, s) => m * s.size, 1);
    const dims: DimClaim[] = vs.dims.map((d, k) => {
      const s = proj[k]!;
      const total = d.kind === 'num' ? numCells(d).length : d.values.length;
      if (d.kind === 'num') {
        const cells = numCells(d);
        const ids = [...s].sort((x, y) => x - y);
        return { path: d.path, any: s.size === total, ...(ids.length ? { range: [cells[ids[0]!]!.lo, cells[ids[ids.length - 1]!]!.hi] as [number, number] } : {}) };
      }
      return { path: d.path, any: s.size === total, values: [...s].sort((x, y) => x - y).map((i) => (d.values[i]!.kind === 'prefix' ? d.values[i]!.value + '*' : d.values[i]!.value)) };
    });
    return { verb: vs.verb, allowed: acc.length > 0, boxShaped: acc.length === boxCount, dims };
  });
}

export interface ClaimDiff {
  verb: string;
  kind: 'extra-verb' | 'missing-verb' | 'looser' | 'tighter' | 'different' | 'shape';
  path?: string;
  /** Plain-language explanation shown to the principal. */
  text: string;
}

function dimText(c: DimClaim | undefined): string {
  if (!c) return 'anything';
  if (c.any) return 'any value';
  if (c.range) return `${c.range[0]} to ${c.range[1]}`;
  return c.values?.length ? c.values.join(', ') : 'nothing';
}

interface DiffWording {
  extra(verb: string): string;
  missing(verb: string): string;
  shape(verb: string): string;
  dim(verb: string, path: string, a: string, b: string): string;
}

function diffClaims(g: VerbClaim[], s: VerbClaim[], w: DiffWording): ClaimDiff[] {
  const out: ClaimDiff[] = [];
  g.forEach((gc, i) => {
    const sc = s[i]!;
    if (gc.allowed && !sc.allowed) return void out.push({ verb: gc.verb, kind: 'extra-verb', text: w.extra(gc.verb) });
    if (!gc.allowed && sc.allowed) return void out.push({ verb: gc.verb, kind: 'missing-verb', text: w.missing(gc.verb) });
    if (!gc.allowed) return;
    if (!gc.boxShaped || !sc.boxShaped) {
      // A non-box region cannot be summarized dimension-by-dimension without loss; compare the projections and
      // ALSO flag the shape so the reader is shown the full rendering.
      if (gc.boxShaped !== sc.boxShaped) out.push({ verb: gc.verb, kind: 'shape', text: w.shape(gc.verb) });
    }
    gc.dims.forEach((gd, k) => {
      const sd = sc.dims[k]!;
      if (JSON.stringify(gd) === JSON.stringify(sd)) return;
      let kind: ClaimDiff['kind'] = 'different';
      if (gd.range && sd.range) kind = gd.range[0] <= sd.range[0] && gd.range[1] >= sd.range[1] ? 'looser' : gd.range[0] >= sd.range[0] && gd.range[1] <= sd.range[1] ? 'tighter' : 'different';
      else if (gd.values && sd.values) kind = sd.values.every((v) => gd.values!.includes(v)) ? 'looser' : gd.values.every((v) => sd.values!.includes(v)) ? 'tighter' : 'different';
      else if (gd.any && !sd.any) kind = 'looser';
      out.push({ verb: gc.verb, kind, path: gd.path, text: w.dim(gc.verb, gd.path, dimText(gd), dimText(sd)) });
    });
  });
  return out;
}

/**
 * Back-translation diff: render the grant and the intent slots into the same claim IR over Ω and list every
 * difference. With an ideal reader (one who reads every line and compares it to what they meant) a non-empty
 * diff is exactly what a human confirming the rendering would catch; the benchmark reports it as SIMULATED.
 */
export function backTranslationDiff(grant: PolicyInput, slots: IntentSlots, omega: Omega): ClaimDiff[] {
  return diffClaims(claimsOf(grant, omega), claimsOf(slotsToPolicy(slots), omega), {
    extra: (v) => `The grant allows ${v}, which your request did not mention.`,
    missing: (v) => `Your request mentions ${v}, but the grant does not allow it.`,
    shape: (v) => `The grant's rule for ${v} is a combination of cases that your request did not describe.`,
    dim: (v, path, a, b) => `For ${v}, the grant allows ${labelOf(path)} ${a}; your request said ${b}.`,
  });
}

/**
 * The same claim diff between two GRANTS (two compilers' readings, spec §4.2a/b): what `a` allows that `b` does
 * not, dimension by dimension, as sentences. `kind` is from a's point of view (looser = a allows more).
 */
export function claimDiff(a: PolicyInput, b: PolicyInput, omega: Omega, names: [string, string] = ['the first reading', 'the second reading']): ClaimDiff[] {
  return diffClaims(claimsOf(a, omega), claimsOf(b, omega), {
    extra: (v) => `${names[0]} allows ${v}; ${names[1]} does not.`,
    missing: (v) => `${names[1]} allows ${v}; ${names[0]} does not.`,
    shape: (v) => `${names[0]} and ${names[1]} describe ${v} with differently shaped rules.`,
    dim: (v, path, x, y) => `For ${v}, ${names[0]} allows ${labelOf(path)} ${x}; ${names[1]} allows ${y}.`,
  });
}

/**
 * A concrete action in plain language (deterministic; the text a judge or a JIT consent prompt shows, spec §4.4/4.5).
 * Values are printed verbatim; a value outside every named cell is still shown, so nothing is hidden.
 */
export function renderAction(vs: VerbSpace, values: Record<string, number | string>, catalog: Catalog = DEFAULT_CATALOG): string {
  const s = catalog.get(vs.verb);
  const what = s ? `${s.description.replace(/\.$/, '')} [${vs.verb}, ${vs.reversibility.replace('_', '-')}]` : `perform "${vs.verb}" [uncatalogued: treated as irreversible]`;
  const keys = Object.keys(values).sort();
  const parts = keys.map((k) => `${labelOf(k)} ${typeof values[k] === 'string' ? `"${String(values[k])}"` : String(values[k])}`);
  return `The agent wants to: ${what}${parts.length ? `, with ${parts.join(', ')}` : ''}.`;
}
