import { isGroupCondition, isLeafCondition, type Condition, type Predicate } from '@atlasauth/pca';
import type { ActionSchema } from '@atlasauth/pca/ext/intent';
import type { UnitTag } from '@atlasauth/pca';
import { toModel } from './enumerate';
import { alwaysDenies } from './index';
import type { ActionDefLike, ActionDefStructural, ParamShape, PolicyInput, VerbShape } from './types';

/**
 * VALIDATING A POLICY AGAINST THE ACTION SCHEMA / ACTIONDEFS (borrowed-ideas item 22, security contract C-253).
 *
 * A signed action schema (or an ActionDef) says which verbs exist, which parameters each has and of which type, range, closed
 * value set and unit. A policy is a second description of the same actions, written by a different hand. This lint compares the
 * two before the policy is signed: a condition on an undeclared parameter, a number compared with a string, an enum value that
 * does not exist, a bound the schema makes impossible or redundant, a predicate that can never match, a money verb with no
 * ceiling, and (rule 20) a unit-bearing parameter read without the matching unit tag. Cedar validates policies against its
 * schema in the same way; here it is a lint that runs in CI, and a failure at compile time for typed goals.
 */

export type SchemaFindingCode =
  | 'undeclared-verb'
  | 'undeclared-param'
  | 'type-mismatch'
  | 'value-not-in-enum'
  | 'out-of-range'
  | 'redundant-bound'
  | 'unreachable-predicate'
  | 'unbounded-money'
  | 'unit-missing'
  | 'unit-mismatch'
  | 'verb-not-granted'
  | 'ordering-on-string';

export interface SchemaFinding {
  code: SchemaFindingCode;
  severity: 'error' | 'warn' | 'info';
  message: string;
  where: string;
}

export interface ValidateOptions {
  /** The grant's `units` map (`action.params.<name>` to unit tag), when it has one. */
  units?: Record<string, UnitTag>;
  /** The schema's own `units` table, keyed by unit id (taken from a signed schema automatically). */
  schemaUnits?: Record<string, UnitTag>;
  /** Also list schema verbs that no predicate grants (informational). */
  listUngranted?: boolean;
}

const DEF_TYPE: Record<string, ParamShape['type']> = { string: 'string', integer: 'integer', boolean: 'boolean', date: 'date', set: 'set', array: 'array' };

/**
 * Verb shapes from real ActionDefs. Types the policy language cannot compare directly (`datetime`, `duration`, `object_ref`) are
 * left untyped (unchecked). A money role keeps its semantic so the unbounded-money lint applies; the unit table of a def lives in
 * the derived schema, so unit tags are checked against a schema (`verbShapes(schema)`), not here.
 */
export function verbShapesFromActionDefs(defs: readonly ActionDefStructural[]): VerbShape[] {
  return defs.map((d) => ({
    verb: d.verb,
    params: Object.fromEntries(
      Object.entries(d.params ?? {}).map(([k, p]) => [
        k,
        {
          ...(DEF_TYPE[p.type] ? { type: DEF_TYPE[p.type] } : {}),
          ...(p.role ? { semantic: p.role } : {}),
          ...(p.values ? { values: p.values } : {}),
          ...(p.min !== undefined ? { min: p.min } : {}),
          ...(p.max !== undefined ? { max: p.max } : {}),
          ...(p.sensitivity ? { sensitivity: p.sensitivity } : {}),
          ...(p.required !== undefined ? { required: p.required } : {}),
        } as ParamShape,
      ]),
    ),
  }));
}

/** The verbs and parameters of a signed action schema, a list of shapes, or a list of ActionDefs. */
export function verbShapes(src: ActionSchema | readonly VerbShape[] | readonly ActionDefLike[] | readonly ActionDefStructural[]): VerbShape[] {
  if (!Array.isArray(src) && 'verbs' in (src as ActionSchema)) {
    return (src as ActionSchema).verbs.map((v) => ({
      verb: v.verb,
      params: Object.fromEntries(Object.entries(v.params ?? {}).map(([k, d]) => [k, { type: d.type, ...(d.values ? { values: d.values } : {}), ...(d.min !== undefined ? { min: d.min } : {}), ...(d.max !== undefined ? { max: d.max } : {}), ...(d.unit ? { unit: d.unit } : {}), semantic: d.semantic, sensitivity: d.sensitivity, ...(d.required !== undefined ? { required: d.required } : {}) } as ParamShape])),
    }));
  }
  const list = src as ReadonlyArray<VerbShape | ActionDefLike | ActionDefStructural>;
  return list.map((d) => ({
    verb: ('verb' in d && d.verb) || ('id' in d && d.id) || '',
    params: Object.fromEntries(Object.entries((d.params ?? {}) as Record<string, ParamShape & { role?: string }>).map(([k, p]) => [k, verbShapesFromActionDefs([{ verb: '', params: { [k]: p as never } }])[0]!.params[k]!])),
  })).map((v, i) => {
    // shape-style params carry `semantic` and `unit` directly; keep them
    const orig = (list[i]!.params ?? {}) as Record<string, ParamShape>;
    for (const k of Object.keys(v.params)) {
      if (orig[k]?.semantic !== undefined) v.params[k]!.semantic = orig[k]!.semantic;
      if (orig[k]?.unit !== undefined) v.params[k]!.unit = orig[k]!.unit;
    }
    return v;
  });
}

const NUMERIC_OPS = ['lt', 'lte', 'gt', 'gte'];

function leaves(c: Condition, into: Condition[] = []): Condition[] {
  if (c === null || typeof c !== 'object') return into;
  if (isGroupCondition(c)) {
    if ('all_of' in c && Array.isArray(c.all_of)) c.all_of.forEach((x) => leaves(x, into));
    else if ('any_of' in c && Array.isArray(c.any_of)) c.any_of.forEach((x) => leaves(x, into));
    else if ('not' in c) leaves(c.not, into);
  } else into.push(c);
  return into;
}

const typeOk = (t: ParamShape['type'], v: unknown): boolean =>
  t === undefined ||
  (t === 'integer' ? typeof v === 'number' && Number.isFinite(v) : t === 'boolean' ? typeof v === 'boolean' : t === 'string' || t === 'date' ? typeof v === 'string' : true);

/** Lint a policy against the schema it is written for. `ok` is false when any finding is an error. */
export function validatePolicyAgainstSchema(policy: PolicyInput, src: ActionSchema | readonly VerbShape[] | readonly ActionDefLike[] | readonly ActionDefStructural[], o: ValidateOptions = {}): { ok: boolean; findings: SchemaFinding[] } {
  const shapes = verbShapes(src);
  const byVerb = new Map(shapes.map((s) => [s.verb, s]));
  const schemaUnits = o.schemaUnits ?? (!Array.isArray(src) && 'units' in (src as ActionSchema) ? ((src as ActionSchema).units as Record<string, UnitTag> | undefined) : undefined);
  const model = toModel(policy);
  const findings: SchemaFinding[] = [];
  const add = (code: SchemaFindingCode, severity: SchemaFinding['severity'], where: string, message: string): void => void findings.push({ code, severity, where, message });

  const check = (p: Predicate, where: string, isVeto: boolean): void => {
    const verbs = p.verb === '*' || (Array.isArray(p.verb) && p.verb.includes('*')) ? shapes.map((s) => s.verb) : Array.isArray(p.verb) ? p.verb : [p.verb];
    for (const v of verbs) if (!byVerb.has(v)) add('undeclared-verb', isVeto ? 'warn' : 'error', where, `verb '${v}' is not declared by the schema`);
    const declared = verbs.map((v) => byVerb.get(v)).filter((s): s is VerbShape => s !== undefined);
    if (declared.length === 0) return;
    (p.where ?? []).forEach((w, wi) => {
      for (const c of leaves(w)) {
        if (!isLeafCondition(c) || !c.field.startsWith('action.params.')) continue;
        const name = c.field.slice('action.params.'.length).split('.')[0]!;
        const at = `${where}.where[${wi}]`;
        const having = declared.filter((s) => Object.prototype.hasOwnProperty.call(s.params, name));
        if (having.length === 0) {
          add('undeclared-param', 'error', at, `parameter '${name}' is declared by none of ${declared.map((s) => s.verb).join(', ')}`);
          continue;
        }
        if (having.length < declared.length) add('undeclared-param', 'warn', at, `parameter '${name}' is not declared by ${declared.filter((s) => !having.includes(s)).map((s) => s.verb).join(', ')}`);
        const d = having[0]!.params[name]!;
        const op = c.op;
        const vals = Array.isArray(c.value) && (op === 'in' || op === 'nin') ? (c.value as unknown[]) : [c.value];
        if (c.ref === undefined && ['eq', 'ne', 'in', 'nin', ...NUMERIC_OPS].includes(op)) {
          for (const x of vals) if (!typeOk(d.type, x)) add('type-mismatch', 'error', at, `'${name}' is ${d.type} but is compared (${op}) with ${typeof x}`);
        }
        if (NUMERIC_OPS.includes(op) && d.type !== undefined && d.type !== 'integer') {
          if (d.type === 'string' || d.type === 'date') add('ordering-on-string', 'warn', at, `'${name}' is ${d.type}: ordering follows UTF-8 byte order`);
          else add('type-mismatch', 'error', at, `ordering operator ${op} on ${d.type} parameter '${name}'`);
        }
        if (d.values && (op === 'eq' || op === 'in') && typeof vals[0] === 'string') {
          const missing = vals.filter((x) => typeof x === 'string' && !d.values!.includes(x));
          if (missing.length === vals.length) add('value-not-in-enum', 'error', at, `no value of ${op} ${JSON.stringify(vals)} is in the schema's set for '${name}'`);
          else if (missing.length > 0) add('value-not-in-enum', 'warn', at, `${JSON.stringify(missing)} are not in the schema's set for '${name}'`);
        }
        if (d.type === 'integer' && typeof c.value === 'number' && c.ref === undefined) {
          const v = c.value;
          const dead =
            (op === 'eq' && ((d.max !== undefined && v > d.max) || (d.min !== undefined && v < d.min))) ||
            (op === 'gt' && d.max !== undefined && v >= d.max) ||
            (op === 'gte' && d.max !== undefined && v > d.max) ||
            (op === 'lt' && d.min !== undefined && v <= d.min) ||
            (op === 'lte' && d.min !== undefined && v < d.min);
          if (dead) add('out-of-range', 'error', at, `'${name}' ${op} ${v} can never hold: the schema bounds it to [${d.min ?? '-inf'}, ${d.max ?? 'inf'}]`);
          else if ((op === 'lte' && d.max !== undefined && v >= d.max) || (op === 'gte' && d.min !== undefined && v <= d.min)) add('redundant-bound', 'info', at, `'${name}' ${op} ${v} never binds: the schema already bounds it to [${d.min ?? '-inf'}, ${d.max ?? 'inf'}]`);
        }
        if (d.unit && o.units !== undefined && (NUMERIC_OPS.includes(op) || op === 'eq') && !isVeto) {
          const tag = o.units[c.field] ?? o.units[`action.params.${name}`];
          const sch = schemaUnits?.[d.unit];
          if (tag === undefined) add('unit-missing', 'error', at, `'${name}' carries unit '${d.unit}' but the policy has no unit tag for it (rule 20)`);
          else if (sch && (tag.kind !== sch.kind || tag.currency !== sch.currency || tag.exponent !== sch.exponent)) add('unit-mismatch', 'error', at, `'${name}': policy unit ${JSON.stringify(tag)} differs from the schema's ${JSON.stringify(sch)} (rule 20)`);
        }
      }
    });
  };

  model.predicates.forEach((p, i) => {
    if (p === null || typeof p !== 'object') return;
    check(p, `predicates[${i}]`, false);
    const r = alwaysDenies({ predicates: [p] });
    if (r.alwaysDenies && !r.approximate) add('unreachable-predicate', 'warn', `predicates[${i}]`, 'no action can ever match this predicate');
  });
  model.vetoes.forEach((v, i) => check(v.when, `vetoes[${i}]`, true));

  // a money verb with no ceiling in any predicate that grants it
  for (const s of shapes) {
    const money = Object.entries(s.params).filter(([, d]) => (d.semantic ?? '').startsWith('money.'));
    if (money.length === 0) continue;
    const granting = model.predicates.filter((p) => p.verb === '*' || p.verb === s.verb || (Array.isArray(p.verb) && (p.verb.includes('*') || p.verb.includes(s.verb))));
    if (granting.length === 0) {
      if (o.listUngranted) add('verb-not-granted', 'info', s.verb, `the schema declares '${s.verb}' but no predicate grants it`);
      continue;
    }
    for (const [name] of money) {
      const path = `action.params.${name}`;
      const bounded = (p: Predicate) => (p.where ?? []).some((w) => leaves(isGroupCondition(w) && 'all_of' in w ? { all_of: w.all_of } : w).some((c) => isLeafCondition(c) && c.field === path && ['lt', 'lte', 'eq', 'in'].includes(c.op)));
      if (!granting.every(bounded)) add('unbounded-money', 'warn', s.verb, `'${s.verb}' can move '${name}' with no per-action ceiling in at least one granting predicate`);
    }
  }
  if (o.listUngranted) {
    for (const s of shapes) {
      if ((s.params && Object.values(s.params).some((d) => (d.semantic ?? '').startsWith('money.'))) ) continue;
      const granted = model.predicates.some((p) => p.verb === '*' || p.verb === s.verb || (Array.isArray(p.verb) && (p.verb.includes('*') || p.verb.includes(s.verb))));
      if (!granted) add('verb-not-granted', 'info', s.verb, `the schema declares '${s.verb}' but no predicate grants it`);
    }
  }
  return { ok: findings.every((f) => f.severity !== 'error'), findings };
}
