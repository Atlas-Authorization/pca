// approval-render.ts - the canonical approval render of an action (K7, security contract C-460..C-465).
// What you see is what you sign: the render is a deterministic, locale-free field list made ONLY from the ActionDef and the executed
// parameters. The approval challenge commits to H(R) (see @atlasauth/pca approval-render). Completeness is structural: EVERY supplied
// parameter is a field, so a value-bearing, recipient or permission-granting parameter can never be left off the screen, and a
// parameter the definition does not declare is refused (closed world). A model never produces any part of it.

import { approvalRenderDigest, hasLoneSurrogate, paramsDigest, type ApprovalRender, type RenderField, type RenderUnit } from '@atlasauth/pca';
import { ActionKitError, MAX_PARAM_PATH_DEPTH, type ActionDef } from './def';
import { defDigest } from './digest';
import { isConfirmed, type ReviewOpts } from './effective';
import { normalize } from './normalize';

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Nested plain objects become dotted keys (up to MAX_PARAM_PATH_DEPTH segments); arrays and scalars are leaves. A key that itself
 * contains a dot is refused: `{"to.iban": x}` and `{to: {iban: x}}` would otherwise render alike.
 */
function flattenForRender(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const walk = (prefix: string, depth: number, v: unknown): void => {
    const plain = v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
    if (plain && depth < MAX_PARAM_PATH_DEPTH && Object.keys(v as object).length > 0) {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        if (k.includes('.')) throw new ActionKitError('render_bad_params', `the parameter key '${k}' contains a dot`);
        walk(prefix === '' ? k : `${prefix}.${k}`, depth + 1, x);
      }
    } else out[prefix] = v;
  };
  for (const [k, v] of Object.entries(params)) {
    if (k.includes('.')) throw new ActionKitError('render_bad_params', `the parameter key '${k}' contains a dot`);
    walk(k, 1, v);
  }
  return out;
}

/** Is `v` a value of the declared parameter type, inside the strict canonical domain (strings without lone surrogates, safe integers, no floats, no null)? */
function valueOk(type: string, v: unknown): boolean {
  switch (type) {
    case 'integer': case 'duration': return typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
    case 'boolean': return typeof v === 'boolean';
    case 'string': case 'date': case 'datetime': case 'object_ref': return typeof v === 'string' && !hasLoneSurrogate(v);
    case 'set': case 'array': return Array.isArray(v) && v.every(canonicalLeaf);
    default: return false;
  }
}
const canonicalLeaf = (v: unknown): boolean =>
  typeof v === 'string' ? !hasLoneSurrogate(v) : typeof v === 'boolean' || (typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0)) || (Array.isArray(v) && v.every(canonicalLeaf));

/**
 * R = render(ActionDef, params). Throws ActionKitError (`render_undeclared_param`, `render_missing_param`, `render_bad_value`, `render_bad_params`,
 * `render_unresolved_currency`) rather than render something partial. `unreviewed` is true unless the def carries a valid signed
 * confirmation (`opts.attestationVerified`): single-tap approval is then forbidden, and the digest differs from the confirmed render.
 */
export function renderApproval(def: ActionDef, params: Record<string, unknown>, opts: ReviewOpts = {}): ApprovalRender {
  if (params === null || typeof params !== 'object' || Array.isArray(params)) throw new ActionKitError('render_bad_params', 'params must be an object');
  const n = normalize(def);
  const flat = flattenForRender(params);
  for (const k of Object.keys(flat)) if (!Object.prototype.hasOwnProperty.call(n.params, k)) throw new ActionKitError('render_undeclared_param', `'${k}' is not a parameter of ${n.verb}`);
  for (const [k, p] of Object.entries(n.params)) if (p.required && !Object.prototype.hasOwnProperty.call(flat, k)) throw new ActionKitError('render_missing_param', `required parameter '${k}' of ${n.verb} is missing`);
  const fields: RenderField[] = Object.keys(flat).sort(cmp).map((id) => {
    const p = n.params[id]!;
    if (!valueOk(p.type, flat[id])) throw new ActionKitError('render_bad_value', `'${id}' is not a ${p.type} in the canonical domain (no floats, no null, no lone surrogates)`);
    const f: RenderField = { id, class: p.role ?? 'param', value: flat[id] };
    const u = p.unit;
    if (u !== undefined) {
      let unit: RenderUnit;
      if (u.kind === 'money') {
        const ccy = typeof u.ccy === 'string' ? u.ccy : flat[u.ccy.from];
        if (typeof ccy !== 'string' || ccy.length === 0) throw new ActionKitError('render_unresolved_currency', `the currency of '${id}' is not a string`);
        unit = { kind: 'money', ccy, exp: u.exp };
      } else unit = { kind: u.kind };
      f.unit = unit;
    }
    return f;
  });
  return { v: 1, kind: 'pca-approval-render', verb: n.verb, def_digest: defDigest(def), unreviewed: !isConfirmed(def, opts), fields };
}

/**
 * H(R) for an executed action: the verifier's own recomputation. Refuses (throws) unless the params really are the ones the PCActn
 * signed (`params_digest`) and the verb is the PCActn's verb, so an approval can only ever be checked against what will run.
 */
export function renderDigestForAction(def: ActionDef, params: Record<string, unknown>, pcactn: { action: { verb: string; params_digest?: string } }, opts: ReviewOpts = {}): string {
  if (pcactn.action.verb !== def.verb) throw new ActionKitError('render_verb_mismatch', `the PCActn is for '${pcactn.action.verb}', the definition for '${def.verb}'`);
  if (pcactn.action.params_digest !== paramsDigest(params)) throw new ActionKitError('render_params_mismatch', 'the supplied params are not the params the PCActn signed');
  return approvalRenderDigest(renderApproval(def, params, opts));
}

/**
 * The approver client's check before it signs: re-render from the PINNED definition and the displayed params, and require the
 * digest the request carries. Returns the digest to sign; throws on any mismatch (never sign what you cannot reproduce).
 */
export function approverRenderCheck(def: ActionDef, params: Record<string, unknown>, requestedRenderDigest: string, opts: ReviewOpts = {}): string {
  const d = approvalRenderDigest(renderApproval(def, params, opts));
  if (d !== requestedRenderDigest) throw new ActionKitError('render_mismatch', 'the approval request commits to a render this definition and these params do not produce');
  return d;
}

/** Single-tap (one-gesture) approval is allowed only for a confirmed definition. */
export const singleTapAllowed = (r: ApprovalRender): boolean => !r.unreviewed;

/**
 * The step-up renderer, derived from the PINNED action definitions (the policy card): `reviewAction(agent, verb, resource, params,
 * { renderer: renderersFromDefs(defs, review) })`. The definition is found by verb (or alias); a verb with no pinned definition throws,
 * which makes the review a deny (an action that cannot be displayed completely is never put to a human). `review` decides whether a
 * definition counts as confirmed (see `renderApproval`).
 */
export function renderersFromDefs(defs: readonly ActionDef[], review: ReviewOpts = {}): (verb: string, resource: string, params: Record<string, unknown> | undefined) => ApprovalRender {
  const byVerb = new Map<string, ActionDef>();
  for (const d of defs) {
    byVerb.set(d.verb, d);
    for (const a of d.aliases ?? []) if (!byVerb.has(a)) byVerb.set(a, d);
  }
  return (verb, _resource, params) => {
    const d = byVerb.get(verb);
    if (d === undefined) throw new ActionKitError('render_unknown_verb', `no pinned action definition for '${verb}'`);
    return renderApproval(d, params ?? {}, review);
  };
}
