// undo.ts - the undo-window engine over action definitions (docs/pca/specs/undo-windows.md section 3). Reversibility counts
// only when it is CONFIRMED: the definition carries a valid signed review by a pinned reviewer key, its effective class (declared
// joined with every trait floor, and for value-dependent reversibility the class of THESE params) is `reversible`, and it names
// a compensating action that is itself confirmed and can be derived before the effect runs. Anything else is irreversible.
//
// The compensating call is derived, never authored by the agent:
//   verb      the definition's `compensates`
//   resource  the original operation's resource (same resource type, else not derivable)
//   params    the original params the compensating definition declares under the same name and type
//   target    the compensating definition's resource-id parameter (role `id.<type>`), when the original params do not carry it:
//             filled at execution from the original effect's result (the created object's id)
//   idempotency  the compensating definition's key parameter is the attempt key (`UndoCompensationCall.idempotencyKey`)
// Any other required parameter of the compensating definition makes the action not undoable (lint LD-010 reports it).

import { approvalRenderDigest, type ApprovalRender, type PcaOperation, type UndoEngine, type UndoPlan } from '@atlasauth/pca';
import { isReadOnly, type ActionDef, type ParamDef, type Rev } from './def';
import { CORE_REGISTRY } from './core-traits';
import { defDigest } from './digest';
import { effective, isConfirmed, type ReviewOpts } from './effective';
import { normalize } from './normalize';
import { renderApproval } from './approval-render';
import { attestationVerifier } from './import/review';
import type { ReviewerPins } from './confirmation';
import type { Registry } from './traits';

/** The class of a reversibility declaration for concrete params (an unmapped or absent value takes `default`, else irreversible). */
export function reversibilityFor(d: ActionDef, params: Record<string, unknown>): Rev {
  const r = normalize(d).reversibility;
  if (typeof r === 'string') return r;
  const v = Object.prototype.hasOwnProperty.call(params, r.by) ? params[r.by] : undefined;
  const k = typeof v === 'string' ? v : typeof v === 'boolean' || (typeof v === 'number' && Number.isSafeInteger(v)) ? String(v) : null;
  return k !== null && Object.prototype.hasOwnProperty.call(r.map, k) ? r.map[k]! : (r.default ?? 'irreversible');
}

/** True when some value of the declaration is `reversible` (a fixed class, a map value or the default). */
export function mayBeReversible(d: Pick<ActionDef, 'reversibility'>): boolean {
  const r = d.reversibility;
  if (r === undefined) return false;
  if (typeof r === 'string') return r === 'reversible';
  return Object.values(r.map).includes('reversible') || r.default === 'reversible';
}

const sameType = (a: ParamDef | undefined, b: ParamDef): boolean => a !== undefined && a.type === b.type && (a.items ?? null) === (b.items ?? null);

export interface CompensationShape {
  /** The parameters copied from the original call. */
  copied: string[];
  /** The compensating definition's resource-id parameter filled from the effect's result, when needed. */
  target?: string;
}

/**
 * Can `comp` undo `orig` without the agent's help? Null with the shape when it can, else the reason. Structural only (no
 * confirmation): the linter (LD-010) and the engine share it.
 */
export function compensationShape(orig: ActionDef, comp: ActionDef): { ok: true; shape: CompensationShape } | { ok: false; reason: string } {
  if (isReadOnly(comp.effects)) return { ok: false, reason: `the compensating action ${comp.verb} only reads` };
  if (comp.resource.type !== orig.resource.type) return { ok: false, reason: `the compensating action ${comp.verb} acts on ${comp.resource.type}, not ${orig.resource.type}` };
  const nc = normalize(comp);
  const copied: string[] = [];
  let target: string | undefined;
  // the compensation's own idempotency key is the attempt key the coordinator hands the executor, never the original's
  const idem = nc.idempotency.mode === 'key_param' ? nc.idempotency.param : undefined;
  for (const [name, p] of Object.entries(nc.params).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (name === idem) continue;
    if (sameType(orig.params[name], p)) {
      copied.push(name);
      continue;
    }
    if (!p.required) continue;
    if (p.role === `id.${comp.resource.type}` && target === undefined) {
      target = name;
      continue;
    }
    return { ok: false, reason: `the compensating action ${comp.verb} needs '${name}', which neither the original call nor its result supplies` };
  }
  return { ok: true, shape: { copied, ...(target !== undefined ? { target } : {}) } };
}

export interface UndoEngineOptions {
  /** The verifier's pinned action definitions (with their review attestations). */
  defs: readonly ActionDef[];
  /** The reviewer keys a confirmation must be signed by. No pins: nothing is confirmed, nothing is undoable. */
  pins: ReviewerPins | undefined;
  registry?: Registry;
}

/**
 * The {@link UndoEngine} for `createUndoCoordinator`: answers only from confirmed definitions (see the module comment). Exact
 * verb match only (an alias never confers reversibility). Never throws: anything it cannot decide is "not undoable".
 */
export function undoEngine(o: UndoEngineOptions): UndoEngine {
  const reg = o.registry ?? CORE_REGISTRY;
  const byVerb = new Map<string, ActionDef>();
  for (const d of o.defs) if (!byVerb.has(d.verb)) byVerb.set(d.verb, d);
  const review: ReviewOpts = o.pins === undefined ? {} : { attestationVerified: attestationVerifier({ pins: o.pins, registry: reg }) };
  const confirmed = (d: ActionDef): boolean => {
    try {
      return isConfirmed(d, review);
    } catch {
      return false;
    }
  };
  return {
    plan(op: PcaOperation): UndoPlan | null {
      try {
        const d = byVerb.get(op.verb);
        const params = op.params ?? {};
        if (!d || !confirmed(d) || isReadOnly(d.effects) || d.compensates === undefined) return null;
        if (effective(d, reg, review).eff.rev !== 'reversible' || reversibilityFor(d, params) !== 'reversible') return null;
        const c = byVerb.get(d.compensates);
        if (!c || !confirmed(c)) return null;
        const s = compensationShape(d, c);
        if (!s.ok) return null;
        const cparams: Record<string, unknown> = {};
        const nc = normalize(c);
        for (const k of s.shape.copied) {
          if (Object.prototype.hasOwnProperty.call(params, k)) cparams[k] = structuredClone(params[k]);
          else if (nc.params[k]!.required) return null; // the call left out what the undo needs
        }
        // an action that cannot be shown completely is never put to a human, so it gets no window either
        const render: ApprovalRender = renderApproval(d, params, review);
        return {
          def_digest: defDigest(d),
          compensation: { verb: c.verb, params: cparams, def_digest: defDigest(c), ...(s.shape.target !== undefined ? { target_param: s.shape.target } : {}) },
          render,
          render_digest: approvalRenderDigest(render),
        };
      } catch {
        return null;
      }
    },
  };
}
