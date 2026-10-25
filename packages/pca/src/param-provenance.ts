import { compareUtf8, hashCanonical } from './hash';
import {
  closedMembers,
  isBoundedString,
  isDigest,
  isParamPath,
  isPlainObject,
  nullRecord,
  resolveParamPath,
  setNested,
} from './intent-artifacts';
import { flowAllowed, isLabelKey, labelsRef, validateFlowRules, validateLabelsWire, verifyLabels, type FlowRules, type LabelKey, type PcaLabels } from './label-receipts';
import { classifyRef, isTaintLevel, joinLabels, labelRank, type TaintLabel, type TaintLevel, type TrustedInputRegistry } from './taint';

/**
 * PER-PARAMETER PROVENANCE (Intent Layer v2 §2.8, §3.13 items 3-4, milestone V7; label refs of §3.16, V14;
 * NORMATIVE conformance rule 17, `primitives.intent_provenance`).
 *
 * The agent declares, in the signed `intent_session.prov` member, which refs each material or critical parameter's
 * value came from. The VERIFIER classifies every ref itself, exactly as the L4 taint functional does (`taint.ts`
 * `classifyRef`): a ref counts only at the label the SERVER vouches for in its trusted-input registry (the offer ids
 * and seller ids it issued in this session, wallet-signed principal input), and anything it cannot vouch for is
 * `agent`. A parameter's provenance prov_d is the JOIN (the least trusted) of its refs' labels; a material or
 * critical parameter with no declared refs is `agent`. So the agent can only RAISE a label, never lower it.
 *
 * Label receipt refs `pca-labels:<receipt ref>#<field path>` (§3.16) name a field of a site-signed `pca-labels`
 * receipt the PCActn commits in `intent_session.labels`. The receipt must be committed, supplied, signed under a
 * pinned key and bound to the session, and must contain the field. The value's provenance is then `first_party`
 * when the receipt was issued by THIS verifier's audience and `tool` otherwise, but ONLY if the parameter value's
 * digest equals the field's `value_digest`; a mismatching value is `agent` (the receipt does not vouch for it). The
 * field's data class attaches to the parameter either way (declaring a class can only add restrictions), and every
 * class must be allowed to flow to this audience (`flowAllowed`).
 *
 * Ω̃ gains the categorical dimension `env.prov.<path>` per material or critical parameter (pca-intent `world.ts`
 * `provenanceDim`): confirmed values are confirmed WITH their provenance (T26).
 */

export const LABEL_REF_PREFIX = 'pca-labels:';
export const MAX_PROV_PATHS = 32;
export const MAX_PROV_REFS = 8;
export const MAX_COMMITTED_LABELS = 16;
/** A `prov` key: one `action.params.<name>` segment (the `intent_session` wire rule), never a prototype name. */
export const PROV_PATH_RE = /^action\.params\.[A-Za-z0-9_]{1,64}$/;
const PROTO_NAMES = new Set(['__proto__', 'constructor', 'prototype']);
export const isProvPath = (k: string): boolean => PROV_PATH_RE.test(k) && !PROTO_NAMES.has(k.slice('action.params.'.length));

export type ParamSensitivity = 'material' | 'critical';
/** What a TAINTED (tool / web / agent) material or critical value triggers. */
export type TaintedMode = 'allow' | 'question' | 'question_typed' | 'deny';

export interface ProvenancePolicy {
  /** The material and critical parameters of this verb (from the action schema; free parameters are absent). */
  params: Record<string, ParamSensitivity>;
  /** The injected trusted-input registry: ref → the level the SERVER vouches for. */
  registry?: Record<string, TaintLevel>;
  /** Pinned label-receipt signers. */
  label_keys?: LabelKey[];
  /** The least trusted level a CRITICAL value may have (more tainted: deny). Default `agent` (no cap). */
  critical_max?: TaintLevel;
  /** Default `question`. */
  material_tainted?: TaintedMode;
  /** Default `question_typed` (§3.13 item 4: a tainted critical value is always a typed-tier question). */
  critical_tainted?: Exclude<TaintedMode, 'allow'>;
  /** Flow rules from the session root (class pattern → sink audiences). Default `{}`. */
  flows?: FlowRules;
}

export interface ProvenanceInput {
  aud: string;
  session: string;
  action: { params?: Record<string, unknown> };
  /** `intent_session.prov` (absent = {}). */
  prov?: unknown;
  /** `intent_session.labels` (absent = []). */
  committed_labels?: unknown;
  /** Receipts delivered alongside the PCActn. */
  labels?: unknown[];
  policy: ProvenancePolicy;
}

export interface ProvenanceDecision {
  /** pass: admit (as far as provenance goes); question: `intent_required`; deny: terminal. */
  outcome: 'pass' | 'question' | 'deny';
  reason?: string;
  /** Minimum friction tier of the question (present iff outcome is question). */
  friction?: 'tap' | 'typed';
  /** prov_d per classified parameter path (declared paths and undeclared material/critical ones the action carries). */
  labels: Record<string, TaintLevel>;
  /** Data classes per parameter path (from label receipts), sorted, de-duplicated. */
  classes: Record<string, string[]>;
  /** `env.prov`: the labels nested by path (`env.prov.action.params.offer_id`). */
  env: Record<string, unknown>;
}

const MODES: readonly TaintedMode[] = ['allow', 'question', 'question_typed', 'deny'];
const TAINTED_RANK = 2; // tool, web, agent

/** Policy sanity (rule 17 step 0). Null = well-formed. */
export function validateProvenancePolicy(p: ProvenancePolicy): string | null {
  if (!isPlainObject(p) || !isPlainObject(p.params)) return 'provenance policy needs a params map';
  const cm = closedMembers(p, ['params'], ['registry', 'label_keys', 'critical_max', 'material_tainted', 'critical_tainted', 'flows'], 'policy');
  if (cm) return cm;
  for (const [k, v] of Object.entries(p.params)) {
    if (!isParamPath(k)) return `policy param '${k}' is not an action.params path`;
    if (v !== 'material' && v !== 'critical') return `policy param '${k}': sensitivity must be material or critical`;
  }
  if (p.registry !== undefined) {
    if (!isPlainObject(p.registry)) return 'registry must be an object';
    for (const [k, v] of Object.entries(p.registry)) if (!isBoundedString(k, 256) || !isTaintLevel(v)) return `registry entry '${k}' must map to a taint level`;
  }
  if (p.label_keys !== undefined) {
    if (!Array.isArray(p.label_keys)) return 'label_keys must be a list';
    for (const k of p.label_keys) if (!isLabelKey(k)) return 'every label key needs site, kid, a 32-byte pk and an optional string pq_pk';
  }
  if (p.critical_max !== undefined && !isTaintLevel(p.critical_max)) return 'critical_max must be a taint level';
  if (p.material_tainted !== undefined && !MODES.includes(p.material_tainted)) return 'material_tainted must be allow | question | question_typed | deny';
  if (p.critical_tainted !== undefined && ((p.critical_tainted as string) === 'allow' || !MODES.includes(p.critical_tainted))) return 'critical_tainted must be question | question_typed | deny';
  if (p.flows !== undefined) {
    const e = validateFlowRules(p.flows);
    if (e) return e;
  }
  return null;
}

/** Validate the `intent_session.prov` member. Null = well-formed. */
export function validateProvWire(prov: unknown): string | null {
  if (!isPlainObject(prov)) return "'prov' must be an object";
  const keys = Object.keys(prov);
  if (keys.length > MAX_PROV_PATHS) return `'prov' holds more than ${MAX_PROV_PATHS} paths`;
  for (const k of keys) {
    if (!isProvPath(k)) return `'prov' key '${k}' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)`;
    const refs = prov[k];
    if (!Array.isArray(refs) || refs.length === 0 || refs.length > MAX_PROV_REFS) return `'prov.${k}' must hold 1..${MAX_PROV_REFS} refs`;
    for (const r of refs) if (!isBoundedString(r, 256)) return `'prov.${k}' refs must be non-empty strings (<= 256 bytes)`;
  }
  return null;
}

/** Parse `pca-labels:<ref>#<field>`; null when malformed. */
export function parseLabelRef(ref: string): { receipt: string; field: string } | null {
  if (typeof ref !== 'string' || !ref.startsWith(LABEL_REF_PREFIX)) return null;
  const rest = ref.slice(LABEL_REF_PREFIX.length);
  const i = rest.indexOf('#');
  if (i < 0) return null;
  const receipt = rest.slice(0, i);
  const field = rest.slice(i + 1);
  return isDigest(receipt) && field.length > 0 ? { receipt, field } : null;
}

const levelOf = (l: TaintLabel): TaintLevel => (isTaintLevel(l.kind) ? l.kind : 'agent');
/** UTF-8 byte order (the canonical-ordering rule), never the default UTF-16 order. */
const sortUtf8 = (xs: string[]): string[] => xs.sort(compareUtf8);

/**
 * NORMATIVE rule 17 (`provenance`). Every failure is `deny`; steps in order, first failure wins:
 *   0. policy sanity ({@link validateProvenancePolicy}); ABSENT optional members are empty / default, PRESENT ones of the
 *      wrong JSON type (`null` included) deny: `prov`, `committed_labels`, `labels`, `action.params` and every optional
 *      policy member;
 *   1. `prov` wire ({@link validateProvWire}: an object of at most 32 keys, each `action.params.<name>` with
 *      <name> in [A-Za-z0-9_]{1,64} and not `__proto__` / `constructor` / `prototype`, each value 1..8 non-empty
 *      strings of at most 256 UTF-8 bytes); `committed_labels` is a list of at most 16 distinct canonical 32-byte
 *      digests;
 *   2. every `prov` path names a parameter the action carries (an own member of `params`);
 *   3. per `prov` path in ascending (bytewise) order, per ref in list order: a `pca-labels:` ref must parse, be
 *      committed, be supplied, verify (wire, suite (`unsupported_suite`), pinned (site, kid), signature), be bound to the session and contain the
 *      field; its label is `first_party` (receipt site = aud) or `tool` (another site) when
 *      sha256-digest(strictCanonical(value)) equals the field's `value_digest`, else `agent`; any other ref gets the
 *      registry's level (own entries only) or `agent`. prov_d = join of the ref labels;
 *   4. every material / critical parameter the action carries and `prov` does not declare: prov_d = `agent`;
 *   5. FLOW: every (class, origin) attached to a parameter must satisfy flowAllowed(flows, class, origin, aud);
 *   6. every CRITICAL parameter: rank(prov_d) <= rank(critical_max);
 *   7. tainted (rank >= tool) critical parameters apply `critical_tainted`, tainted material ones
 *      `material_tainted`: deny → deny; question / question_typed → question (typed if any is question_typed);
 *      otherwise pass;
 *   8. `env.prov` nests every classified path; two classified paths where one is a prefix of the other (possible
 *      through the policy's `params`) deny.
 * Ranks: trusted 0 < first_party 1 < tool 2 < web 3 < agent 4. Never throws.
 */
export function decideParamProvenance(input: ProvenanceInput): ProvenanceDecision {
  const labels = nullRecord<TaintLevel>();
  const classes = nullRecord<string[]>();
  const deny = (reason: string): ProvenanceDecision => ({ outcome: 'deny', reason: `provenance: ${reason}`, labels, classes, env: {} });
  try {
    if (!isPlainObject(input)) return deny('input must be an object');
    const policy = input.policy;
    const pe = validateProvenancePolicy(policy);
    if (pe) return deny(`policy misconfigured (fail closed): ${pe}`);
    // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) deny.
    const prov = input.prov === undefined ? {} : input.prov;
    const we = validateProvWire(prov);
    if (we) return deny(we);
    const committed = input.committed_labels === undefined ? [] : input.committed_labels;
    if (!Array.isArray(committed) || committed.length > MAX_COMMITTED_LABELS) return deny(`committed labels must be a list of at most ${MAX_COMMITTED_LABELS} digests`);
    const committedSet = new Set<string>();
    for (const d of committed) {
      if (!isDigest(d) || committedSet.has(d)) return deny('committed labels must be distinct canonical 32-byte digests');
      committedSet.add(d);
    }
    if (!isPlainObject(input.action)) return deny('action must be an object');
    const params = input.action.params === undefined ? {} : input.action.params;
    if (!isPlainObject(params)) return deny('action.params must be an object');
    const suppliedLabels = input.labels === undefined ? [] : input.labels;
    if (!Array.isArray(suppliedLabels)) return deny('labels must be an array');
    const labelKeys = policy.label_keys === undefined ? [] : policy.label_keys;
    const reg = policy.registry === undefined ? {} : policy.registry;
    const flows = policy.flows === undefined ? {} : policy.flows;
    const provMap = prov as Record<string, string[]>;
    const paths = sortUtf8(Object.keys(provMap));
    for (const p of paths) if (!resolveParamPath(params, p).found) return deny(`prov names '${p}', a parameter the action does not carry`);
    for (const a of paths) for (const b of paths) if (a !== b && b.startsWith(a + '.')) return deny(`prov paths '${a}' and '${b}' overlap`);

    const receipts = new Map<string, unknown>();
    for (const r of suppliedLabels) {
      try {
        if (validateLabelsWire(r) === null) receipts.set(labelsRef(r as PcaLabels), r);
      } catch {
        /* not strictly canonical: no reference, never matches a commitment */
      }
    }
    const registry: TrustedInputRegistry = {
      lookup: (d) => (Object.prototype.hasOwnProperty.call(reg, d) && isTaintLevel(reg[d]) ? { kind: reg[d]! } as TaintLabel : undefined),
    };
    const origins = nullRecord<{ cls: string; origin: string }[]>();

    for (const p of paths) {
      const value = resolveParamPath(params, p).value;
      const refLabels: TaintLabel[] = [];
      for (const ref of provMap[p]!) {
        if (!ref.startsWith(LABEL_REF_PREFIX)) {
          refLabels.push(classifyRef(ref, { registry }));
          continue;
        }
        const lr = parseLabelRef(ref);
        if (!lr) return deny(`malformed label ref on '${p}'`);
        if (!committedSet.has(lr.receipt)) return deny(`label ref on '${p}' names a receipt the PCActn does not commit`);
        const rc = receipts.get(lr.receipt);
        if (rc === undefined) return deny(`label receipt for '${p}' was not supplied`);
        const ve = verifyLabels(rc, labelKeys);
        if (ve) return deny(`label receipt for '${p}': ${ve}`);
        const receipt = rc as PcaLabels;
        if (receipt.session !== input.session) return deny(`label receipt for '${p}' is bound to another session`);
        if (!Object.prototype.hasOwnProperty.call(receipt.fields, lr.field)) return deny(`label receipt for '${p}' has no field '${lr.field}'`);
        const field = receipt.fields[lr.field]!;
        let match = false;
        try {
          match = hashCanonical(value) === field.value_digest;
        } catch {
          match = false;
        }
        refLabels.push(match ? (receipt.site === input.aud ? { kind: 'first_party' } : { kind: 'tool', id: receipt.site }) : { kind: 'agent' });
        (origins[p] ??= []).push({ cls: field.class, origin: receipt.site });
      }
      labels[p] = levelOf(joinLabels(refLabels));
    }
    for (const p of sortUtf8(Object.keys(policy.params))) {
      if (Object.prototype.hasOwnProperty.call(labels, p)) continue;
      if (resolveParamPath(params, p).found) labels[p] = 'agent';
    }
    for (const p of sortUtf8(Object.keys(origins))) {
      classes[p] = sortUtf8([...new Set(origins[p]!.map((o) => o.cls))]);
      for (const o of origins[p]!) {
        if (!flowAllowed(flows, o.cls, o.origin, input.aud)) return deny(`flow: class '${o.cls}' from '${o.origin}' may not reach '${input.aud}' (parameter '${p}')`);
      }
    }
    const capRank = labelRank({ kind: policy.critical_max === undefined ? 'agent' : policy.critical_max } as TaintLabel);
    const sens = (p: string): ParamSensitivity | undefined => (Object.prototype.hasOwnProperty.call(policy.params, p) ? policy.params[p] : undefined);
    for (const p of sortUtf8(Object.keys(labels))) {
      if (sens(p) === 'critical' && labelRank({ kind: labels[p]! } as TaintLabel) > capRank) {
        return deny(`critical parameter '${p}' has provenance '${labels[p]}', above the policy maximum '${policy.critical_max}'`);
      }
    }
    let question = false;
    let typed = false;
    for (const p of sortUtf8(Object.keys(labels))) {
      const s = sens(p);
      if (s === undefined || labelRank({ kind: labels[p]! } as TaintLabel) < TAINTED_RANK) continue;
      const mode: TaintedMode =
        s === 'critical' ? (policy.critical_tainted === undefined ? 'question_typed' : policy.critical_tainted) : policy.material_tainted === undefined ? 'question' : policy.material_tainted;
      if (mode === 'deny') return deny(`tainted ${s} parameter '${p}' (provenance '${labels[p]}') is denied by policy`);
      if (mode === 'question' || mode === 'question_typed') question = true;
      if (mode === 'question_typed') typed = true;
    }
    const env = nullRecord<unknown>();
    for (const p of sortUtf8(Object.keys(labels))) if (!setNested(env, p, labels[p])) return deny(`provenance paths overlap at '${p}'`);
    return question
      ? { outcome: 'question', reason: 'provenance: a tainted value needs the principal (lazy question)', friction: typed ? 'typed' : 'tap', labels, classes, env }
      : { outcome: 'pass', labels, classes, env };
  } catch (e) {
    return deny(`evaluation error (fail closed): ${(e as Error).message}`);
  }
}
