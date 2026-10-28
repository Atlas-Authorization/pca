import { meetAll, type Decision } from './decision';

/**
 * POLICY CLASSES (NIST NGAC idea: access is granted only if it is allowed in every policy class). A decision is the AND (the
 * `meet`) of the answers of every class consulted. Naming the classes and their revisions in the decision record gives audit
 * "who said no": `denied_by` lists the classes that said deny, `escalated_by` the ones that asked for a principal.
 *
 * Fail-strict: no class consulted is a deny (`no_policy_class`); a malformed list, a duplicate class or an unknown class name is a
 * deny. Classes are reported in the fixed order of {@link POLICY_CLASSES}, so the same inputs give the same record.
 * Total; never throws.
 */
export const POLICY_CLASSES = ['constitution', 'regulatory', 'org', 'blueprint', 'user'] as const;
export type PolicyClass = (typeof POLICY_CLASSES)[number];
export const MAX_POLICY_CLASSES = POLICY_CLASSES.length;

export interface ClassVerdict {
  class: PolicyClass;
  /** The revision of that class's policy the answer was computed under. */
  revision: number;
  /** Digest of that class's policy (or bundle) at that revision. */
  digest: string;
  decision: Decision;
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Null = a well-formed list: closed members, known classes, each at most once. */
export function classVerdictsError(list: unknown): string | null {
  if (!Array.isArray(list)) return 'policy classes must be an array';
  if (list.length > MAX_POLICY_CLASSES) return `more than ${MAX_POLICY_CLASSES} policy classes`;
  const seen = new Set<string>();
  for (const [i, v] of list.entries()) {
    if (!isObj(v)) return `policy_classes[${i}] must be an object`;
    for (const k of Object.keys(v)) if (!['class', 'revision', 'digest', 'decision'].includes(k)) return `policy_classes[${i}] has unknown member '${k}'`;
    if (typeof v.class !== 'string' || !(POLICY_CLASSES as readonly string[]).includes(v.class)) return `policy_classes[${i}].class is not a known class`;
    if (seen.has(v.class)) return `policy class '${v.class}' appears twice`;
    seen.add(v.class);
    if (typeof v.revision !== 'number' || !Number.isSafeInteger(v.revision) || v.revision < 0) return `policy_classes[${i}].revision must be a non-negative safe integer`;
    if (typeof v.digest !== 'string' || v.digest.length === 0 || v.digest.length > 128) return `policy_classes[${i}].digest invalid`;
    if (v.decision !== 'allow' && v.decision !== 'escalate' && v.decision !== 'deny') return `policy_classes[${i}].decision must be allow, escalate or deny`;
  }
  return null;
}

export interface ClassDecision {
  decision: Decision;
  /** The classes consulted, in canonical order. */
  classes: ClassVerdict[];
  denied_by: PolicyClass[];
  escalated_by: PolicyClass[];
  reason?: string;
}

export function decideClasses(list: unknown): ClassDecision {
  try {
    if (Array.isArray(list) && list.length === 0) return { decision: 'deny', classes: [], denied_by: [], escalated_by: [], reason: 'no_policy_class' };
    const e = classVerdictsError(list);
    if (e) return { decision: 'deny', classes: [], denied_by: [], escalated_by: [], reason: `malformed policy classes: ${e}` };
    const order = (c: string) => POLICY_CLASSES.indexOf(c as PolicyClass);
    const classes = [...(list as ClassVerdict[])].sort((a, b) => order(a.class) - order(b.class)).map((v) => ({ class: v.class, revision: v.revision, digest: v.digest, decision: v.decision }));
    return {
      decision: meetAll(classes.map((c) => c.decision)),
      classes,
      denied_by: classes.filter((c) => c.decision === 'deny').map((c) => c.class),
      escalated_by: classes.filter((c) => c.decision === 'escalate').map((c) => c.class),
    };
  } catch {
    return { decision: 'deny', classes: [], denied_by: [], escalated_by: [], reason: 'evaluation error (fail closed)' };
  }
}
