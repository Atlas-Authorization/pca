import {
  REVERSIBILITY_ORDER,
  b64u,
  hashCanonical,
  predicateMatches,
  sha256,
  sign,
  utf8,
  verifyB64u,
  type Caveat,
  type Condition,
  type Predicate,
} from '@atlasauth/pca';
import { DEFAULT_CATALOG, resolveAction, type Catalog } from '@atlasauth/pca/ext/research';
import { toModel } from './enumerate';
import { diffPolicies, type PolicyDiff } from './exposure';
import { policyDigestOf } from './residual';
import { subsumes, admitsConcrete } from './index';
import type { AnalyzerAction, PolicyInput } from './types';

/**
 * LEAST PRIVILEGE FROM OBSERVED BEHAVIOUR (borrowed-ideas item 8, security contract C-250, C-251).
 *
 * `suggestNarrowing(policy, observed)` proposes a narrower replacement for a grant from what its holder really did, plus the
 * unused-permission findings, ranked by blast radius and reversibility. It is a REVIEW artefact, never applied:
 *
 *  - It only narrows. The proposal is built as "the original predicate AND extra conditions", and it is then PROVEN subsumed by
 *    the original with the analyzer (`subsumes`); if that proof is not exact the proposal is withheld, so a poisoned
 *    observation cannot widen anything even by a bug in the builder.
 *  - Only observations from the principal's own ledger (`source: 'ledger'`) count. An action the agent merely CLAIMS to have
 *    done is counted as `rejected` and never used.
 *  - A denied attempt never loosens a grant. It becomes an `AccessRequest` for a human to read and, if they choose, to answer
 *    by minting a new grant. Nothing in this module can apply one.
 *  - An optional decay appends an `expires` caveat so permissions unused after N runs lapse at re-mint.
 */

export interface ObservedAction {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
  /** Where the record came from. Only `ledger` entries (committed, hash-linked) are trusted. */
  source: 'ledger' | 'agent';
  /** `denied` (a request the policy refused, e.g. a dry-run) feeds access requests, never the proposal. */
  outcome?: 'allowed' | 'denied';
  /** Ledger entry digest, carried into the findings for audit. */
  entry?: string;
}

export interface NarrowingOptions {
  /** Headroom above the largest observed numeric value (default 0.1 = 10%). */
  margin?: number;
  /** A parameter is constrained only when at least this many observations carry it (default 5). */
  minSamples?: number;
  /** Largest enum a string parameter may be narrowed to (default 8 distinct values). */
  enumLimit?: number;
  catalog?: Catalog;
  /** Bind the proposal to a goal / task (carried through unchanged). */
  taskBinding?: string;
  /** Decay: the re-minted grant lapses at `nowSec + expiresInSecs`. */
  decay?: { nowSec: number; expiresInSecs: number };
}

export interface UnusedFinding {
  kind: 'unused-predicate' | 'unused-verb' | 'unreached-cap';
  /** Index of the original predicate, or -1 for a caveat. */
  predicate: number;
  verb?: string;
  detail: string;
  blastRadius: number;
  reversibility: string;
  /** Higher = look at it first. */
  rank: number;
}

export interface AccessRequest {
  v: 1;
  kind: 'pca-access-request';
  verb: string;
  resource: string;
  /** One refused request as an example; the parameter values are the holder's own. */
  example_params: Record<string, unknown>;
  denied_count: number;
  /** hashCanonical of the policy the requests were refused under. */
  policy_digest: string;
  task_binding?: string;
}

export interface NarrowingResult {
  /** Observations used / rejected (not from the ledger) / refused attempts. */
  used: number;
  rejected: number;
  denied: number;
  /** The narrower policy, present only when it is proven subsumed by the original. */
  proposal?: PolicyInput;
  /** Why there is no proposal. */
  reason?: string;
  /** The proposal covers every used observation. */
  coversObserved: boolean;
  diff?: PolicyDiff;
  findings: UnusedFinding[];
  accessRequests: AccessRequest[];
  taskBinding?: string;
}

const revWeight = (r: string): number => (REVERSIBILITY_ORDER as readonly string[]).indexOf(r) + 1;

const isObj = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);

function commonPrefix(rs: string[]): string {
  let p = rs[0] ?? '';
  for (const r of rs) {
    let i = 0;
    while (i < p.length && i < r.length && p[i] === r[i]) i++;
    p = p.slice(0, i);
  }
  const cut = p.lastIndexOf('/');
  return cut >= 0 ? p.slice(0, cut + 1) : '';
}

function ceilWithMargin(max: number, margin: number, integer: boolean): number {
  const v = max * (1 + margin);
  return integer ? Math.ceil(v) : v;
}

function upperBoundOf(where: readonly Condition[] | undefined, path: string): number {
  let ub = Infinity;
  for (const c of where ?? []) {
    if (c && typeof c === 'object' && 'field' in c && c.field === path && (c.op === 'lte' || c.op === 'lt') && typeof c.value === 'number') ub = Math.min(ub, c.value);
  }
  return ub;
}

/** Propose a narrower grant from what the holder did, and list what was never used. Never applies anything. */
export function suggestNarrowing(policy: PolicyInput, observed: readonly ObservedAction[], o: NarrowingOptions = {}): NarrowingResult {
  const margin = o.margin ?? 0.1;
  const minSamples = o.minSamples ?? 5;
  const enumLimit = o.enumLimit ?? 8;
  const catalog = o.catalog ?? DEFAULT_CATALOG;
  const model = toModel(policy);
  const digest = policyDigestOf(model);

  const trusted = observed.filter((x) => x.source === 'ledger' && x.outcome !== 'denied');
  const rejected = observed.filter((x) => x.source !== 'ledger').length;
  const refused = observed.filter((x) => x.source === 'ledger' && x.outcome === 'denied');

  const ctxOf = (a: ObservedAction) => ({ action: { verb: a.verb, resource: a.resource, params: a.params ?? {} } });
  const findings: UnusedFinding[] = [];
  const base = Array.isArray((policy as { predicates?: unknown }).predicates) ? (policy as { predicates: Predicate[] }).predicates : [];

  const build = (narrowResources: boolean): Predicate[] => {
    const out: Predicate[] = [];
    base.forEach((p) => {
      const hits = trusted.filter((a) => predicateMatches(p, ctxOf(a)));
      if (hits.length === 0) return;
      const verbs = [...new Set(hits.map((h) => h.verb))].sort();
      const resources = [...new Set(hits.map((h) => h.resource))].sort();
      const next: Predicate = { verb: verbs.length === 1 ? verbs[0]! : verbs };
      if (narrowResources) {
        if (resources.length === 1) next.resource = resources[0]!;
        else {
          const pre = commonPrefix(resources);
          if (pre.length > 1) next.resource = pre + '*';
          else if (p.resource !== undefined) next.resource = p.resource;
        }
      } else if (p.resource !== undefined) next.resource = p.resource;
      const where: Condition[] = [...(p.where ?? [])];
      const names = new Set(hits.flatMap((h) => Object.keys(h.params ?? {})));
      for (const name of [...names].sort()) {
        const path = `action.params.${name}`;
        const vals = hits.map((h) => (h.params ?? {})[name]);
        if (vals.length < minSamples || vals.some((v) => v === undefined)) continue;
        if (vals.every((v) => typeof v === 'number' && Number.isFinite(v))) {
          const nums = vals as number[];
          const ceil = ceilWithMargin(Math.max(...nums), margin, nums.every(Number.isInteger));
          if (ceil < upperBoundOf(p.where, path)) where.push({ field: path, op: 'lte', value: ceil });
        } else if (vals.every((v) => typeof v === 'string')) {
          const set = [...new Set(vals as string[])].sort();
          if (set.length <= enumLimit) where.push({ field: path, op: 'in', value: set });
        }
      }
      if (where.length > 0) next.where = where;
      out.push(next);
    });
    return out;
  };

  base.forEach((p, i) => {
    const hit = trusted.some((a) => predicateMatches(p, ctxOf(a)));
    const verbs = typeof p.verb === 'string' ? [p.verb] : Array.isArray(p.verb) ? p.verb : [];
    if (!hit) {
      const v = verbs[0] ?? '*';
      const s = resolveAction(catalog, v === '*' ? 'unknown.any' : v).spec;
      findings.push({ kind: 'unused-predicate', predicate: i, verb: v, detail: `no observed action used predicate ${i} (${verbs.join(', ') || '*'})`, blastRadius: s.blastRadius, reversibility: s.reversibility, rank: s.blastRadius * revWeight(s.reversibility) });
      return;
    }
    for (const v of verbs) {
      if (v === '*') continue;
      if (!trusted.some((a) => a.verb === v && predicateMatches(p, ctxOf(a)))) {
        const s = resolveAction(catalog, v).spec;
        findings.push({ kind: 'unused-verb', predicate: i, verb: v, detail: `verb ${v} is granted by predicate ${i} but never used`, blastRadius: s.blastRadius, reversibility: s.reversibility, rank: s.blastRadius * revWeight(s.reversibility) });
      }
    }
    for (const c of p.where ?? []) {
      if (isObj(c) && typeof c.field === 'string' && (c.op === 'lte' || c.op === 'lt') && typeof c.value === 'number' && c.field.startsWith('action.params.')) {
        const name = c.field.slice('action.params.'.length);
        const vals = trusted.filter((a) => predicateMatches(p, ctxOf(a))).map((a) => (a.params ?? {})[name]).filter((v): v is number => typeof v === 'number');
        if (vals.length >= minSamples && Math.max(...vals) < c.value / 2) {
          const s = resolveAction(catalog, verbs[0] ?? 'unknown.any').spec;
          findings.push({ kind: 'unreached-cap', predicate: i, ...(verbs[0] ? { verb: verbs[0] } : {}), detail: `${name} <= ${c.value} but the largest observed value is ${Math.max(...vals)}`, blastRadius: s.blastRadius, reversibility: s.reversibility, rank: s.blastRadius * revWeight(s.reversibility) });
        }
      }
    }
  });
  findings.sort((a, b) => b.rank - a.rank || a.predicate - b.predicate);

  const groups = new Map<string, AccessRequest>();
  for (const a of refused) {
    const k = `${a.verb}\u0000${a.resource}`;
    const g = groups.get(k);
    if (g) g.denied_count++;
    else groups.set(k, { v: 1, kind: 'pca-access-request', verb: a.verb, resource: a.resource, example_params: { ...(a.params ?? {}) }, denied_count: 1, policy_digest: digest, ...(o.taskBinding ? { task_binding: o.taskBinding } : {}) });
  }
  const accessRequests = [...groups.values()].sort((a, b) => b.denied_count - a.denied_count || (a.verb < b.verb ? -1 : 1));

  const res: NarrowingResult = { used: trusted.length, rejected, denied: refused.length, coversObserved: false, findings, accessRequests };
  if (o.taskBinding) res.taskBinding = o.taskBinding;

  const caveats: Caveat[] = [...(model.caveats ?? [])];
  if (o.decay) caveats.push({ type: 'expires', at: o.decay.nowSec + o.decay.expiresInSecs });
  const extras = { vetoes: model.vetoes, tighten: model.tighten };
  const original: PolicyInput = policy;
  for (const narrowResources of [true, false]) {
    const proposal: PolicyInput = { predicates: build(narrowResources), caveats, ...extras };
    if (proposal.predicates.length === 0) {
      res.reason = 'no ledger observation matches any predicate';
      return res;
    }
    const proof = subsumes(original, proposal);
    if (proof.subsumes !== true || proof.approximate === true) {
      res.reason = proof.reason ?? 'the proposal could not be proven narrower than the original';
      continue;
    }
    delete res.reason;
    res.proposal = proposal;
    res.coversObserved = trusted.every((a) => admitsConcrete(proposal, { verb: a.verb, resource: a.resource, params: a.params ?? {} } as AnalyzerAction));
    res.diff = diffPolicies(original, proposal);
    return res;
  }
  return res;
}

// ---- access requests ------------------------------------------------------------------------------

export const ACCESS_REQUEST_SIG_DOMAIN = 'atlas-pca/access-request/v1\0';

export interface SignedAccessRequest {
  request: AccessRequest;
  /** The holder's public key (b64u). */
  signer: string;
  sig: string;
}

function requestMessage(r: AccessRequest): Uint8Array {
  const pre = utf8(ACCESS_REQUEST_SIG_DOMAIN);
  const d = sha256(utf8(hashCanonical(r)));
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}

/** The agent's (or its holder's) signed ask. It is a request for a human to read; no function here turns it into authority. */
export function signAccessRequest(r: AccessRequest, secret: Uint8Array, signerPublic: string): SignedAccessRequest {
  return { request: r, signer: signerPublic, sig: b64u(sign(secret, requestMessage(r))) };
}

export function verifyAccessRequest(s: SignedAccessRequest, expectedSigner?: string): boolean {
  try {
    if (!isObj(s) || !isObj(s.request) || s.request.kind !== 'pca-access-request' || s.request.v !== 1) return false;
    if (expectedSigner !== undefined && s.signer !== expectedSigner) return false;
    return typeof s.sig === 'string' && verifyB64u(s.signer, requestMessage(s.request), s.sig);
  } catch {
    return false;
  }
}
