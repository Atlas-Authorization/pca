// compat.ts - migration shims between the old, disagreeing action vocabularies and the one ActionDef vocabulary
// (spec sections 1 and 10). Old names stay accepted on INPUT for one release; every conversion is total and fails closed.

import { BLAST_PPM, BLAST_RADII, PPM_MAX, REV_RANK, type ActionDef, type BlastRadius, type Effect, type Rev, type UnitDecl } from './def';

// ---- reversibility vocabularies (four today -> one) -------------------------------------------------------------------------

/**
 * Any old reversibility word to the canonical class: `costly` (operations/revocation) is `rate_limited`; the ontology's
 * `read` and `reversible` are `reversible`, `external_send` is `irreversible` (a sent message cannot be unsent);
 * anything else is `irreversible` (fail closed).
 */
export function normalizeReversibility(x: unknown): Rev {
  switch (x) {
    case 'reversible': case 'read': return 'reversible';
    case 'rate_limited': case 'costly': return 'rate_limited';
    case 'irreversible': case 'external_send': return 'irreversible';
    default: return 'irreversible';
  }
}

/** The one place the operations-side word is produced for the revocation staleness table (`rate_limited` -> `costly`). */
export const legacyOperationsClass = (r: Rev): 'reversible' | 'costly' | 'irreversible' => (r === 'rate_limited' ? 'costly' : r);

export const maxRevOf = (a: Rev, b: Rev): Rev => (REV_RANK[a] >= REV_RANK[b] ? a : b);

// ---- units (five today -> one) ----------------------------------------------------------------------------------------------

/** The schema `units` entry and the envelope `UnitTag` (rule 20) are one shape; this is its only producer from a def's unit. */
export function unitTagOf(u: UnitDecl): { kind: string; currency?: string; exponent?: number } | null {
  if (u.kind !== 'money') return { kind: u.kind };
  return typeof u.ccy === 'string' ? { kind: 'money', currency: u.ccy, exponent: u.exp } : null;
}

// ---- blast (a 0..1 float preset -> radius + ppm) -------------------------------------------------------------------------------

/** The smallest radius whose default covers the float, and the integer ppm (rounded; the override only ever raises). */
export function blastOfFloat(x: number): { radius: BlastRadius; ppm: number } {
  const ppm = Math.min(PPM_MAX, Math.max(0, Math.round((Number.isFinite(x) ? x : 1) * 1_000_000)));
  const radius = BLAST_RADII.find((r) => BLAST_PPM[r] >= ppm) ?? 'global';
  return { radius, ppm };
}

/**
 * A legacy float kept EXACTLY: the largest radius whose default does not exceed it, with the ppm override carrying the exact value
 * (the override only raises a radius default, so the effective blast equals the float). Used for the reviewed built-ins, which must
 * never be priced below, or above, what the old catalog said.
 */
export function blastExactOfFloat(x: number): { radius: BlastRadius; ppm: number } {
  const ppm = Math.min(PPM_MAX, Math.max(0, Math.round((Number.isFinite(x) ? x : 1) * 1_000_000)));
  const radius = [...BLAST_RADII].reverse().find((r) => BLAST_PPM[r] <= ppm) ?? 'one';
  return { radius, ppm };
}

// ---- catalog (ActionSpec) -> ActionDef ----------------------------------------------------------------------------------------------

/** The structural shape of `ActionSpec` (kept structural so this package does not import the old catalog). */
export interface CatalogSpecLike {
  connector: string;
  action: string;
  verb: string;
  reversibility: string;
  blastRadius: number;
  amountField?: string;
  resource?: string;
  description: string;
}

const READ_RE = /^(read|get|list|view|search|fetch|head)(_|$)/;
const DELETE_RE = /(^|_)(delete|remove|destroy|drop|purge)(_|$)/;
const SEND_RE = /(^|_)(send|post|publish|notify|email|sms)(_|$)/;

/**
 * Convert an old catalog entry. Effects are inferred conservatively from the action name (an unknown write is `update`, never
 * `read`); an `amountField` becomes a bounded `money.amount` parameter (USD, minor units, option `ccy`/`exp`/`max`);
 * reversibility keeps the spec's class (a trait floor can only raise it); blast maps to the nearest radius. The result is
 * `authored` (the entry was written by the integrator); the 21 built-ins are NOT converted by this shim but hand-reviewed
 * in `./builtin`.
 */
export function fromCatalogSpec(s: CatalogSpecLike, o: { ccy?: string; exp?: number; maxAmount?: number } = {}): ActionDef {
  const effects: Effect[] = [];
  if (s.amountField !== undefined) effects.push('pay');
  if (READ_RE.test(s.action)) effects.push('read');
  if (DELETE_RE.test(s.action)) effects.push('delete');
  if (SEND_RE.test(s.action)) effects.push('send');
  if (effects.length === 0) effects.push('update');
  const params: ActionDef['params'] = {};
  if (s.amountField !== undefined) {
    params[s.amountField] = {
      type: 'integer', role: 'money.amount', min: 0, max: o.maxAmount ?? 100_000_000_000,
      unit: { kind: 'money', ccy: o.ccy ?? 'USD', exp: o.exp ?? 2 },
    };
    params.idempotency_key = { type: 'string', max_len: 128 };
  }
  const b = blastOfFloat(s.blastRadius);
  const wildcard = s.resource === undefined || s.resource === '*';
  return {
    v: 1,
    kind: 'pca-action-def',
    verb: s.verb,
    title: s.description.length > 120 ? s.description.slice(0, 117) + '...' : s.description,
    description: s.description,
    effects,
    resource: { type: s.connector, id: wildcard ? '*' : { prefix: '', class: 'any_safe', len: [1, 128] }, scope: wildcard ? 'set' : 'one' },
    params,
    reversibility: normalizeReversibility(s.reversibility),
    blast: { radius: b.radius, ppm: b.ppm },
    ...(s.amountField !== undefined ? { idempotency: { mode: 'key_param' as const, param: 'idempotency_key' } } : {}),
    review: { state: 'authored' },
  };
}

export const fromCatalog = (specs: readonly CatalogSpecLike[], o?: Parameters<typeof fromCatalogSpec>[1]): ActionDef[] => specs.map((s) => fromCatalogSpec(s, o));
