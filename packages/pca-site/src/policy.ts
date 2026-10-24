import { taint } from '@atlasauth/pca';
import { isB64u32 } from '@atlasauth/pca-wallet';
import { parseTierRule, type TierRule } from './tiers';

/**
 * THE VERIFIER POLICY A SITE SETS (docs/specs/pca-intent-layer-v2.md §5). Every member is optional; a missing member
 * means the default shown in §5; an UNKNOWN member is a configuration error that fails closed (this parser throws).
 *
 * This package enforces `tiers` (per-verb required tier, rate, JIT, bond) and `web_bot_auth` itself. The intent,
 * session, schema, lazy, provenance, oracle, classifier, frame and accumulator members are validated here and handed to
 * the intent port, whose real checks are the V3/V5–V9 verifier modules (owned elsewhere).
 */

export interface SitePolicy {
  v: 2;
  intent: { require: boolean; max_residual_risk_ppm: number; replay: 'never' | 'on_first_use' | 'always'; max_prior_admitted_ppm: number };
  session: { require: boolean; principal_signed_deltas_only: true; max_revocation_age_s: number; accept_sequencers: string[] };
  schema: { digest?: string; accept_previous_for_s: number; closed_world: boolean };
  tiers: Record<string, TierRule>;
  lazy: { enabled: boolean; deliver: 'wallet_direct' | 'agent_relay'; question_ttl_s: number; max_questions_per_session: number };
  provenance: { critical_max: taint.TaintLevel; material_tainted: 'allow' | 'question' | 'question_typed' | 'deny' };
  oracles: Record<string, unknown>;
  classifiers: Record<string, unknown>;
  frame: { monitor: string[]; on_violation: 'veto' | 'veto_and_alert' };
  evidence: { store: boolean; retain_days: number; anchor: 'atlas' | 'none' };
  web_bot_auth: { accept: boolean; directory?: string };
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isNat = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

function section(v: unknown, name: string, keys: readonly string[]): Record<string, unknown> {
  if (v === undefined) return {};
  if (!isObj(v)) throw new TypeError(`policy.${name}: must be an object`);
  for (const k of Object.keys(v)) if (!keys.includes(k)) throw new TypeError(`policy.${name}: unknown member "${k}"`);
  return v;
}

function bool(v: unknown, d: boolean, where: string): boolean {
  if (v === undefined) return d;
  if (typeof v !== 'boolean') throw new TypeError(`policy.${where} must be a boolean`);
  return v;
}

function nat(v: unknown, d: number, where: string, max = Number.MAX_SAFE_INTEGER): number {
  if (v === undefined) return d;
  if (!isNat(v) || v > max) throw new TypeError(`policy.${where} must be an integer in [0, ${max}]`);
  return v;
}

function oneOf<T extends string>(v: unknown, d: T, allowed: readonly T[], where: string): T {
  if (v === undefined) return d;
  if (typeof v !== 'string' || !(allowed as readonly string[]).includes(v)) throw new TypeError(`policy.${where} must be one of ${allowed.join(', ')}`);
  return v as T;
}

function strings(v: unknown, where: string): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || !v.every((s) => typeof s === 'string' && s.length > 0)) throw new TypeError(`policy.${where} must be an array of non-empty strings`);
  return [...v] as string[];
}

const TOP = ['v', 'intent', 'session', 'schema', 'tiers', 'lazy', 'provenance', 'oracles', 'classifiers', 'frame', 'evidence', 'web_bot_auth'];

/** Parse and default a §5 policy. Throws on any unknown member or ill-typed value. */
export function parseSitePolicy(raw: unknown = {}): SitePolicy {
  if (!isObj(raw)) throw new TypeError('policy: must be an object');
  for (const k of Object.keys(raw)) if (!TOP.includes(k)) throw new TypeError(`policy: unknown member "${k}"`);
  if (raw.v !== undefined && raw.v !== 2) throw new TypeError('policy.v must be 2');

  const i = section(raw.intent, 'intent', ['require', 'max_residual_risk_ppm', 'replay', 'max_prior_admitted_ppm']);
  const s = section(raw.session, 'session', ['require', 'principal_signed_deltas_only', 'max_revocation_age_s', 'accept_sequencers']);
  if (s.principal_signed_deltas_only !== undefined && s.principal_signed_deltas_only !== true) {
    throw new TypeError('policy.session.principal_signed_deltas_only: true is the only conforming value');
  }
  const sc = section(raw.schema, 'schema', ['digest', 'accept_previous_for_s', 'closed_world']);
  if (sc.digest !== undefined && !isB64u32(sc.digest)) throw new TypeError('policy.schema.digest must be canonical base64url (32 bytes)');
  if (sc.closed_world === false) throw new TypeError('policy.schema.closed_world: a v2 verifier is closed-world (true is the only conforming value)');
  const lz = section(raw.lazy, 'lazy', ['enabled', 'deliver', 'question_ttl_s', 'max_questions_per_session']);
  const pv = section(raw.provenance, 'provenance', ['critical_max', 'material_tainted']);
  const fr = section(raw.frame, 'frame', ['monitor', 'on_violation']);
  const ev = section(raw.evidence, 'evidence', ['store', 'retain_days', 'anchor']);
  const wb = section(raw.web_bot_auth, 'web_bot_auth', ['accept', 'directory']);
  if (wb.directory !== undefined && (typeof wb.directory !== 'string' || !/^https?:\/\//.test(wb.directory))) throw new TypeError('policy.web_bot_auth.directory must be an absolute http(s) URL');

  const tiers: Record<string, TierRule> = {};
  if (raw.tiers !== undefined) {
    if (!isObj(raw.tiers)) throw new TypeError('policy.tiers: must be an object');
    for (const [verb, rule] of Object.entries(raw.tiers)) {
      if (verb.length === 0) throw new TypeError('policy.tiers: empty verb');
      tiers[verb] = parseTierRule(rule, `policy.tiers.${verb}`);
    }
  }
  const opaque = (v: unknown, where: string): Record<string, unknown> => {
    if (v === undefined) return {};
    if (!isObj(v)) throw new TypeError(`policy.${where} must be an object`);
    return { ...v };
  };

  return {
    v: 2,
    intent: {
      require: bool(i.require, true, 'intent.require'),
      max_residual_risk_ppm: nat(i.max_residual_risk_ppm, 20000, 'intent.max_residual_risk_ppm', 1_000_000),
      replay: oneOf(i.replay, 'on_first_use', ['never', 'on_first_use', 'always'] as const, 'intent.replay'),
      max_prior_admitted_ppm: nat(i.max_prior_admitted_ppm, 0, 'intent.max_prior_admitted_ppm', 1_000_000),
    },
    session: {
      require: bool(s.require, true, 'session.require'),
      principal_signed_deltas_only: true,
      max_revocation_age_s: nat(s.max_revocation_age_s, 60, 'session.max_revocation_age_s'),
      accept_sequencers: strings(s.accept_sequencers, 'session.accept_sequencers'),
    },
    schema: {
      ...(sc.digest !== undefined ? { digest: sc.digest as string } : {}),
      accept_previous_for_s: nat(sc.accept_previous_for_s, 86400, 'schema.accept_previous_for_s'),
      closed_world: true,
    },
    tiers,
    lazy: {
      enabled: bool(lz.enabled, true, 'lazy.enabled'),
      deliver: oneOf(lz.deliver, 'wallet_direct', ['wallet_direct', 'agent_relay'] as const, 'lazy.deliver'),
      question_ttl_s: nat(lz.question_ttl_s, 900, 'lazy.question_ttl_s'),
      max_questions_per_session: nat(lz.max_questions_per_session, 6, 'lazy.max_questions_per_session'),
    },
    provenance: {
      critical_max: oneOf(pv.critical_max, 'first_party', taint.TAINT_LEVELS, 'provenance.critical_max'),
      material_tainted: oneOf(pv.material_tainted, 'question_typed', ['allow', 'question', 'question_typed', 'deny'] as const, 'provenance.material_tainted'),
    },
    oracles: opaque(raw.oracles, 'oracles'),
    classifiers: opaque(raw.classifiers, 'classifiers'),
    frame: {
      monitor: strings(fr.monitor, 'frame.monitor'),
      on_violation: oneOf(fr.on_violation, 'veto_and_alert', ['veto', 'veto_and_alert'] as const, 'frame.on_violation'),
    },
    evidence: {
      store: bool(ev.store, true, 'evidence.store'),
      retain_days: nat(ev.retain_days, 540, 'evidence.retain_days'),
      anchor: oneOf(ev.anchor, 'atlas', ['atlas', 'none'] as const, 'evidence.anchor'),
    },
    web_bot_auth: {
      accept: bool(wb.accept, false, 'web_bot_auth.accept'),
      ...(wb.directory !== undefined ? { directory: wb.directory as string } : {}),
    },
  };
}
