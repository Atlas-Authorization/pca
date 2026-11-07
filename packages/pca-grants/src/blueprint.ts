import { evaluateAgentCaveats, type Caveat, type CaveatContext } from '@atlasauth/pca';
import { isObj, isSafeInt, isStr, signBody, signerOf, verifyBody } from './sig';

/**
 * AGENT BLUEPRINTS: a fleet ceiling and a group kill for every instance minted from one template.
 *
 * Shape (the Entra Agent ID idea, made verifiable): an operator holds a BLUEPRINT KEY. A grant is delegated to that key
 * (it is the holder of one hop) and the blueprint key delegates to each instance (the issuer of the next hop). So "an
 * instance of blueprint B" is simply "a chain with a hop issued by B's key": no new caveat type, nothing the instance can
 * drop, and an instance the verifier has never seen is still recognised.
 *
 * The operator signs a {@link AgentBlueprint} record: the ceiling, the depth below the blueprint, an expiry, a monotone
 * `epoch` and a `status`. The verifier keeps the newest record per blueprint key ({@link BlueprintRegistry}):
 *  - the CEILING is tighten-only: the effective authority is the chain's caveats AND the ceiling, so the blueprint level can
 *    never be a second place where a grant is widened (a ceiling the verifier cannot evaluate denies);
 *  - `status: 'disabled'` at a higher epoch is the GROUP KILL: every instance, seen or not, is refused by the next check;
 *    re-enabling needs a still higher epoch signed by the operator, and a lower or equal-epoch record never replaces one;
 *  - a verifier whose registry lags the epoch a caller proves it has seen (the `revocation_epoch` of a `fresh_at` token)
 *    escalates (`stale_blueprint_state`), never allows;
 *  - an unreachable store denies.
 *
 * Nothing here verifies the PCActn or its chain; run it beside the verifier (it only gates, it never allows by itself).
 */
export const AGENT_BLUEPRINT_DOMAIN = 'atlas-pca/agent-blueprint/v1\0';
const MAX_CEILING = 32;

export type BlueprintStatus = 'active' | 'disabled';

/** A measured identity an instance may run as: every field present must equal the measured value. */
export interface RuntimePin {
  runtime_measurement?: string;
  model_id?: string;
  weights_digest?: string;
  operator?: string;
  /** The SPIFFE ID of the workload (verified through an SVID, see `@atlasauth/pca-spiffe`). */
  spiffe_id?: string;
}
const PIN_KEYS = ['runtime_measurement', 'model_id', 'weights_digest', 'operator', 'spiffe_id'] as const;

export interface AgentBlueprint {
  v: 1;
  /** Human-readable name; the identity is the key. */
  id: string;
  /** The blueprint key (b64u): the issuer of every instance hop. */
  key: string;
  /** Tighten-only caveats added to every instance's authority. */
  ceiling: Caveat[];
  /** Most hops at and below the blueprint's own instance hop. Absent: unlimited. */
  max_depth?: number;
  /** Epoch ms after which no instance is accepted. Absent: none. */
  expires_at?: number;
  /**
   * Attestation-gated admission: the measured identities an instance may run as. Present: an instance is accepted only after
   * `admitBlueprintInstance` verified hardware evidence matching one pin (see blueprint-admission.ts). Absent: no admission
   * requirement. The native verifiers do not know this member, so they refuse such a record (its signature covers it).
   */
  runtime_pins?: RuntimePin[];
  /** Monotone: a record replaces another only with a strictly higher epoch. */
  epoch: number;
  status: BlueprintStatus;
  issued_at: number;
  /** The operator that signed it (b64u). */
  operator: string;
  sig: string;
}

const bodyOf = (b: Omit<AgentBlueprint, 'sig'>) => ({
  v: b.v, id: b.id, key: b.key, ceiling: b.ceiling, ...(b.max_depth !== undefined ? { max_depth: b.max_depth } : {}),
  ...(b.expires_at !== undefined ? { expires_at: b.expires_at } : {}), ...(b.runtime_pins !== undefined ? { runtime_pins: b.runtime_pins } : {}), epoch: b.epoch, status: b.status, issued_at: b.issued_at, operator: b.operator,
});

export type NewBlueprint = Omit<AgentBlueprint, 'v' | 'sig' | 'operator'>;

/** Sign a blueprint record with the operator's secret. Throws on a malformed record. */
export function signBlueprint(secret: Uint8Array, b: NewBlueprint): AgentBlueprint {
  const base = { v: 1 as const, ...b, operator: signerOf(secret) };
  if (!wellFormed(base)) throw new RangeError('signBlueprint: a malformed blueprint');
  return { ...base, sig: signBody(AGENT_BLUEPRINT_DOMAIN, bodyOf(base), secret) };
}

function wellFormed(b: unknown): b is Omit<AgentBlueprint, 'sig'> {
  if (!isObj(b) || b.v !== 1 || !isStr(b.id, 128) || !isStr(b.key, 128) || !isStr(b.operator, 128)) return false;
  if (!isSafeInt(b.epoch) || !isSafeInt(b.issued_at) || (b.status !== 'active' && b.status !== 'disabled')) return false;
  if (b.max_depth !== undefined && !(isSafeInt(b.max_depth) && b.max_depth >= 1)) return false;
  if (b.expires_at !== undefined && !isSafeInt(b.expires_at)) return false;
  if (b.runtime_pins !== undefined) {
    const p = b.runtime_pins;
    const okPin = (x: unknown): boolean =>
      isObj(x) && Object.keys(x).length > 0 && Object.keys(x).every((k) => (PIN_KEYS as readonly string[]).includes(k) && isStr(x[k], 256));
    if (!Array.isArray(p) || p.length === 0 || p.length > 16 || !p.every(okPin)) return false;
  }
  return Array.isArray(b.ceiling) && b.ceiling.length <= MAX_CEILING && b.ceiling.every((c) => isObj(c) && typeof c.type === 'string');
}

/** Well formed and signed by its `operator` over exactly its content. Never throws. */
export function verifyBlueprint(b: unknown): b is AgentBlueprint {
  if (!wellFormed(b)) return false;
  const { sig, ...rest } = b as AgentBlueprint;
  return verifyBody(AGENT_BLUEPRINT_DOMAIN, bodyOf(rest), rest.operator, sig);
}

export interface BlueprintStore {
  get(key: string): Promise<AgentBlueprint | undefined>;
  put(b: AgentBlueprint): Promise<void>;
  /** The highest epoch across every stored record (0 when empty). */
  maxEpoch(): Promise<number>;
}

export class MemoryBlueprintStore implements BlueprintStore {
  private readonly m = new Map<string, AgentBlueprint>();
  async get(key: string) { const x = this.m.get(key); return x && structuredClone(x); }
  async put(b: AgentBlueprint) { this.m.set(b.key, structuredClone(b)); }
  async maxEpoch() { let e = 0; for (const b of this.m.values()) e = Math.max(e, b.epoch); return e; }
}

export type AcceptCode = 'bad_record' | 'unknown_operator' | 'stale_epoch' | 'epoch_fork' | 'operator_changed';
export type AcceptResult = { ok: true; replaced: boolean } | { ok: false; code: AcceptCode };

export class BlueprintRegistry {
  /** @param operators the operator keys (b64u) whose records this verifier accepts. A record from any other key is refused. */
  constructor(private readonly operators: readonly string[], private readonly store: BlueprintStore) {
    // A disabled blueprint must stay disabled across a restart, so the store is required.
    if (typeof store?.get !== 'function' || typeof store?.put !== 'function' || typeof store?.maxEpoch !== 'function') throw new TypeError('BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintStore is for tests and single-process use)');
  }

  /**
   * Take a signed record. It must verify under a pinned operator, may not change the operator of a known key, and replaces the
   * stored record only with a strictly higher epoch. The same epoch with different content is a fork and is refused (the
   * stored record stays); the identical record again is accepted as a no-op.
   */
  async accept(b: unknown): Promise<AcceptResult> {
    if (!verifyBlueprint(b)) return { ok: false, code: 'bad_record' };
    if (!this.operators.includes(b.operator)) return { ok: false, code: 'unknown_operator' };
    const cur = await this.store.get(b.key);
    if (cur !== undefined) {
      if (cur.operator !== b.operator) return { ok: false, code: 'operator_changed' };
      if (b.epoch < cur.epoch) return { ok: false, code: 'stale_epoch' };
      if (b.epoch === cur.epoch) return cur.sig === b.sig ? { ok: true, replaced: false } : { ok: false, code: 'epoch_fork' };
    }
    await this.store.put(b);
    return { ok: true, replaced: true };
  }

  get(key: string): Promise<AgentBlueprint | undefined> { return this.store.get(key); }
  /** The highest blueprint epoch this verifier has accepted: its contribution to a `fresh_at` `revocation_epoch`. */
  epoch(): Promise<number> { return this.store.maxEpoch(); }
}

export type BlueprintCode =
  | 'no_blueprint' | 'blueprint_disabled' | 'blueprint_expired' | 'too_deep' | 'ceiling_unevaluable' | 'ceiling_violated'
  | 'broken_link' | 'store_unreachable' | 'bad_input' | 'admission_required' | 'not_admitted';
export type BlueprintDecision =
  | { decision: 'allow'; governed: string[] }
  | { decision: 'escalate'; code: 'stale_blueprint_state'; have: number; need: number }
  | { decision: 'deny'; code: BlueprintCode; blueprint?: string; failed?: string[] };

export interface ChainHop { issuer: string; holder: string }

export interface BlueprintCheckOptions {
  now: number;
  /** `require`: the chain must pass through a registered blueprint. `any`: chains that do not are not governed by this check. */
  mode: 'require' | 'any';
  /** The `revocation_epoch` of the newest `fresh_at` token the caller presented. A registry behind it escalates. */
  minEpoch?: number;
  /** Evaluates the ceiling for the action. Default: the core caveat evaluator over `action` and `caveatContext`. */
  evaluateCeiling?: (ceiling: Caveat[], bp: AgentBlueprint) => { ok: boolean; failed?: string[] };
  /** The action being checked (verb, resource, params): used by the default ceiling evaluator. */
  action?: { verb: string; resource: string; params?: Record<string, unknown> };
  caveatContext?: Partial<CaveatContext>;
  /**
   * For a blueprint with `runtime_pins`: is the instance key (the holder of the hop issued by the blueprint key) admitted under
   * this record? Absent while a blueprint has pins: deny `admission_required`. False: deny `not_admitted`. See {@link AdmissionRegistry}.
   */
  admitted?: (instanceKey: string, bp: AgentBlueprint) => boolean | Promise<boolean>;
}

/**
 * Gate a verified chain by its blueprints. `chain` is the capability chain root first. The order of checks is: input, the
 * registry's freshness, then for every hop whose issuer is a registered blueprint key (outermost first): status, expiry, depth,
 * ceiling. The first failure is returned; allow lists the governing blueprints. Only tightens: a pass proves nothing about the
 * chain itself.
 */
export async function checkBlueprints(chain: readonly ChainHop[], registry: BlueprintRegistry, o: BlueprintCheckOptions): Promise<BlueprintDecision> {
  if (!Array.isArray(chain) || chain.length === 0 || !chain.every((h) => isObj(h) && isStr(h.issuer, 128) && isStr(h.holder, 128)) || !isSafeInt(o?.now)) {
    return { decision: 'deny', code: 'bad_input' };
  }
  try {
    if (o.minEpoch !== undefined) {
      const have = await registry.epoch();
      if (have < o.minEpoch) return { decision: 'escalate', code: 'stale_blueprint_state', have, need: o.minEpoch };
    }
    const governed: string[] = [];
    for (let i = 0; i < chain.length; i++) {
      const hop = chain[i] as ChainHop;
      const bp = await registry.get(hop.issuer);
      if (bp === undefined) continue;
      // the hop that creates an instance must be issued to the blueprint key by the hop before it: a gap would mean the key never held the grant
      if (i === 0 || (chain[i - 1] as ChainHop).holder !== bp.key) return { decision: 'deny', code: 'broken_link', blueprint: bp.id };
      if (bp.status !== 'active') return { decision: 'deny', code: 'blueprint_disabled', blueprint: bp.id };
      if (bp.expires_at !== undefined && o.now >= bp.expires_at) return { decision: 'deny', code: 'blueprint_expired', blueprint: bp.id };
      if (bp.max_depth !== undefined && chain.length - i > bp.max_depth) return { decision: 'deny', code: 'too_deep', blueprint: bp.id };
      if (bp.runtime_pins !== undefined) {
        if (o.admitted === undefined) return { decision: 'deny', code: 'admission_required', blueprint: bp.id };
        if ((await o.admitted(hop.holder, bp)) !== true) return { decision: 'deny', code: 'not_admitted', blueprint: bp.id };
      }
      if (bp.ceiling.length > 0) {
        const r = o.evaluateCeiling
          ? o.evaluateCeiling(bp.ceiling, bp)
          : o.action
            ? evaluateAgentCaveats(bp.ceiling, { now: o.now, ...o.caveatContext }, { action: o.action })
            : undefined;
        if (r === undefined) return { decision: 'deny', code: 'ceiling_unevaluable', blueprint: bp.id };
        if (!r.ok) return { decision: 'deny', code: 'ceiling_violated', blueprint: bp.id, failed: r.failed ?? [] };
      }
      governed.push(bp.id);
    }
    if (governed.length === 0 && o.mode === 'require') return { decision: 'deny', code: 'no_blueprint' };
    return { decision: 'allow', governed };
  } catch {
    return { decision: 'deny', code: 'store_unreachable' };
  }
}

/** Anything with `revoke(input)` shaped like `@atlasauth/pca-revoke`'s RevocationRegistry. */
export interface IssuerRevoker {
  revoke(input: { kind: 'issuer'; value: string; reason?: string; revokedAt?: number }): Promise<unknown>;
}

/** Anything shaped like `FreshAtIssuer`: advance the verifier's counters and get the signed token for the write. */
export interface FreshAtAdvancer {
  advance(patch: { revocation_epoch: number }, now: number): unknown;
}

/**
 * GROUP KILL: the operator signs the blueprint as `disabled` at the next epoch; the verifier accepts it and, when given a
 * revocation registry, also revokes the blueprint key as an ISSUER there so verifiers that only read the revocation feed
 * refuse every instance too, and, when given a `FreshAtIssuer`, advances its `revocation_epoch` to the record's epoch and returns
 * the token. Returns the signed record to distribute. The epoch moves strictly forward.
 */
export async function groupKill(
  secret: Uint8Array,
  registry: BlueprintRegistry,
  key: string,
  o: { now: number; reason?: string; revocation?: IssuerRevoker; freshAt?: FreshAtAdvancer },
): Promise<{ ok: true; record: AgentBlueprint; freshAt?: unknown } | { ok: false; code: 'unknown_blueprint' | AcceptCode }> {
  const cur = await registry.get(key);
  if (cur === undefined) return { ok: false, code: 'unknown_blueprint' };
  const { sig: _s, operator: _o, v: _v, ...rest } = cur;
  const record = signBlueprint(secret, { ...rest, status: 'disabled', epoch: cur.epoch + 1, issued_at: o.now });
  const r = await registry.accept(record);
  if (!r.ok) return r;
  if (o.revocation) await o.revocation.revoke({ kind: 'issuer', value: key, reason: o.reason ?? 'blueprint disabled (group kill)', revokedAt: o.now });
  // the kill is a write: it moves the verifier's revocation epoch to the record's, so a request carrying the token cannot be decided on older state
  const freshAt = o.freshAt ? o.freshAt.advance({ revocation_epoch: record.epoch }, o.now) : undefined;
  return { ok: true, record, ...(freshAt !== undefined ? { freshAt } : {}) };
}
