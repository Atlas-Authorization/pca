/* eslint-disable @typescript-eslint/no-explicit-any */
// ext-attest.ts - typed adapter over the PROVED attestation decisions (formal/dafny/Attest.dfy -> generated/pca_attest.js).
//
// The glue here only evaluates primitives (typeof checks, signature verification, canonical binding bytes, clock reads, store calls)
// and interns compared values to integers; every combination decision (N-of-M, required roots, identity reconciliation, binding
// match, stage order / first failure, nonce consumption rule, allowlist rollback / high-water mark, anchored-feed scan) is made by
// the compiled Dafny functions. Reasons are rendered here, byte-identical to the production TypeScript.
//
// Drop-in status (see docs/pca/security/verified-core.md): createMultiRootVerifierVerified, matchAgentBindingVerified,
// verifyAttestationVerified, createAttestationVerifierVerified, VerifiedMemoryNonceStore, verifyAllowlistDurableVerified and
// verifyAllowlistAnchoredVerified are behaviour-identical re-implementations of the production entry points on the inputs the
// differential tests cover; NONE is imported by production code yet.
import { hardenDafnyRuntime } from './runtime';
import BigNumber from 'bignumber.js';

// Minimal structural types (the production types live in @atlasauth/pca, which depends on this package).
export interface MeasuredIdentity {
  model_id: string;
  weights_digest: string;
  weights_measured?: boolean;
  runtime_measurement: string;
  operator: string;
  system_prompt_digest?: string;
  tool_manifest_digest?: string;
}
export interface HardwareAttestationResult {
  ok: boolean;
  reason?: string;
  measured?: MeasuredIdentity;
  bound?: boolean;
  hostAsserted?: Record<string, string>;
}
export interface HardwareAttestationVerifier {
  verify(input: any): Promise<HardwareAttestationResult>;
}
export interface MultiRootAttestationPolicy {
  roots: Array<{ id: string; verifier: HardwareAttestationVerifier; required?: boolean; suite?: string }>;
  threshold: number;
}
export interface AgentBinding {
  model_allowlist?: unknown[];
  min_measurement?: string | { svn: number };
  operator?: string;
  weights_allowlist?: unknown[];
  system_prompt_allowlist?: unknown[];
  tool_manifest_allowlist?: unknown[];
  require_hardware?: boolean;
  require_measured_weights?: boolean;
}
// eslint-disable-next-line @typescript-eslint/no-require-imports
const gen = require('../generated/pca_attest.js') as { _dafny: any; Attest: any };
hardenDafnyRuntime(gen._dafny);
const A = gen.Attest;
const D = gen._dafny;
const DF = A.__default;

const bn = (n: number): BigNumber => {
  if (!Number.isSafeInteger(n)) throw new RangeError(`pca-verified-core/attest: expected a safe integer, got ${String(n)}`);
  return new BigNumber(n);
};
const seqOf = (a: readonly any[]): any => {
  const s = D.Seq.of();
  for (let i = 0; i < a.length; i++) s.push(a[i]);
  return s;
};
const kindName = (k: any): string => String(k).replace(/^.*\./, '').replace(/\(.*$/, '');
const none = (): any => A.Option.create_None();

/** Intern values to positive integers with SameValueZero equality (exactly `Array.prototype.includes` / `Map` semantics). */
class Interner {
  private readonly m = new Map<unknown, number>();
  readonly vals: unknown[] = [undefined];
  id(v: unknown): number {
    let n = this.m.get(v);
    if (n === undefined) {
      n = this.vals.length;
      this.vals.push(v);
      this.m.set(v, n);
    }
    return n;
  }
  /** 0 for anything that is not a non-empty string (the multi-root reconciliation convention). */
  sid(v: unknown): number {
    return typeof v === 'string' && v.length > 0 ? this.id(v) : 0;
  }
}

// ================================================================================================
// A. multi-root N-of-M
// ================================================================================================
export interface AttestationRootLike {
  id: string;
  verifier: HardwareAttestationVerifier;
  required?: boolean;
  suite?: string;
}

const IDENT_FIELDS = ['model_id', 'weights_digest', 'runtime_measurement', 'operator', 'system_prompt_digest', 'tool_manifest_digest'] as const;

/** Build the verified multi-root verifier. Same construction errors, same results, same reason strings as createMultiRootVerifier. */
export function createMultiRootVerifierVerified(policy: MultiRootAttestationPolicy): HardwareAttestationVerifier {
  // Freeze the configuration (as createMultiRootVerifier does): later edits by the caller must not change what this
  // verifier enforces. Each root is copied shallowly; its verifier stays the caller's object (behaviour, not data).
  policy = Object.freeze({
    threshold: policy?.threshold,
    roots: Array.isArray(policy?.roots) ? Object.freeze(policy.roots.map((r) => (r !== null && typeof r === 'object' ? Object.freeze({ ...r }) : r))) : policy?.roots,
  }) as MultiRootAttestationPolicy;

  if (!policy || !Array.isArray(policy.roots) || policy.roots.length === 0) {
    throw new TypeError('createMultiRootVerifier: at least one attestation root is required');
  }
  if (!Number.isInteger(policy.threshold) || policy.threshold < 1 || policy.threshold > policy.roots.length) {
    throw new TypeError('createMultiRootVerifier: threshold must be an integer in [1, roots.length]');
  }
  const ids = new Set<string>();
  for (const r of policy.roots) {
    if (!r || typeof r.id !== 'string' || r.id.length === 0) throw new TypeError('createMultiRootVerifier: each root needs a non-empty id');
    if (ids.has(r.id)) throw new TypeError(`createMultiRootVerifier: duplicate root id '${r.id}'`);
    ids.add(r.id);
  }
  // the verified predicate agrees with the checks above (defence against drift)
  {
    const it = new Interner();
    if (!DF.ValidPolicy(seqOf(policy.roots.map((r) => bn(it.id(r.id)))), bn(policy.threshold))) {
      throw new Error('pca-verified-core/attest: ValidPolicy disagrees with the construction checks');
    }
  }

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        const it = new Interner();
        let st = A.St.create_Running(D.Seq.of());
        const results: Array<HardwareAttestationResult | undefined> = [];
        const hostAsserted: Record<string, string> = {};
        for (let i = 0; i < policy.roots.length; i++) {
          const root = policy.roots[i]!;
          let res: HardwareAttestationResult;
          try {
            res = await root.verifier.verify(input);
          } catch (e) {
            res = { ok: false, reason: `root '${root.id}' threw (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
          }
          results.push(res);
          // a null / undefined / non-object result: the proved model's NullRes (a FAILED root: skipped, or RequiredFailed)
          let rr: any;
          if (res === null || typeof res !== 'object') rr = A.RootRes.create_NullRes();
          else try {
            const okFlag = res.ok === true && res.bound === true;
            const hasMeasured = okFlag && !!res.measured;
            rr = A.RootRes.create_Res(res.ok === true, res.bound === true, !!res.measured, identOf(res.measured, it));
            void hasMeasured;
          } catch (e) {
            const stM = DF.Step(st, bn(i), root.required === true, A.RootRes.create_Malformed());
            st = stM;
            return finish(st, () => `multi-root attestation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
          }
          const next = DF.Step(st, bn(i), root.required === true, rr);
          if (next.is_Done) {
            st = next;
            break;
          }
          st = next;
          if (DF.Passes(rr) && res.hostAsserted) {
            for (const [k, v] of Object.entries(res.hostAsserted)) hostAsserted[`${root.id}.${k}`] = v;
          }
        }
        return finish(st, () => '', results, it, hostAsserted);
      } catch (e) {
        return fail(`multi-root attestation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }

      function finish(
        s: any,
        caught: () => string,
        results?: Array<HardwareAttestationResult | undefined>,
        it?: Interner,
        host?: Record<string, string>,
      ): HardwareAttestationResult {
        const out = DF.Finish(bn(policy.threshold), s);
        if (out.is_MOk) {
          const m = out.dtor_m;
          const v = (f: number): string => {
            const id = Number(f === 0 ? m.dtor_f0 : f === 1 ? m.dtor_f1 : f === 2 ? m.dtor_f2 : f === 3 ? m.dtor_f3 : f === 4 ? m.dtor_f4 : m.dtor_f5);
            return id === 0 ? '' : (it!.vals[id] as string);
          };
          const system_prompt_digest = v(4);
          const tool_manifest_digest = v(5);
          const measured: MeasuredIdentity = {
            model_id: v(0),
            weights_digest: v(1),
            weights_measured: m.dtor_weightsMeasured,
            runtime_measurement: v(2),
            operator: v(3),
            ...(system_prompt_digest !== '' ? { system_prompt_digest } : {}),
            ...(tool_manifest_digest !== '' ? { tool_manifest_digest } : {}),
          };
          return { ok: true, bound: true, measured, ...(Object.keys(host ?? {}).length > 0 ? { hostAsserted: host } : {}) };
        }
        const f = out.dtor_f;
        if (f.is_ErrorCaught) return { ok: false, reason: caught() };
        if (f.is_RequiredFailed) {
          const i = f.dtor_idx.toNumber();
          const ri: unknown = results![i];
          const why = ri === null || typeof ri !== 'object' ? `root '${policy.roots[i]!.id}' returned a malformed result (fail closed)` : ((ri as HardwareAttestationResult).reason ?? 'invalid');
          return { ok: false, reason: `required attestation root '${policy.roots[i]!.id}' failed: ${why}` };
        }
        if (f.is_BelowThreshold) {
          return { ok: false, reason: `multi-root attestation below threshold (${f.dtor_count.toNumber()}/${policy.threshold} independent roots corroborated)` };
        }
        const a = f.dtor_first.toNumber();
        const b = f.dtor_second.toNumber();
        return {
          ok: false,
          reason: `multi-root attestation identity conflict: roots '${policy.roots[a]!.id}' and '${policy.roots[b]!.id}' disagree on ${IDENT_FIELDS[f.dtor_field.toNumber()]}`,
        };
      }
    },
  };

  function identOf(m: any, it: Interner): any {
    // production only reads these when the root passed; reading them for a non-passing root is harmless (no side effects) except
    // for a null `measured`, which is falsy and never dereferenced.
    const g = (k: string): unknown => (m ? m[k] : undefined);
    return A.Ident.create_Ident(
      bn(it.sid(g('model_id'))), bn(it.sid(g('weights_digest'))), bn(it.sid(g('runtime_measurement'))),
      bn(it.sid(g('operator'))), bn(it.sid(g('system_prompt_digest'))), bn(it.sid(g('tool_manifest_digest'))),
      m ? m.weights_measured === true : false,
    );
  }
}

// ================================================================================================
// B. agent-binding match
// ================================================================================================
const REASONS = {
  model: (id: MeasuredIdentity) => `model_id ${id.model_id} not in model_allowlist`,
  op: (id: MeasuredIdentity) => `operator ${id.operator} is not the bound operator`,
  measured: () => `weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)`,
  weights: () => `weights_digest not in weights_allowlist (model swap / fine-tune?)`,
  sys: () => `system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)`,
  tool: () => `tool_manifest_digest not in tool_manifest_allowlist (tools changed?)`,
};

/** A canonical decimal SVN text: "0" or a non-zero digit followed by digits (no sign, spaces, exponent, hex or leading zeros). */
const SVN_TEXT = /^(?:0|[1-9][0-9]*)$/;
/** A minimum SVN: a safe non-negative integer JSON number (not -0). */
const isSvnBound = (x: unknown): x is number => typeof x === 'number' && Number.isSafeInteger(x) && x >= 0 && !Object.is(x, -0);
const OWN_HAS = Object.prototype.hasOwnProperty;
/** True iff `mm` is exactly `{svn: n}` (one own enumerable key, a plain object) with a valid bound. */
function svnSpec(mm: unknown): mm is { svn: number } {
  if (mm === null || typeof mm !== 'object' || Array.isArray(mm)) return false;
  const proto = Object.getPrototypeOf(mm);
  if (proto !== Object.prototype && proto !== null) return false;
  const keys = Object.keys(mm);
  return keys.length === 1 && keys[0] === 'svn' && OWN_HAS.call(mm, 'svn') && isSvnBound((mm as { svn: unknown }).svn);
}
/** The measured SVN, or undefined when `runtime` is not the canonical decimal text of a safe integer. */
function measuredSvn(runtime: unknown): number | undefined {
  if (typeof runtime !== 'string' || !SVN_TEXT.test(runtime)) return undefined;
  const n = Number(runtime);
  return Number.isSafeInteger(n) ? n : undefined;
}
/**
 * min_measurement as the proved MinM (Attest.dfy). Absent or "" constrains nothing; a non-empty string is an equality pin; `{svn: n}`
 * (n a safe non-negative integer JSON number) is the monotone ladder over a canonical decimal runtime_measurement; ANY other present
 * value is MinBad and fails closed (it used to be ignored: `{svn: "5"}` enforced nothing). Never throws.
 */
function minMeasurementDecision(mm: unknown, runtime: unknown): any {
  if (mm === undefined || mm === '') return A.MinM.create_NoMin();
  if (typeof mm === 'string') return A.MinM.create_EqPin(runtime === mm);
  if (!svnSpec(mm)) return A.MinM.create_MinBad();
  const got = measuredSvn(runtime);
  return A.MinM.create_Svn(got === undefined ? A.SvnCheck.create_SvnNotInteger() : got < mm.svn ? A.SvnCheck.create_SvnBelow() : A.SvnCheck.create_SvnOk());
}

/** matchAgentBinding with the decision made by the proved MatchBinding. Same reasons as production. */
export function matchAgentBindingVerified(id: MeasuredIdentity, binding: AgentBinding | undefined): string | null {
  const b = binding ?? {};
  const it = new Interner();
  const list = (x: unknown): any => seqOf(Array.isArray(x) && x.length > 0 ? x.map((e) => bn(it.id(e))) : []);
  const minM = minMeasurementDecision(b.min_measurement, id.runtime_measurement);
  const operatorPinned = typeof b.operator === 'string' && b.operator.length > 0;
  const bid = A.BIdent.create_BIdent(
    bn(it.id(id.model_id)), bn(it.id(id.weights_digest)), id.weights_measured === true,
    typeof id.system_prompt_digest === 'string', bn(it.id(id.system_prompt_digest)),
    typeof id.tool_manifest_digest === 'string', bn(it.id(id.tool_manifest_digest)),
    operatorPinned ? id.operator === b.operator : true,
  );
  const bb = A.Binding.create_Binding(
    list(b.model_allowlist), minM, operatorPinned, b.require_measured_weights === true,
    list(b.weights_allowlist), list(b.system_prompt_allowlist), list(b.tool_manifest_allowlist),
  );
  const r = DF.MatchBinding(bid, bb);
  if (r.is_None) return null;
  const k = kindName(r.dtor_v);
  switch (k) {
    case 'BModel': return REASONS.model(id);
    case 'BMinBad': return `min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)`;
    case 'BMinEq': return `runtime_measurement does not match required min_measurement`;
    case 'BMinSvnNotInt': return `runtime_measurement ${id.runtime_measurement} is not an integer SVN (required min svn ${(b.min_measurement as { svn: number }).svn})`;
    case 'BMinSvnBelow': return `runtime_measurement svn ${measuredSvn(id.runtime_measurement)} is below required min svn ${(b.min_measurement as { svn: number }).svn}`;
    case 'BOperator': return REASONS.op(id);
    case 'BNotMeasured': return REASONS.measured();
    case 'BWeights': return REASONS.weights();
    case 'BSys': return REASONS.sys();
    default: return REASONS.tool();
  }
}

/** requiresAttestation via the proved flag combination. */
export function requiresAttestationVerified(binding: AgentBinding | undefined): boolean {
  const b = binding ?? {};
  const mm = b.min_measurement as unknown;
  // any present min_measurement other than "" constrains (a malformed one fails closed in MatchBinding, so it must also require a document)
  const hasMin = mm !== undefined && mm !== '';
  const ne = (x: unknown): boolean => Array.isArray(x) && x.length > 0;
  return DF.RequiresAttestation(
    A.BindingFlags.create_BindingFlags(ne(b.model_allowlist), hasMin, typeof b.operator === 'string' && b.operator.length > 0, ne(b.weights_allowlist), ne(b.system_prompt_allowlist), ne(b.tool_manifest_allowlist), b.require_hardware === true, b.require_measured_weights === true),
  );
}

/**
 * The proved model of memoryNonceStore (Attest.dfy: MsConsume, SingleUse, LiveNeverEvicted, FullOfLiveRefuses): a consumed nonce is
 * rejected for `retentionMs`; a full store refuses (never evicts a live entry); only aged-out entries are dropped. Same construction
 * checks and messages as production. The proved arithmetic is over integers: `retentionMs` and every `now()` value must be safe
 * integers (Date.now() is); a non-finite clock value is rejected exactly like production, a fractional one throws RangeError.
 */
export class VerifiedMemoryNonceStore {
  private s: any;
  private readonly it = new Interner();
  private readonly clock: () => number;
  constructor(max = 100_000, opts: { retentionMs?: number; now?: () => number } = {}) {
    if (typeof max !== 'number' || !Number.isSafeInteger(max) || max < 1) {
      throw new TypeError('memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)');
    }
    const retention = opts.retentionMs ?? 60 * 60 * 1000;
    if (typeof retention !== 'number' || !Number.isSafeInteger(retention) || retention <= 0) {
      throw new TypeError('memoryNonceStore: retentionMs must be a positive integer (ms)');
    }
    if (!DF.ValidStore(bn(max), bn(retention))) throw new Error('pca-verified-core/attest: ValidStore disagrees with the construction checks');
    this.clock = opts.now ?? (() => Date.now());
    this.s = DF.MsEmpty(bn(max), bn(retention));
  }
  consume(nonce: string): boolean {
    if (typeof nonce !== 'string') return false;
    const t = this.clock();
    if (typeof t !== 'number' || !Number.isSafeInteger(t)) return false; // same as production: integer epoch ms only
    const r = DF.MsConsume(this.s, bn(this.it.id(nonce)), bn(t));
    this.s = r[0];
    return r[1] as boolean;
  }
}

// ================================================================================================
// E. allowlist
// ================================================================================================
export type AllowlistGateKind = 'shape' | 'options' | 'unknown-issuer' | 'alg-mismatch' | 'issuer-expired' | 'bad-signature' | 'not-yet-valid' | 'expired' | 'lifetime-too-long' | 'below-min-version' | 'rollback' | 'conflict';
const AK: Record<string, AllowlistGateKind> = {
  ASshape: 'shape', AOptions: 'options', AUnknownIssuer: 'unknown-issuer', AAlgMismatch: 'alg-mismatch', AIssuerExpired: 'issuer-expired', ABadSig: 'bad-signature',
  ANotYet: 'not-yet-valid', AExpired: 'expired', ALifetime: 'lifetime-too-long', ABelowMin: 'below-min-version', ARollback: 'rollback', AConflict: 'conflict',
};
export interface AllowlistGateFacts {
  shapeOk: boolean; issuerKnown: boolean; algMatches: boolean; issuerLive: boolean; sigOk: boolean;
  nowMs: number; skew: number; notBefore: number; expiresAt: number;
  maxLifetimeMs?: number; minVersion?: number;
  version: number; lastSeenVersion?: number; lastSeenDigest?: string; digest: string;
}
/** The ordered decision of verifyAllowlistManifest after the primitive facts are known. `undefined` == accepted. A non-finite skew / lifetime or a non-integer version option is the proved `options` reject (production: `malformed`); otherwise numerics must be safe integers (skew is floored, negative skew clamps to 0). */
export function allowlistGate(f: AllowlistGateFacts): AllowlistGateKind | undefined {
  // option validity is a glue fact (finite numbers / safe-integer versions, exactly the production checks); the MODEL orders it
  const fin = (x: unknown): boolean => x === undefined || (typeof x === 'number' && Number.isFinite(x));
  const int = (x: unknown): boolean => x === undefined || (typeof x === 'number' && Number.isSafeInteger(x));
  const optionsOk = fin(f.skew) && fin(f.maxLifetimeMs) && int(f.minVersion) && int(f.lastSeenVersion);
  const num = (x: number | undefined, fallback = 0): BigNumber => bn(optionsOk && x !== undefined ? x : fallback);
  const it = new Interner();
  const hasLast = f.lastSeenVersion !== undefined;
  const facts = A.AFacts.create_AFacts(
    f.shapeOk, f.issuerKnown, f.algMatches, f.issuerLive, f.sigOk, optionsOk,
    bn(f.nowMs), optionsOk ? bn(Math.floor(Math.max(0, f.skew))) : bn(0), bn(f.notBefore), bn(f.expiresAt),
    f.maxLifetimeMs !== undefined, optionsOk && f.maxLifetimeMs !== undefined ? bn(Math.floor(f.maxLifetimeMs)) : bn(0), f.minVersion !== undefined, num(f.minVersion),
    bn(f.version), hasLast, num(f.lastSeenVersion), f.lastSeenDigest !== undefined, bn(it.id(f.lastSeenDigest)), bn(it.id(f.digest)),
  );
  const r = DF.AllowVerify(facts);
  return r.is_None ? undefined : AK[kindName(r.dtor_v)];
}


/** Internal bridge for the production drop-ins in test/support/attest-dropins.ts (not part of the public API). */
export const attestBridge = { A, D, DF, bn, seqOf, kindName, none, Interner };
