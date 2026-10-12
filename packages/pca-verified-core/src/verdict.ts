/* eslint-disable @typescript-eslint/no-explicit-any */
import { Common, Verdict, bn, fromOpt, fromSeq, fromStatus, none, num, opt, seq, some, toStatus, D, wrapRes, type Res, type Status } from './bridge';

// ---------------------------------------------------------------------------------------------
// Per-check decisions (formal/dafny/Verdict.dfy, section A). Pure functions of pre-evaluated facts.
// ---------------------------------------------------------------------------------------------
const V = Verdict.__default;

/** audience: `arg` is how the verifier supplied its own audience (absent / explicit null opt-out / a string). */
export function audienceStatus(hasAud: boolean, arg: 'absent' | 'null' | 'string', equal: boolean): Status {
  const a = arg === 'absent' ? Verdict.AudArg.create_AudAbsent() : arg === 'null' ? Verdict.AudArg.create_AudNull() : Verdict.AudArg.create_AudStr();
  return toStatus(V.AudienceStatus(hasAud, a, equal));
}

export type ValidityOutcome = 'pass' | 'bad-clock' | 'not-greater' | 'too-long' | 'future' | 'expired';
/** Window check. `iat`/`exp` are wire-validated safe integers; `clockOk` is false when the verifier clock is not a safe integer. */
export function validityDecision(clockOk: boolean, iat: number, exp: number, now: number): ValidityOutcome {
  const r = V.ValidityDecision(clockOk, bn(iat), bn(exp), bn(clockOk ? now : 0));
  return r.is_VPass ? 'pass' : r.is_VBadClock ? 'bad-clock' : r.is_VNotGreater ? 'not-greater' : r.is_VTooLong ? 'too-long' : r.is_VFuture ? 'future' : 'expired';
}
export const PCACTN_MAX_LIFETIME_MS_VERIFIED = num(Verdict.__default.MaxLifetimeMs ?? bn(3_600_000));
export const PCACTN_MAX_SKEW_MS_VERIFIED = num(Verdict.__default.MaxSkewMs ?? bn(60_000));

export const versionStatus = (versionOk: boolean): Status => toStatus(V.VersionStatus(versionOk));
export const grantRefBoundStatus = (grantRefNonEmptyString: boolean, rootIdIsString: boolean, equal: boolean): Status =>
  toStatus(V.GrantRefBoundStatus(grantRefNonEmptyString, rootIdIsString, equal));
export const counterStatus = (nonNegSafeInt: boolean): Status => toStatus(V.CounterStatus(nonNegSafeInt));

export type SuiteViolation = 'not-allowed' | 'no-pq-commitment' | 'pq-mismatch';
const viol = (o: any): SuiteViolation | undefined => (o.is_None ? undefined : o.dtor_v.is_NotAllowed ? 'not-allowed' : o.dtor_v.is_NoPqCommitment ? 'no-pq-commitment' : 'pq-mismatch');
/** F-4: with a suite policy set the alg must be listed. */
export const suitePolicy = (policyDefined: boolean, algAllowed: boolean): SuiteViolation | undefined => viol(V.SuitePolicy(policyDefined, algAllowed));
/** F-2 / R2-01: a PQ-key suite is accepted only under a matching holder_pq commitment (unless the legacy opt-out is set). */
export const pqBinding = (needsPqKey: boolean, allowUnbound: boolean, committed: boolean, matches: boolean): SuiteViolation | undefined =>
  viol(V.PqBinding(needsPqKey, allowUnbound, committed, matches));

export type PqResolution = 'refused' | 'trusted' | 'pinned' | 'committed' | 'unbound';
/**
 * Where may a PQ verification key come from (R2-01 / R3-01 choke point)? `trusted`: the verifier's own configured key;
 * `artifactKeyOk`: the artifact carries a non-empty string key; `pinPresent`/`pinEquals`: a pin exists for the identity and
 * equals the artifact key; `commitPresent`/`commitMatches`: the holder_pq commitment exists and the artifact key hashes to it.
 */
export function pqResolve(f: { trusted: boolean; artifactKeyOk: boolean; pinPresent: boolean; pinEquals: boolean; commitPresent: boolean; commitMatches: boolean; allowUnbound: boolean }): PqResolution {
  const r = V.PqResolve(f.trusted, f.artifactKeyOk, f.pinPresent, f.pinEquals, f.commitPresent, f.commitMatches, f.allowUnbound);
  return r.is_PqRefused ? 'refused' : r.is_PqTrusted ? 'trusted' : r.is_PqPinned ? 'pinned' : r.is_PqCommitted ? 'committed' : 'unbound';
}

export type LeafOutcome<M> = { kind: 'pass' } | { kind: 'suite-error'; m: M } | { kind: 'bad-signature' };
export function leafDecision<M>(leafPresent: boolean, suiteErr: () => Res<M>, sigIsString: boolean, verify: () => boolean): LeafOutcome<M> {
  const r = V.LeafDecision(leafPresent, wrapRes(suiteErr), sigIsString, verify);
  return r.is_LeafPass ? { kind: 'pass' } : r.is_LeafSuiteErr ? { kind: 'suite-error', m: r.dtor_m as M } : { kind: 'bad-signature' };
}
export type CapChainOutcome<M> = { kind: 'empty' } | { kind: 'root-not-grant' } | { kind: 'walked'; ok: true } | { kind: 'walked'; ok: false; m: M };
/** cap_chain: non-empty, then rooted at the grant, then the (lazy) walk; each stage runs only if the previous one passed. */
export function capChainStatus<M>(nonEmpty: boolean, rootIsGrant: () => boolean, walk: () => Res<M>): CapChainOutcome<M> {
  const r = V.CapChainStatus(nonEmpty, rootIsGrant, wrapRes(walk));
  if (r.is_CapEmpty) return { kind: 'empty' };
  if (r.is_CapRootNotGrant) return { kind: 'root-not-grant' };
  return r.dtor_r.is_Ok ? { kind: 'walked', ok: true } : { kind: 'walked', ok: false, m: r.dtor_r.dtor_m as M };
}
export const hookStatus = (enforced: boolean, ok: boolean): Status => toStatus(V.HookStatus(enforced, ok));

export type PlanOutcome = 'not-enforced' | 'pass' | 'mismatch' | 'unauthorized';
export function planDecision(planSupplied: boolean, rootMatches: boolean, authorized: boolean | undefined): PlanOutcome {
  const r = V.PlanDecision(planSupplied, rootMatches, opt(authorized));
  return r.is_PlanNotEnforced ? 'not-enforced' : r.is_PlanPass ? 'pass' : r.is_PlanMismatch ? 'mismatch' : 'unauthorized';
}
export type BeaconOutcome = 'not-enforced' | 'pass' | 'rejected' | 'replayed' | 'unbound';
export function beaconDecision(supplied: boolean, verifierOk: boolean, replayed: boolean, refBinds: boolean): BeaconOutcome {
  const r = V.BeaconDecision(supplied, verifierOk, replayed, refBinds);
  return r.is_BeaconNotEnforced ? 'not-enforced' : r.is_BeaconPass ? 'pass' : r.is_BeaconRejected ? 'rejected' : r.is_BeaconReplayed ? 'replayed' : 'unbound';
}
export type ReversibilityOutcome = 'no-server-class' | 'pass' | 'less-restrictive';
export function reversibilityDecision(declaredRank: number, serverRank: number | undefined): ReversibilityOutcome {
  const r = V.RevDecision(bn(declaredRank), serverRank === undefined ? none() : some(bn(serverRank)));
  return r.is_RevNoServerClass ? 'no-server-class' : r.is_RevPass ? 'pass' : 'less-restrictive';
}
/** true => the agent's declared class is the effective one (it is stricter, or no server class exists). */
export const useDeclaredClass = (declaredRank: number, serverRank: number | undefined): boolean =>
  V.UseDeclared(bn(declaredRank), serverRank === undefined ? none() : some(bn(serverRank)));

export type ThresholdRuleOutcome = 'ok' | 'below' | 'rejected' | 'no-verifier';
/** F-1: a step-up (t > 1) needs an ENFORCED threshold hook that reported at least the server-derived t. */
export function thresholdRule(tReq: number, release: boolean, th: Status | undefined, hookT: number | undefined): ThresholdRuleOutcome {
  const r = V.ThresholdRule(bn(tReq), release, th === undefined ? none() : some(fromStatus(th)), hookT === undefined ? none() : some(bn(hookT)));
  return r.is_ThrOk ? 'ok' : r.is_ThrBelow ? 'below' : r.is_ThrRejected ? 'rejected' : 'no-verifier';
}

// ---------------------------------------------------------------------------------------------
// verifyPCActnCore fold (Verdict.dfy, section B)
// ---------------------------------------------------------------------------------------------
export type CheckEntry<N> = [N, Status];
const entries = <N>(cs: any): CheckEntry<N>[] => fromSeq<any>(cs).map((t: any) => [t[0] as N, toStatus(t[1])]);

/** Immutable state of the core verifier's check map + first failure reason. */
export class CoreState<N, M> {
  private constructor(private readonly st: any) {}
  static init<N, M>(): CoreState<N, M> {
    return new CoreState<N, M>(V.CoreInit());
  }
  /** `fail(name, why)`: checks[name] = fail; reason ??= why() (why is evaluated only for the first failure). */
  fail(name: N, why: () => M): CoreState<N, M> {
    return new CoreState<N, M>(V.CoreFail(this.st, name, why));
  }
  set(name: N, s: Status): CoreState<N, M> {
    return new CoreState<N, M>(V.CoreSet(this.st, name, fromStatus(s)));
  }
  /** Terminal wire failure: checks == {wire: fail}. */
  static wireFail<N, M>(wire: N, why: M): CoreState<N, M> {
    return new CoreState<N, M>(V.CoreWireFail(wire, why));
  }
  /** Exception during verification: reason ??= why; checks.malformed = fail. */
  malformed(name: N, why: M): CoreState<N, M> {
    return new CoreState<N, M>(V.CoreMalformed(this.st, name, why));
  }
  /** zk_compliance present: it must have been enforced (pass or fail), else fail closed. */
  zkRule(zk: N, why: () => M): CoreState<N, M> {
    return new CoreState<N, M>(V.ZkRule(this.st, zk, why));
  }
  /** M5 attestation gate: required + not-enforced => fail. */
  attestGate(att: N, gateOn: boolean, required: boolean, why: () => M): CoreState<N, M> {
    return new CoreState<N, M>(V.AttestGate(this.st, att, gateOn, required, why));
  }
  get(name: N): Status | undefined {
    const o = Common.__default.Get(this.st.dtor_checks, name);
    return o.is_Some ? toStatus(o.dtor_v) : undefined;
  }
  get allow(): boolean {
    return V.CoreAllow(this.st);
  }
  get reason(): M | undefined {
    return fromOpt<M>(V.CoreReason(this.st));
  }
  get checks(): CheckEntry<N>[] {
    return entries<N>(this.st.dtor_checks);
  }
}

// ---------------------------------------------------------------------------------------------
// verifyPCActn combinator (Verdict.dfy, section C)
// ---------------------------------------------------------------------------------------------
export class VerdictState<N, M> {
  private constructor(private readonly st: any) {}
  static init<N, M>(checks: readonly CheckEntry<N>[] = [], reasons: readonly M[] = []): VerdictState<N, M> {
    return new VerdictState<N, M>(Verdict.VSt.create_VSt(seq(checks.map(([n, s]) => D._dafny.Tuple.of(n, fromStatus(s)))), seq(reasons)));
  }
  fail(name: N, why: () => M): VerdictState<N, M> {
    return new VerdictState<N, M>(V.VFail(this.st, name, why));
  }
  set(name: N, s: Status): VerdictState<N, M> {
    return new VerdictState<N, M>(V.VSet(this.st, name, fromStatus(s)));
  }
  push(m: M): VerdictState<N, M> {
    return new VerdictState<N, M>(V.VPush(this.st, m));
  }
  pushAll(ms: readonly M[]): VerdictState<N, M> {
    return new VerdictState<N, M>(V.VPushAll(this.st, seq(ms)));
  }
  /** F-1 threshold rule recorded as a check; `why` renders the failure reason. */
  applyThreshold(thr: N, tReq: number, release: boolean, th: Status | undefined, hookT: number | undefined, why: (r: ThresholdRuleOutcome) => M): VerdictState<N, M> {
    const render = (r: any): M => why(r.is_ThrBelow ? 'below' : r.is_ThrRejected ? 'rejected' : r.is_ThrNoVerifier ? 'no-verifier' : 'ok');
    return new VerdictState<N, M>(
      V.ApplyThreshold(this.st, thr, bn(tReq), release, th === undefined ? none() : some(fromStatus(th)), hookT === undefined ? none() : some(bn(hookT)), render),
    );
  }
  get(name: N): Status | undefined {
    const o = Common.__default.Get(this.st.dtor_checks, name);
    return o.is_Some ? toStatus(o.dtor_v) : undefined;
  }
  /** Require-when-bound: a grant that binds the agent REQUIRES a passing `att` check. */
  attestationRequiredFails(requiresAtt: boolean, att: N): boolean {
    return V.AttestationRequiredFails(requiresAtt, this.st.dtor_checks, att);
  }
  /** allow = no check failed && Policy VM released the share && core allowed. */
  finalAllow(release: boolean, coreAllow: boolean): boolean {
    return V.FinalAllow(this.st.dtor_checks, release, coreAllow);
  }
  get checks(): CheckEntry<N>[] {
    return entries<N>(this.st.dtor_checks);
  }
  get reasons(): M[] {
    return fromSeq<M>(this.st.dtor_reasons);
  }
}

export interface EnforcedVerdict<N, M> {
  allow: boolean;
  checks: CheckEntry<N>[];
  reasons: M[];
}
/**
 * enforceRequired (Verdict.dfy: Enforce): every named check MUST be 'pass'; one that is not turns the verdict to deny and
 * (unless already 'fail') is recorded as 'fail' with `mk(name, previous)` as the reason. Proved: allow => every required
 * check is 'pass'; the result never allows more than the input; reasons only grow.
 */
export function enforceRequired<N, M>(allow: boolean, checks: readonly CheckEntry<N>[], reasons: readonly M[], required: readonly N[], mk: (name: N, was: Status | undefined) => M): EnforcedVerdict<N, M> {
  const r = V.Enforce(allow, seq(checks.map(([n, s]) => D._dafny.Tuple.of(n, fromStatus(s)))), seq(reasons), seq(required), (n: N, c: any) => mk(n, c.is_Some ? toStatus(c.dtor_v) : undefined));
  return { allow: r[0], checks: entries<N>(r[1]), reasons: fromSeq<M>(r[2]) };
}
/** A deny is never silent: when denied with no reason, the fallback message is the only reason. */
export const withDeniedFallback = <M>(allow: boolean, reasons: readonly M[], denied: M): M[] => fromSeq<M>(V.WithDeniedFallback(allow, seq(reasons), denied));
