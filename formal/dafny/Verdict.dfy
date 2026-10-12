// Verdict.dfy - the verifier's decision combinators: verifyPCActnCore's per-check decisions and fold, and
// the verifyPCActn (server/verify.ts) verdict combinator, as verified pure functions.
//
// Convention: all primitive evaluations (signatures, hashes, parsing, Policy VM output, hook calls, ...) happen
// OUTSIDE this file in the TypeScript glue; they enter as booleans, small enums, ints, and opaque messages `M`.
// Check names are an opaque type `N` (JS strings).  Nothing here is assumed or axiomatised.
include "Common.dfy"
module Verdict {
  import opened Common

  // ============================================================================================
  // A. per-check decisions
  // ============================================================================================

  datatype AudArg = AudAbsent | AudNull | AudStr

  // F-closed audience rule: absent verifier audience fails closed when the PCActn carries a signed aud.
  function AudienceStatus(hasAud: bool, arg: AudArg, equal: bool): Status {
    match arg {
      case AudNull => NotEnforced
      case AudAbsent => if hasAud then Fail else NotEnforced
      case AudStr => if equal then Pass else Fail
    }
  }

  const MaxLifetimeMs: int := 3600000
  const MaxSkewMs: int := 60000

  datatype Validity = VPass | VBadClock | VNotGreater | VTooLong | VFuture | VExpired

  function ValidityDecision(clockOk: bool, iat: int, exp: int, now: int): Validity {
    if !clockOk then VBadClock
    else if !(exp > iat) then VNotGreater
    else if exp - iat > MaxLifetimeMs then VTooLong
    else if iat > now + MaxSkewMs then VFuture
    else if now > exp then VExpired
    else VPass
  }

  function VersionStatus(versionOk: bool): Status { if versionOk then Pass else Fail }

  function GrantRefBoundStatus(grantRefNonEmptyString: bool, rootIdIsString: bool, equal: bool): Status {
    if grantRefNonEmptyString && rootIdIsString && equal then Pass else Fail
  }

  function CounterStatus(nonNegSafeInt: bool): Status { if nonNegSafeInt then Pass else Fail }

  // Suite policy for one signature (leaf or hop): the alg must be in allowedSuites when a policy is set.
  datatype SuiteViolation = NotAllowed | NoPqCommitment | PqMismatch

  function SuitePolicy(policyDefined: bool, algAllowed: bool): Option<SuiteViolation> {
    if policyDefined && !algAllowed then Some(NotAllowed) else None
  }

  // F-2: a suite that carries a PQ key is accepted only if that key is the one the signer's holder committed to.
  function PqBinding(needsPqKey: bool, allowUnbound: bool, committed: bool, matches: bool): Option<SuiteViolation> {
    if !needsPqKey || allowUnbound then None
    else if !committed then Some(NoPqCommitment)
    else if !matches then Some(PqMismatch)
    else None
  }

  // R2-01 / R3-01: THE choke point deciding where a PQ verification key may come from. A key read from the artifact alone
  // proves nothing about who signed; some verifier-side authority must vouch for it.
  //   trusted        the verifier's own configured key (registry / trust list / stored grant)
  //   pin            a pin for the signer's identity: the artifact's key MUST equal it (a mismatch is a refusal, even with allowUnbound)
  //   holder commit  the parent hop's / leaf holder's holder_pq commitment (F-2): the artifact's key must hash to it
  //   unbound        legacy opt-out (default OFF)
  datatype PqResolution = PqRefused | PqTrusted | PqPinned | PqCommitted | PqUnbound

  function PqResolve(trusted: bool, artifactKeyOk: bool, pinPresent: bool, pinEquals: bool,
                     commitPresent: bool, commitMatches: bool, allowUnbound: bool): PqResolution {
    if trusted then PqTrusted
    else if !artifactKeyOk then PqRefused
    else if pinPresent then (if pinEquals then PqPinned else PqRefused)
    else if commitPresent && commitMatches then PqCommitted
    else if allowUnbound then PqUnbound
    else PqRefused
  }

  datatype LeafOut<M> = LeafPass | LeafSuiteErr(m: M) | LeafBadSig

  // `suiteErr` is only consulted when the leaf capability exists; `verify` only when the suite is fine and sig is a string.
  function LeafDecision<M>(leafPresent: bool, suiteErr: () -> Res<M>, sigIsString: bool, verify: () -> bool): LeafOut<M> {
    if !leafPresent then LeafBadSig
    else match suiteErr() {
      case Err(m) => LeafSuiteErr(m)
      case Ok => if sigIsString && verify() then LeafPass else LeafBadSig
    }
  }

  // cap_chain check: empty chain, then "root is the grant", then the (lazy) chain walk. Each stage runs only if the previous passed.
  datatype CapChainOut<M> = CapEmpty | CapRootNotGrant | CapWalked(r: Res<M>)

  function CapChainStatus<M>(nonEmpty: bool, rootIsGrant: () -> bool, walk: () -> Res<M>): CapChainOut<M> {
    if !nonEmpty then CapEmpty
    else if !rootIsGrant() then CapRootNotGrant
    else CapWalked(walk())
  }

  datatype HookOut = HookNotEnforced | HookPass | HookFail
  function HookStatus(enforced: bool, ok: bool): Status {
    if !enforced then NotEnforced else if ok then Pass else Fail
  }

  // ============================================================================================
  // B. verifyPCActnCore fold
  // ============================================================================================

  datatype CoreSt<N, M> = CoreSt(checks: Checks<N>, reason: Option<M>, terminal: bool)

  function CoreInit<N, M>(): CoreSt<N, M> { CoreSt([], None, false) }

  // fail(name, why): checks[name] = fail; reason ??= why   (`why` is lazy: only built on the first reason)
  function CoreFail<N(==), M>(st: CoreSt<N, M>, name: N, why: () -> M): CoreSt<N, M> {
    CoreSt(Set(st.checks, name, Fail), if st.reason.Some? then st.reason else Some(why()), st.terminal)
  }

  function CoreSet<N(==), M>(st: CoreSt<N, M>, name: N, s: Status): CoreSt<N, M> {
    CoreSt(Set(st.checks, name, s), st.reason, st.terminal)
  }

  // A wire failure is terminal: checks == {wire: fail}.
  function CoreWireFail<N(==), M>(wire: N, why: M): CoreSt<N, M> {
    CoreSt([(wire, Fail)], Some(why), true)
  }

  // Exception inside verification: reason ??= why; checks.malformed = fail.
  function CoreMalformed<N(==), M>(st: CoreSt<N, M>, malformed: N, why: M): CoreSt<N, M> {
    CoreSt(Set(st.checks, malformed, Fail), if st.reason.Some? then st.reason else Some(why), st.terminal)
  }

  // core.allow = no check failed. The reason is reported only when denied.
  function CoreAllow<N, M>(st: CoreSt<N, M>): bool { !st.terminal && !HasFail(st.checks) }
  function CoreReason<N, M>(st: CoreSt<N, M>): Option<M> { if CoreAllow(st) then None else st.reason }

  // zk_compliance: a PCActn that carries a proof is denied unless a verifier actually enforced it.
  function ZkRule<N(==), M>(st: CoreSt<N, M>, zk: N, why: () -> M): CoreSt<N, M> {
    var c := Get(st.checks, zk);
    if c == Some(Pass) || c == Some(Fail) then st else CoreFail(st, zk, why)
  }

  // M5 attestation gate: required + not-enforced is a failure.
  function AttestGate<N(==), M>(st: CoreSt<N, M>, att: N, gateOn: bool, required: bool, why: () -> M): CoreSt<N, M> {
    if gateOn && required && Get(st.checks, att) == Some(NotEnforced) then CoreFail(st, att, why) else st
  }

  // ============================================================================================
  // C. verifyPCActn (server/verify.ts) verdict combinator
  // ============================================================================================

  datatype VSt<N, M> = VSt(checks: Checks<N>, reasons: seq<M>)

  function VFail<N(==), M>(st: VSt<N, M>, name: N, why: () -> M): VSt<N, M> {
    VSt(Set(st.checks, name, Fail), st.reasons + [why()])
  }
  function VSet<N(==), M>(st: VSt<N, M>, name: N, s: Status): VSt<N, M> { VSt(Set(st.checks, name, s), st.reasons) }
  function VPush<N, M>(st: VSt<N, M>, m: M): VSt<N, M> { VSt(st.checks, st.reasons + [m]) }
  function VPushAll<N, M>(st: VSt<N, M>, ms: seq<M>): VSt<N, M> { VSt(st.checks, st.reasons + ms) }

  datatype PlanOut = PlanNotEnforced | PlanPass | PlanMismatch | PlanUnauthorized
  function PlanDecision(planSupplied: bool, rootMatches: bool, authorized: Option<bool>): PlanOut {
    if !planSupplied then PlanNotEnforced
    else if !rootMatches then PlanMismatch
    else match authorized {
      case Some(true) => PlanPass
      case Some(false) => PlanUnauthorized
      case None => PlanNotEnforced
    }
  }

  datatype BeaconOut = BeaconNotEnforced | BeaconPass | BeaconRejected | BeaconReplayed | BeaconUnbound
  function BeaconDecision(supplied: bool, verifierOk: bool, replayed: bool, refBinds: bool): BeaconOut {
    if !supplied then BeaconNotEnforced
    else if !verifierOk then BeaconRejected
    else if replayed then BeaconReplayed
    else if !refBinds then BeaconUnbound
    else BeaconPass
  }

  // Require-when-bound (audit finding 3): a grant that binds the agent REQUIRES a passing attestation.
  function AttestationRequiredFails<N(==)>(requiresAtt: bool, checks: Checks<N>, att: N): bool {
    requiresAtt && Get(checks, att) != Some(Pass)
  }

  // Reversibility: the server's class wins; the agent may only be STRICTER.
  // ranks: reversible 0 < costly 1 < irreversible 2 (unknown = 2, computed by the glue).
  datatype RevOut = RevNoServerClass | RevPass | RevLessRestrictive
  function RevDecision(declaredRank: int, serverRank: Option<int>): RevOut {
    match serverRank {
      case None => RevNoServerClass
      case Some(sr) => if declaredRank < sr then RevLessRestrictive else RevPass
    }
  }
  // true => use the agent's declared class as the effective one, false => the server's
  function UseDeclared(declaredRank: int, serverRank: Option<int>): bool {
    match serverRank { case None => true case Some(sr) => declaredRank > sr }
  }

  datatype ThrOut = ThrOk | ThrBelow | ThrRejected | ThrNoVerifier
  // F-1: t > 1 needs an ENFORCED threshold hook that reported having enforced at least the server-derived t.
  function ThresholdRule(tReq: int, release: bool, th: Option<Status>, hookT: Option<int>): ThrOut {
    if tReq > 1 && release && th == Some(Pass) && !(hookT.Some? && hookT.v >= tReq) then ThrBelow
    else if tReq > 1 && release && th != Some(Pass) then
      (if th == Some(Fail) then ThrRejected else ThrNoVerifier)
    else ThrOk
  }

  function FinalAllow<N>(checks: Checks<N>, release: bool, coreAllow: bool): bool {
    !HasFail(checks) && release && coreAllow
  }

  // enforceRequired: every named check MUST be Pass; anything else denies and (unless already Fail) is turned into Fail.
  function Enforce<N(==), M>(allow: bool, checks: Checks<N>, reasons: seq<M>, req: seq<N>, mk: (N, Option<Status>) -> M): (bool, Checks<N>, seq<M>)
    decreases |req|
  {
    if |req| == 0 then (allow, checks, reasons)
    else
      var c := Get(checks, req[0]);
      if c == Some(Pass) then Enforce(allow, checks, reasons, req[1..], mk)
      else if c == Some(Fail) then Enforce(false, checks, reasons, req[1..], mk)
      else Enforce(false, Set(checks, req[0], Fail), reasons + [mk(req[0], c)], req[1..], mk)
  }

  // ============================================================================================
  // THEOREMS
  // ============================================================================================

  // ---- core fold ----
  // allow <=> no check failed (and the fold did not end on a wire failure).
  lemma CoreAllowIff<N, M>(st: CoreSt<N, M>)
    ensures CoreAllow(st) <==> (!st.terminal && forall k :: 0 <= k < |st.checks| ==> st.checks[k].1 != Fail)
  { HasFailIff(st.checks); }

  // A recorded failure always denies, and cannot be erased by recording a different check.
  lemma CoreFailDenies<N(==), M>(st: CoreSt<N, M>, name: N, why: () -> M)
    ensures !CoreAllow(CoreFail(st, name, why))
    ensures CoreFail(st, name, why).reason.Some?
    ensures st.reason.Some? ==> CoreFail(st, name, why).reason == st.reason
  {
    var s2 := CoreFail(st, name, why);
    assert Get(s2.checks, name) == Some(Fail) by { GetSet(st.checks, name, name, Fail); }
    HasFailGet(s2.checks, name);
  }

  lemma HasFailGet<N(==)>(cs: Checks<N>, n: N)
    requires Get(cs, n) == Some(Fail)
    ensures HasFail(cs)
    decreases |cs|
  {
    if |cs| > 0 && cs[0].0 != n { HasFailGet(cs[1..], n); }
  }

  lemma GetImpliesMember<N(==)>(cs: Checks<N>, n: N)
    ensures Get(cs, n).Some? <==> exists k :: 0 <= k < |cs| && cs[k].0 == n
    ensures Get(cs, n).Some? ==> exists k :: 0 <= k < |cs| && cs[k].0 == n && cs[k].1 == Get(cs, n).v
    decreases |cs|
  {
    if |cs| > 0 && cs[0].0 != n {
      GetImpliesMember(cs[1..], n);
      if Get(cs[1..], n).Some? { var k :| 0 <= k < |cs[1..]| && cs[1..][k].0 == n && cs[1..][k].1 == Get(cs[1..], n).v; assert cs[k + 1] == cs[1..][k]; }
      if exists k :: 0 <= k < |cs| && cs[k].0 == n { var k :| 0 <= k < |cs| && cs[k].0 == n; assert k >= 1; assert cs[1..][k - 1].0 == n; }
    }
  }

  // A recorded Fail anywhere makes the whole HasFail true; conversely HasFail means some entry is Fail.
  lemma HasFailImpliesSome<N(==)>(cs: Checks<N>)
    requires HasFail(cs)
    ensures exists k :: 0 <= k < |cs| && cs[k].1 == Fail
  { HasFailIff(cs); }

  // Wire failure is terminal: nothing but `wire` is reported and the verdict is deny.
  lemma WireTerminal<N(==), M>(wire: N, why: M)
    ensures !CoreAllow(CoreWireFail<N, M>(wire, why))
    ensures |CoreWireFail<N, M>(wire, why).checks| == 1
  {}

  // The reason reported on deny is the FIRST failure recorded (stable, reasons never overwritten).
  lemma CoreFirstReasonWins<N(==), M>(st: CoreSt<N, M>, name: N, why: () -> M)
    requires st.reason.Some?
    ensures CoreFail(st, name, why).reason == st.reason
  {}

  // zk / attestation rules never weaken a verdict: an allow after the rule implies an allow before it.
  lemma ZkRuleMonotone<N(==), M>(st: CoreSt<N, M>, zk: N, why: () -> M)
    requires CoreAllow(ZkRule(st, zk, why))
    ensures CoreAllow(st)
  {
    var c := Get(st.checks, zk);
    if !(c == Some(Pass) || c == Some(Fail)) { CoreFailDenies(st, zk, why); }
  }

  // Zk rule: a present proof is accepted only when a verifier ENFORCED it and it passed.
  lemma ZkRuleSound<N(==), M>(st: CoreSt<N, M>, zk: N, why: () -> M)
    requires CoreAllow(ZkRule(st, zk, why))
    ensures Get(st.checks, zk) == Some(Pass)
  {
    var c := Get(st.checks, zk);
    if c == Some(Fail) { HasFailGet(st.checks, zk); }
    if !(c == Some(Pass) || c == Some(Fail)) { CoreFailDenies(st, zk, why); }
  }

  lemma AttestGateSound<N(==), M>(st: CoreSt<N, M>, att: N, gateOn: bool, required: bool, why: () -> M)
    requires CoreAllow(AttestGate(st, att, gateOn, required, why))
    ensures CoreAllow(st)
    ensures gateOn && required ==> Get(st.checks, att) != Some(NotEnforced)
  {
    if gateOn && required && Get(st.checks, att) == Some(NotEnforced) { CoreFailDenies(st, att, why); }
  }

  // ---- per-check decision theorems ----
  // Audience: a PCActn is accepted for an audience only when its signed aud equals the verifier's (or the
  // verifier deliberately opted out with AudNull; or neither side names one).
  lemma AudienceSound(hasAud: bool, arg: AudArg, equal: bool)
    ensures AudienceStatus(hasAud, arg, equal) == Pass ==> arg.AudStr? && equal
    ensures AudienceStatus(hasAud, arg, equal) != Fail ==> (arg.AudNull? || (arg.AudAbsent? && !hasAud) || (arg.AudStr? && equal))
    ensures arg.AudAbsent? && hasAud ==> AudienceStatus(hasAud, arg, equal) == Fail   // fail-closed on a forgotten audience
  {}

  // Validity/expiry/clock-skew: pass <=> a safe clock, exp > iat, lifetime <= max, iat <= now + skew, now <= exp.
  lemma ValiditySound(clockOk: bool, iat: int, exp: int, now: int)
    ensures ValidityDecision(clockOk, iat, exp, now) == VPass <==>
            (clockOk && exp > iat && exp - iat <= MaxLifetimeMs && iat <= now + MaxSkewMs && now <= exp)
  {}

  // Expiry: an expired PCActn (now > exp) is NEVER valid, regardless of anything else.
  lemma NoAcceptAfterExpiry(clockOk: bool, iat: int, exp: int, now: int)
    requires now > exp
    ensures ValidityDecision(clockOk, iat, exp, now) != VPass
  {}

  // Lifetime bound: no PCActn lives longer than MaxLifetimeMs, and no PCActn from the future beyond the skew passes.
  lemma ValidityWindowBound(iat: int, exp: int, now: int)
    requires ValidityDecision(true, iat, exp, now) == VPass
    ensures iat < exp <= iat + MaxLifetimeMs && now <= exp && iat - MaxSkewMs <= now
  {}

  // grant_ref_bound: no pass without a non-empty string grant_ref that is byte-equal to the root capability id.
  lemma GrantRefBoundSound(g: bool, r: bool, e: bool)
    ensures GrantRefBoundStatus(g, r, e) == Pass <==> (g && r && e)
  {}

  // cap_chain: passes only if the chain is non-empty, rooted at the grant, and the walk accepted.
  lemma CapChainSound<M>(nonEmpty: bool, rootIsGrant: () -> bool, walk: () -> Res<M>)
    ensures CapChainStatus(nonEmpty, rootIsGrant, walk).CapWalked? && CapChainStatus(nonEmpty, rootIsGrant, walk).r.Ok? ==>
              nonEmpty && rootIsGrant() && walk().Ok?
  {}

  // PQ pin binding (F-2 / R2-01): a PQ-key suite is NEVER accepted without a commitment that matches,
  // unless the legacy unbound opt-out is on.
  lemma PqBindingSound(needs: bool, allowUnbound: bool, committed: bool, matches: bool)
    ensures PqBinding(needs, allowUnbound, committed, matches).None? <==> (!needs || allowUnbound || (committed && matches))
    ensures needs && !allowUnbound && !committed ==> PqBinding(needs, allowUnbound, committed, matches) == Some(NoPqCommitment)
  {}

  // THEOREM (PQ key authority, R2-01 / R3-01): a PQ key is resolved only with verifier-side authority; a pin that disagrees
  // with the artifact is always a refusal; the legacy unbound path is reachable only when explicitly enabled and nothing else vouches.
  lemma PqResolveSound(trusted: bool, artifactKeyOk: bool, pinPresent: bool, pinEquals: bool,
                       commitPresent: bool, commitMatches: bool, allowUnbound: bool)
    ensures PqResolve(trusted, artifactKeyOk, pinPresent, pinEquals, commitPresent, commitMatches, allowUnbound) != PqRefused ==>
              trusted || (artifactKeyOk && (if pinPresent then pinEquals else ((commitPresent && commitMatches) || allowUnbound)))
    ensures !trusted && pinPresent && !pinEquals ==> PqResolve(trusted, artifactKeyOk, pinPresent, pinEquals, commitPresent, commitMatches, allowUnbound) == PqRefused
    ensures !trusted && !artifactKeyOk ==> PqResolve(trusted, artifactKeyOk, pinPresent, pinEquals, commitPresent, commitMatches, allowUnbound) == PqRefused
    ensures PqResolve(trusted, artifactKeyOk, pinPresent, pinEquals, commitPresent, commitMatches, allowUnbound) == PqUnbound ==>
              allowUnbound && !trusted && !pinPresent && !(commitPresent && commitMatches)
    ensures !trusted && !pinPresent && !(commitPresent && commitMatches) && !allowUnbound ==>
              PqResolve(trusted, artifactKeyOk, pinPresent, pinEquals, commitPresent, commitMatches, allowUnbound) == PqRefused
  {}

  // Suite policy (F-4): with a policy set, an alg outside it is never accepted.
  lemma SuitePolicySound(def: bool, allowed: bool)
    ensures SuitePolicy(def, allowed).None? <==> (!def || allowed)
  {}

  // Leaf: passes only if (a) the leaf exists, (b) the suite/binding is fine, (c) the signature is a string and verifies.
  lemma LeafSound<M>(leafPresent: bool, suiteErr: () -> Res<M>, sigIsString: bool, verify: () -> bool)
    ensures LeafDecision(leafPresent, suiteErr, sigIsString, verify).LeafPass? ==>
              leafPresent && suiteErr().Ok? && sigIsString && verify()
  {}

  // No allow on a missing binding: a grant that binds the agent with no passing attestation is always denied.
  lemma MissingBindingDenies<N(==), M>(st: VSt<N, M>, att: N, why: () -> M, release: bool, coreAllow: bool)
    requires AttestationRequiredFails(true, st.checks, att)
    ensures !FinalAllow(VFail(st, att, why).checks, release, coreAllow)
  {
    var s2 := VFail(st, att, why);
    GetSet(st.checks, att, att, Fail);
    HasFailGet(s2.checks, att);
  }

  // ---- threshold rule (F-1) ----
  lemma ThresholdRuleSound(tReq: int, release: bool, th: Option<Status>, hookT: Option<int>)
    ensures ThresholdRule(tReq, release, th, hookT).ThrOk? ==>
              (tReq > 1 && release ==> th == Some(Pass) && hookT.Some? && hookT.v >= tReq)
    ensures tReq > 1 && release && th == Some(Pass) && !(hookT.Some? && hookT.v >= tReq) ==> ThresholdRule(tReq, release, th, hookT).ThrBelow?
  {}

  // ---- reversibility: agent may only be stricter ----
  lemma ReversibilitySound(declared: int, server: Option<int>)
    ensures server.Some? && RevDecision(declared, server) == RevPass ==> declared >= server.v
    ensures server.Some? && UseDeclared(declared, server) ==> declared > server.v
    ensures server.Some? && !UseDeclared(declared, server) ==> declared <= server.v
  {}

  // ---- enforceRequired ----
  lemma EnforceMonotone<N(==), M>(allow: bool, checks: Checks<N>, reasons: seq<M>, req: seq<N>, mk: (N, Option<Status>) -> M)
    ensures Enforce(allow, checks, reasons, req, mk).0 ==> allow
    decreases |req|
  {
    if |req| > 0 {
      var c := Get(checks, req[0]);
      if c == Some(Pass) { EnforceMonotone(allow, checks, reasons, req[1..], mk); }
      else if c == Some(Fail) { EnforceMonotone(false, checks, reasons, req[1..], mk); }
      else { EnforceMonotone(false, Set(checks, req[0], Fail), reasons + [mk(req[0], c)], req[1..], mk); }
    }
  }

  // Reasons only ever grow by appending (ordering of reasons is the order of events).
  lemma EnforceReasonsAppend<N(==), M>(allow: bool, checks: Checks<N>, reasons: seq<M>, req: seq<N>, mk: (N, Option<Status>) -> M)
    ensures reasons <= Enforce(allow, checks, reasons, req, mk).2
    decreases |req|
  {
    if |req| > 0 {
      var c := Get(checks, req[0]);
      if c == Some(Pass) { EnforceReasonsAppend(allow, checks, reasons, req[1..], mk); }
      else if c == Some(Fail) { EnforceReasonsAppend(false, checks, reasons, req[1..], mk); }
      else { EnforceReasonsAppend(false, Set(checks, req[0], Fail), reasons + [mk(req[0], c)], req[1..], mk); }
    }
  }

  // Soundness: after Enforce, allow implies every required check is Pass.
  // (requires the checks map has unique names, which Set guarantees by construction: see Unique.)
  ghost predicate Unique<N(==)>(cs: Checks<N>) {
    forall i, j :: 0 <= i < j < |cs| ==> cs[i].0 != cs[j].0
  }

  lemma SetUnique<N(==)>(cs: Checks<N>, n: N, s: Status)
    requires Unique(cs)
    ensures Unique(Set(cs, n, s))
    decreases |cs|
  {
    if |cs| > 0 && cs[0].0 != n {
      assert Unique(cs[1..]) by { forall i, j | 0 <= i < j < |cs[1..]| ensures cs[1..][i].0 != cs[1..][j].0 { assert cs[1..][i] == cs[i + 1] && cs[1..][j] == cs[j + 1]; } }
      SetUnique(cs[1..], n, s);
      // names in Set(cs[1..],..) are those of cs[1..] plus possibly n; none equals cs[0].0
      SetNames(cs[1..], n, s);
      var t := Set(cs[1..], n, s);
      forall j | 1 <= j < 1 + |t| ensures cs[0].0 != ([cs[0]] + t)[j].0 {
        assert ([cs[0]] + t)[j] == t[j - 1];
        assert t[j - 1].0 == n || exists q :: 0 <= q < |cs[1..]| && cs[1..][q].0 == t[j - 1].0;
        if t[j - 1].0 != n { var q :| 0 <= q < |cs[1..]| && cs[1..][q].0 == t[j - 1].0; assert cs[1..][q] == cs[q + 1]; }
      }
    } else if |cs| > 0 {
      forall i, j | 0 <= i < j < |Set(cs, n, s)| ensures Set(cs, n, s)[i].0 != Set(cs, n, s)[j].0 {
        assert Set(cs, n, s) == [(n, s)] + cs[1..];
        if i == 0 { assert j >= 1; assert Set(cs, n, s)[j] == cs[j]; assert cs[j].0 != cs[0].0; }
        else { assert Set(cs, n, s)[i] == cs[i] && Set(cs, n, s)[j] == cs[j]; }
      }
    }
  }

  // every name in Set(cs, n, s) is n or an existing name
  lemma SetNames<N(==)>(cs: Checks<N>, n: N, s: Status)
    ensures forall k :: 0 <= k < |Set(cs, n, s)| ==> Set(cs, n, s)[k].0 == n || exists q :: 0 <= q < |cs| && cs[q].0 == Set(cs, n, s)[k].0
    decreases |cs|
  {
    if |cs| > 0 && cs[0].0 != n {
      SetNames(cs[1..], n, s);
      forall k | 0 <= k < |Set(cs, n, s)| ensures Set(cs, n, s)[k].0 == n || exists q :: 0 <= q < |cs| && cs[q].0 == Set(cs, n, s)[k].0 {
        if k == 0 { assert cs[0].0 == Set(cs, n, s)[0].0; }
        else {
          assert Set(cs, n, s)[k] == Set(cs[1..], n, s)[k - 1];
          if Set(cs[1..], n, s)[k - 1].0 != n { var q :| 0 <= q < |cs[1..]| && cs[1..][q].0 == Set(cs[1..], n, s)[k - 1].0; assert cs[1..][q] == cs[q + 1]; }
        }
      }
    } else if |cs| > 0 {
      forall k | 0 <= k < |Set(cs, n, s)| ensures Set(cs, n, s)[k].0 == n || exists q :: 0 <= q < |cs| && cs[q].0 == Set(cs, n, s)[k].0 {
        if k > 0 { assert Set(cs, n, s)[k] == cs[k]; }
      }
    }
  }

  lemma EnforceRequiredPass<N(==), M>(allow: bool, checks: Checks<N>, reasons: seq<M>, req: seq<N>, mk: (N, Option<Status>) -> M)
    requires Unique(checks)
    ensures Enforce(allow, checks, reasons, req, mk).0 ==> forall k :: 0 <= k < |req| ==> Get(Enforce(allow, checks, reasons, req, mk).1, req[k]) == Some(Pass)
    decreases |req|
  {
    if |req| > 0 {
      var c := Get(checks, req[0]);
      if c == Some(Pass) {
        EnforceRequiredPass(allow, checks, reasons, req[1..], mk);
        EnforceChecksStable(allow, checks, reasons, req[1..], mk, req[0]);
      } else if c == Some(Fail) {
        EnforceFalse(false, checks, reasons, req[1..], mk);
      } else {
        EnforceFalse(false, Set(checks, req[0], Fail), reasons + [mk(req[0], c)], req[1..], mk);
      }
    }
  }

  // Enforce only ever turns non-Pass entries into Fail; a name that is Pass stays Pass.
  lemma EnforceChecksStable<N(==), M>(allow: bool, checks: Checks<N>, reasons: seq<M>, req: seq<N>, mk: (N, Option<Status>) -> M, n: N)
    requires Get(checks, n) == Some(Pass)
    ensures Get(Enforce(allow, checks, reasons, req, mk).1, n) == Some(Pass)
    decreases |req|
  {
    if |req| > 0 {
      var c := Get(checks, req[0]);
      if c == Some(Pass) { EnforceChecksStable(allow, checks, reasons, req[1..], mk, n); }
      else if c == Some(Fail) { EnforceChecksStable(false, checks, reasons, req[1..], mk, n); }
      else {
        assert req[0] != n;
        GetSet(checks, req[0], n, Fail);
        EnforceChecksStable(false, Set(checks, req[0], Fail), reasons + [mk(req[0], c)], req[1..], mk, n);
      }
    }
  }

  // ---- final verdict soundness (the headline theorem for the combinator) ----
  // If, after the full combination, allow holds, then:
  //   * the core verdict allowed, the Policy VM released the guardian share,
  //   * no recorded check is Fail,
  //   * when t > 1 the threshold check passed and the hook enforced >= t (via the ThresholdRule check),
  //   * every required check is Pass.
  function Finalize<N(==), M>(st: VSt<N, M>, release: bool, coreAllow: bool, req: seq<N>, mk: (N, Option<Status>) -> M): (bool, Checks<N>, seq<M>) {
    Enforce(FinalAllow(st.checks, release, coreAllow), st.checks, st.reasons, req, mk)
  }

  lemma FinalizeSound<N(==), M>(st: VSt<N, M>, release: bool, coreAllow: bool, req: seq<N>, mk: (N, Option<Status>) -> M)
    requires Unique(st.checks)
    requires Finalize(st, release, coreAllow, req, mk).0
    ensures release && coreAllow && !HasFail(st.checks)
    ensures forall k :: 0 <= k < |req| ==> Get(Finalize(st, release, coreAllow, req, mk).1, req[k]) == Some(Pass)
    ensures st.reasons <= Finalize(st, release, coreAllow, req, mk).2
    ensures !HasFail(Finalize(st, release, coreAllow, req, mk).1)
  {
    EnforceMonotone(FinalAllow(st.checks, release, coreAllow), st.checks, st.reasons, req, mk);
    EnforceRequiredPass(FinalAllow(st.checks, release, coreAllow), st.checks, st.reasons, req, mk);
    EnforceReasonsAppend(FinalAllow(st.checks, release, coreAllow), st.checks, st.reasons, req, mk);
    EnforceNoFail(FinalAllow(st.checks, release, coreAllow), st.checks, st.reasons, req, mk);
  }

  // Enforce preserves "no Fail" when the result is allow.
  lemma EnforceNoFail<N(==), M>(allow: bool, checks: Checks<N>, reasons: seq<M>, req: seq<N>, mk: (N, Option<Status>) -> M)
    requires !HasFail(checks)
    requires Enforce(allow, checks, reasons, req, mk).0
    ensures !HasFail(Enforce(allow, checks, reasons, req, mk).1)
    decreases |req|
  {
    if |req| > 0 {
      var c := Get(checks, req[0]);
      if c == Some(Pass) { EnforceNoFail(allow, checks, reasons, req[1..], mk); }
      // c is Fail or not Pass => the result is allow=false, contradicting the requirement
      else { EnforceFalse(false, if c == Some(Fail) then checks else Set(checks, req[0], Fail), if c == Some(Fail) then reasons else reasons + [mk(req[0], c)], req[1..], mk); }
    }
  }

  lemma EnforceFalse<N(==), M>(allow: bool, checks: Checks<N>, reasons: seq<M>, req: seq<N>, mk: (N, Option<Status>) -> M)
    requires !allow
    ensures !Enforce(allow, checks, reasons, req, mk).0
    decreases |req|
  {
    if |req| > 0 {
      var c := Get(checks, req[0]);
      if c == Some(Pass) { EnforceFalse(allow, checks, reasons, req[1..], mk); }
      else if c == Some(Fail) { EnforceFalse(false, checks, reasons, req[1..], mk); }
      else { EnforceFalse(false, Set(checks, req[0], Fail), reasons + [mk(req[0], c)], req[1..], mk); }
    }
  }

  // A deny is never silent: the fallback adds "denied" when no reason exists.
  function WithDeniedFallback<M>(allow: bool, reasons: seq<M>, denied: M): seq<M> {
    if !allow && |reasons| == 0 then [denied] else reasons
  }

  lemma DeniedAlwaysHasReason<M>(allow: bool, reasons: seq<M>, denied: M)
    ensures !allow ==> |WithDeniedFallback(allow, reasons, denied)| > 0
    ensures allow ==> WithDeniedFallback(allow, reasons, denied) == reasons
  {}

  // Determinism: the combinator is a pure function of its inputs (stated extensionally for Enforce).
  lemma EnforceDeterministic<N(==), M>(allow: bool, checks: Checks<N>, reasons: seq<M>, req: seq<N>, mk1: (N, Option<Status>) -> M, mk2: (N, Option<Status>) -> M)
    requires forall n, c :: mk1(n, c) == mk2(n, c)
    ensures Enforce(allow, checks, reasons, req, mk1) == Enforce(allow, checks, reasons, req, mk2)
    decreases |req|
  {
    if |req| > 0 {
      var c := Get(checks, req[0]);
      if c == Some(Pass) { EnforceDeterministic(allow, checks, reasons, req[1..], mk1, mk2); }
      else if c == Some(Fail) { EnforceDeterministic(false, checks, reasons, req[1..], mk1, mk2); }
      else { EnforceDeterministic(false, Set(checks, req[0], Fail), reasons + [mk1(req[0], c)], req[1..], mk1, mk2); }
    }
  }

  // ---- the threshold rule as a recorded check, and the end-to-end consequence ----
  function ApplyThreshold<N(==), M>(st: VSt<N, M>, thr: N, tReq: int, release: bool, th: Option<Status>, hookT: Option<int>, why: ThrOut -> M): VSt<N, M> {
    var r := ThresholdRule(tReq, release, th, hookT);
    if r.ThrOk? then st else VFail(st, thr, () => why(r))
  }

  // THEOREM (hook-enforced t, F-1): if the final verdict allows, and the server requires t > 1 and the Policy VM
  // released the share, then the threshold check passed AND the hook reported enforcing at least t.
  lemma HookEnforcedT<N(==), M>(st: VSt<N, M>, thr: N, tReq: int, release: bool, coreAllow: bool,
                                th: Option<Status>, hookT: Option<int>, why: ThrOut -> M)
    requires FinalAllow(ApplyThreshold(st, thr, tReq, release, th, hookT, why).checks, release, coreAllow)
    ensures tReq > 1 && release ==> th == Some(Pass) && hookT.Some? && hookT.v >= tReq
  {
    var r := ThresholdRule(tReq, release, th, hookT);
    if !r.ThrOk? {
      var s2 := VFail(st, thr, () => why(r));
      GetSet(st.checks, thr, thr, Fail);
      HasFailGet(s2.checks, thr);
    }
  }

  // Check names built only through VSet/VFail stay unique (the precondition of FinalizeSound).
  lemma EmptyUnique<N(==)>() ensures Unique<N>([]) {}
  lemma VSetUnique<N(==), M>(st: VSt<N, M>, n: N, s: Status) requires Unique(st.checks) ensures Unique(VSet(st, n, s).checks) { SetUnique(st.checks, n, s); }
  lemma VFailUnique<N(==), M>(st: VSt<N, M>, n: N, why: () -> M) requires Unique(st.checks) ensures Unique(VFail(st, n, why).checks) { SetUnique(st.checks, n, Fail); }

  // THEOREM (monotone fail): once a check is recorded Fail by VFail, the verdict cannot be allow.
  lemma VFailDenies<N(==), M>(st: VSt<N, M>, n: N, why: () -> M, release: bool, coreAllow: bool)
    ensures !FinalAllow(VFail(st, n, why).checks, release, coreAllow)
  {
    var s2 := VFail(st, n, why);
    GetSet(st.checks, n, n, Fail);
    HasFailGet(s2.checks, n);
  }

  // THEOREM (reasons are append-only): every combinator step extends the reason list.
  lemma ReasonsAppendOnly<N(==), M>(st: VSt<N, M>, n: N, why: () -> M, m: M, ms: seq<M>)
    ensures st.reasons <= VFail(st, n, why).reasons
    ensures st.reasons <= VPush(st, m).reasons
    ensures st.reasons <= VPushAll(st, ms).reasons
    ensures VSet(st, n, Pass).reasons == st.reasons
  {}
}
