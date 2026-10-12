// Harness.dfy - differential-testing driver for the verified PCA core. NOT part of the proof (built with --no-verify):
// it reads a case file (one case per line, space-separated tokens, see ../../../packages/pca-verified-core/test/diverse/README
// in cases.mts for the grammar), calls the proved functions, and prints one canonical result line per case.
// The SAME file is compiled to cs / go / java / py / js with `dafny build --target:T`; transcripts must be byte-identical
// across targets and equal to the transcript produced by the production JS bridge (packages/pca-verified-core/src/*).
// The core modules are included unchanged (this file edits none of them).
include "../Common.dfy"
include "../Chain.dfy"
include "../Caveats.dfy"
include "../Threshold.dfy"
include "../Replay.dfy"
include "../Verdict.dfy"
module Harness {
  import Std.FileIO
  import opened Common
  import opened Chain
  import opened Caveats
  import opened Threshold
  import opened Replay
  import opened Verdict

  // ---- token reader -------------------------------------------------------------------------------
  class Rd {
    var t: seq<string>
    var i: nat
    constructor(t: seq<string>) { this.t := t; this.i := 0; }
    method Str() returns (s: string) {
      if i < |t| { s := t[i]; i := i + 1; } else { s := ""; }
    }
    method Int() returns (r: int) {
      var s := Str();
      r := ParseInt(s);
    }
    method OInt() returns (r: Option<int>) {
      var s := Str();
      if s == "n" { r := None; } else { var v := ParseInt(s); r := Some(v); }
    }
    method Bool() returns (b: bool) { var r := Int(); b := r != 0; }
    method Nat() returns (n: nat) { var r := Int(); n := if r < 0 then 0 else r; if n > 64 { n := 64; } }
  }

  method ParseInt(s: string) returns (r: int) {
    r := 0;
    var neg := false;
    var k := 0;
    if |s| > 0 && s[0] == '-' { neg := true; k := 1; }
    while k < |s| {
      var d := (s[k] as int) - ('0' as int);
      r := r * 10 + d;
      k := k + 1;
    }
    if neg { r := -r; }
  }

  method Split(line: string) returns (out: seq<string>) {
    out := [];
    var cur: string := "";
    var k := 0;
    while k < |line| {
      if line[k] == ' ' {
        if |cur| > 0 { out := out + [cur]; cur := ""; }
      } else { cur := cur + [line[k]]; }
      k := k + 1;
    }
    if |cur| > 0 { out := out + [cur]; }
  }

  // ---- canonical printing ---------------------------------------------------------------------------
  function IS(i: int): string { if i < 0 then "-" + NS((-i) as nat) else NS(i as nat) }
  function NS(n: nat): string decreases n { if n < 10 then [DigitC(n)] else NS(n / 10) + [DigitC(n % 10)] }
  function DigitC(d: nat): char requires d < 10 { match d { case 0 => '0' case 1 => '1' case 2 => '2' case 3 => '3' case 4 => '4' case 5 => '5' case 6 => '6' case 7 => '7' case 8 => '8' case _ => '9' } }
  function BS(b: bool): string { if b then "1" else "0" }
  function StS(s: Status): string { match s { case Pass => "P" case Fail => "F" case NotEnforced => "N" } }
  function OStS(o: Option<Status>): string { match o { case None => "-" case Some(s) => StS(s) } }
  function OIS(o: Option<int>): string { match o { case None => "-" case Some(v) => IS(v) } }
  function ChecksS(cs: Checks<string>): string decreases |cs| { if |cs| == 0 then "" else cs[0].0 + "=" + StS(cs[0].1) + ";" + ChecksS(cs[1..]) }
  function ReasonsS(ms: seq<int>): string decreases |ms| { if |ms| == 0 then "" else IS(ms[0]) + "," + ReasonsS(ms[1..]) }
  function RoleS(r: Role): string { match r { case Agent => "a" case Guardian => "g" case Principal => "p" } }
  function RolesS(rs: seq<Role>): string decreases |rs| { if |rs| == 0 then "" else RoleS(rs[0]) + RolesS(rs[1..]) }

  function StatusOf(c: int): Status { if c == 0 then Pass else if c == 1 then Fail else NotEnforced }
  function OptStatus(c: int): Option<Status> { if c < 0 then None else Some(StatusOf(c)) }
  function RoleOf(c: int): Option<Role> { if c < 0 then None else if c == 0 then Some(Agent) else if c == 1 then Some(Guardian) else Some(Principal) }
  function ResOf(v: int): Res<int> { if v < 0 then Ok else Err(v) }
  function ResS(r: Res<int>): string { match r { case Ok => "ok" case Err(m) => "err" + IS(m) } }

  // deterministic stand-ins for the opaque / function-typed inputs
  function MkReason(n: string, c: Option<Status>): int { |n| * 7 + (match c { case None => 1 case Some(Pass) => 2 case Some(Fail) => 3 case Some(NotEnforced) => 4 }) }
  function CeqMode(mode: int, a: int, b: int): bool {
    if mode == 0 then a == b else if mode == 1 then ((a % 3) + 3) % 3 == ((b % 3) + 3) % 3 else if mode == 2 then true else false
  }

  // ---- op implementations ---------------------------------------------------------------------------
  method ReadHops(r: Rd, n: nat) returns (hops: seq<Hop<int, int>>) {
    hops := [];
    var k := 0;
    while k < n {
      var wt := r.Bool(); var hp := r.Bool(); var ri := r.Bool();
      var nc := r.Nat();
      var cav: seq<int> := [];
      var j := 0;
      while j < nc { var c := r.Int(); cav := cav + [c]; j := j + 1; }
      var pl := r.Bool(); var ih := r.Bool();
      var su := r.Int(); var pq := r.Int(); var sg := r.Int();
      hops := hops + [Hop(wt, hp, ri, cav, () => pl, () => ih, () => ResOf(su), () => ResOf(pq), () => ResOf(sg))];
      k := k + 1;
    }
  }

  function ErrS(e: ChainErr<int>): string {
    match e {
      case Empty => "empty" case TooLong => "toolong" case Malformed(h) => "malformed" + IS(h) case RootHasParent => "roothasparent"
      case RootIssuer => "rootissuer" case SuiteErr(h, m) => "suite" + IS(h) + ":" + IS(m) case PqErr(h, m) => "pq" + IS(h) + ":" + IS(m)
      case SigErr(h, m) => "sig" + IS(h) + ":" + IS(m) case ParentLink(h) => "parentlink" + IS(h) case IssuerNotHolder(h) => "issuernotholder" + IS(h)
      case Drops(h) => "drops" + IS(h) case Altered(h, j) => "altered" + IS(h) + "." + IS(j) case Alloc(m) => "alloc" + IS(m)
    }
  }

  function ThReasonS(o: Option<ThReason>): string {
    match o {
      case None => "-"
      case Some(r) => match r {
        case InvalidT => "invalidt" case SetMalformed => "setmalformed" case SetPq => "setpq" case TwoKeysForRole(e) => "twokeys" + IS(e)
        case OneKeyTwoRoles => "onekeytworoles" case MalformedShare => "malformedshare" case RoleNotInSet(s) => "rolenotinset" + IS(s)
        case KeyNotRegistered(s) => "keynotreg" + IS(s) case UnknownAlg(s) => "unknownalg" + IS(s) case PqPkMismatch(s) => "pqpkmismatch" + IS(s) case InvalidSig(s) => "invalidsig" + IS(s) case NeedMore => "needmore"
      }
    }
  }
  function DenyS(o: Option<Deny>): string {
    match o { case None => "-" case Some(d) => match d { case Malformed => "malformed" case Audience => "audience" case NotYetValid => "notyet" case Expired => "expired" case Replay => "replay" case StoreUnavailable => "storeunavail" } }
  }
  function OutS(o: Out): string { match o { case Accepted => "A" case Dup => "D" case Rejected => "R" } }
  function SuiteVS(o: Option<SuiteViolation>): string { match o { case None => "-" case Some(NotAllowed) => "na" case Some(NoPqCommitment) => "nopq" case Some(PqMismatch) => "mm" } }

  // CoreSt / VSt programs: a list of ops separated by their own arity
  method CoreProg(r: Rd) returns (s: string) {
    var st: CoreSt<string, int> := CoreInit();
    var n := r.Nat();
    var k := 0;
    while k < n {
      var op := r.Str();
      var name := r.Str();
      if op == "F" { var w := r.Int(); st := CoreFail(st, name, () => w); }
      else if op == "S" { var c := r.Int(); st := CoreSet(st, name, StatusOf(c)); }
      else if op == "W" { var w := r.Int(); st := CoreWireFail(name, w); }
      else if op == "M" { var w := r.Int(); st := CoreMalformed(st, name, w); }
      else if op == "Z" { var w := r.Int(); st := ZkRule(st, name, () => w); }
      else { var g := r.Bool(); var rq := r.Bool(); var w := r.Int(); st := AttestGate(st, name, g, rq, () => w); }
      k := k + 1;
    }
    s := ChecksS(st.checks) + "|" + BS(st.terminal) + "|" + BS(CoreAllow(st)) + "|" + OIS(CoreReason(st));
  }

  method VProg(r: Rd) returns (s: string) {
    var st: VSt<string, int> := VSt([], []);
    var n := r.Nat();
    var k := 0;
    while k < n {
      var op := r.Str();
      if op == "F" { var name := r.Str(); var w := r.Int(); st := VFail(st, name, () => w); }
      else if op == "S" { var name := r.Str(); var c := r.Int(); st := VSet(st, name, StatusOf(c)); }
      else if op == "P" { var m := r.Int(); st := VPush(st, m); }
      else if op == "Q" { var cnt := r.Nat(); var ms: seq<int> := []; var j := 0; while j < cnt { var m := r.Int(); ms := ms + [m]; j := j + 1; } st := VPushAll(st, ms); }
      else {
        var name := r.Str(); var tReq := r.Int(); var rel := r.Bool(); var th := r.Int(); var ht := r.OInt();
        st := ApplyThreshold(st, name, tReq, rel, OptStatus(th), ht, (o: ThrOut) => (match o { case ThrOk => 0 case ThrBelow => 1 case ThrRejected => 2 case ThrNoVerifier => 3 }));
      }
      k := k + 1;
    }
    var rel := r.Bool(); var ca := r.Bool(); var ra := r.Bool(); var an := r.Str();
    var nreq := r.Nat();
    var req: seq<string> := [];
    var j := 0;
    while j < nreq { var q := r.Str(); req := req + [q]; j := j + 1; }
    var fa := FinalAllow(st.checks, rel, ca);
    var arf := AttestationRequiredFails(ra, st.checks, an);
    var en := Enforce(fa, st.checks, st.reasons, req, MkReason);
    var fin := Finalize(st, rel, ca, req, MkReason);
    var wd := WithDeniedFallback(en.0, en.2, 99);
    s := ChecksS(st.checks) + "|" + ReasonsS(st.reasons) + "|" + BS(fa) + "|" + BS(arf) + "|" + BS(en.0) + ":" + ChecksS(en.1) + ":" + ReasonsS(en.2)
       + "|" + BS(fin.0) + ":" + ChecksS(fin.1) + ":" + ReasonsS(fin.2) + "|" + ReasonsS(wd);
  }

  method CaveatOp(r: Rd) returns (s: string) {
    var n := r.Nat();
    var cs: seq<Caveat> := [];
    var k := 0;
    while k < n {
      var kind := r.Int(); var cnt := r.Nat();
      if kind == 0 { var ss: set<string> := {}; var j := 0; while j < cnt { var x := r.Str(); ss := ss + {x}; j := j + 1; } cs := cs + [VerbIn(ss)]; }
      else if kind == 1 { var ss: set<string> := {}; var j := 0; while j < cnt { var x := r.Str(); ss := ss + {x}; j := j + 1; } cs := cs + [ResIn(ss)]; }
      else if kind == 2 { var t := r.Int(); cs := cs + [ExpiresAt(t)]; }
      else { var x := r.Str(); cs := cs + [Opaque(x)]; }
      k := k + 1;
    }
    var v := r.Str(); var rs := r.Str(); var now := r.Int();
    var a := Act(v, rs, now);
    s := OIS(EffExpiry(cs)) + "|";
    k := 0;
    while k < |cs| { s := s + BS(Allows(cs[k], a)) + BS(Same(cs[k], cs[(k + 1) % |cs|])); k := k + 1; }
  }

  method RunCase(line: string) returns (out: string) {
    var tk := Split(line);
    if |tk| == 0 { return ""; }
    var r := new Rd(tk[1..]);
    var op := tk[0];
    if op == "aud" { var h := r.Bool(); var a := r.Int(); var e := r.Bool(); out := StS(AudienceStatus(h, if a == 0 then AudAbsent else if a == 1 then AudNull else AudStr, e)); }
    else if op == "val" {
      var c := r.Bool(); var iat := r.Int(); var exp := r.Int(); var now := r.Int();
      var v := ValidityDecision(c, iat, exp, now);
      out := match v { case VPass => "pass" case VBadClock => "badclock" case VNotGreater => "notgreater" case VTooLong => "toolong" case VFuture => "future" case VExpired => "expired" };
    }
    else if op == "ver" { var b := r.Bool(); out := StS(VersionStatus(b)); }
    else if op == "gref" { var a := r.Bool(); var b := r.Bool(); var c := r.Bool(); out := StS(GrantRefBoundStatus(a, b, c)); }
    else if op == "ctr" { var b := r.Bool(); out := StS(CounterStatus(b)); }
    else if op == "suite" { var a := r.Bool(); var b := r.Bool(); out := SuiteVS(SuitePolicy(a, b)); }
    else if op == "pqb" { var a := r.Bool(); var b := r.Bool(); var c := r.Bool(); var d := r.Bool(); out := SuiteVS(PqBinding(a, b, c, d)); }
    else if op == "pqr" {
      var a := r.Bool(); var b := r.Bool(); var c := r.Bool(); var d := r.Bool(); var e := r.Bool(); var f := r.Bool(); var g := r.Bool();
      out := match PqResolve(a, b, c, d, e, f, g) { case PqRefused => "refused" case PqTrusted => "trusted" case PqPinned => "pinned" case PqCommitted => "committed" case PqUnbound => "unbound" };
    }
    else if op == "leaf" {
      var p := r.Bool(); var se := r.Int(); var ss := r.Bool(); var vf := r.Bool();
      out := match LeafDecision(p, () => ResOf(se), ss, () => vf) { case LeafPass => "pass" case LeafSuiteErr(m) => "suiteerr" + IS(m) case LeafBadSig => "badsig" };
    }
    else if op == "cap" {
      var ne := r.Bool(); var rg := r.Bool(); var w := r.Int();
      out := match CapChainStatus(ne, () => rg, () => ResOf(w)) { case CapEmpty => "empty" case CapRootNotGrant => "rootnotgrant" case CapWalked(x) => "walked:" + ResS(x) };
    }
    else if op == "hook" { var e := r.Bool(); var o := r.Bool(); out := StS(HookStatus(e, o)); }
    else if op == "plan" {
      var s := r.Bool(); var m := r.Bool(); var a := r.Int();
      out := match PlanDecision(s, m, if a < 0 then None else Some(a != 0)) { case PlanNotEnforced => "ne" case PlanPass => "pass" case PlanMismatch => "mismatch" case PlanUnauthorized => "unauth" };
    }
    else if op == "beacon" {
      var a := r.Bool(); var b := r.Bool(); var c := r.Bool(); var d := r.Bool();
      out := match BeaconDecision(a, b, c, d) { case BeaconNotEnforced => "ne" case BeaconPass => "pass" case BeaconRejected => "rejected" case BeaconReplayed => "replayed" case BeaconUnbound => "unbound" };
    }
    else if op == "rev" {
      var d := r.Int(); var s := r.Int();
      var so: Option<int> := if s < 0 then None else Some(s);
      out := (match RevDecision(d, so) { case RevNoServerClass => "nosc" case RevPass => "pass" case RevLessRestrictive => "less" }) + BS(UseDeclared(d, so));
    }
    else if op == "thr" {
      var t := r.Int(); var rel := r.Bool(); var th := r.Int(); var ht := r.OInt();
      out := match ThresholdRule(t, rel, OptStatus(th), ht) { case ThrOk => "ok" case ThrBelow => "below" case ThrRejected => "rejected" case ThrNoVerifier => "nov" };
    }
    else if op == "core" { out := CoreProg(r); }
    else if op == "vst" { out := VProg(r); }
    else if op == "cav" { out := CaveatOp(r); }
    else if op == "chain" {
      var mode := r.Int(); var n := r.Nat(); var al := r.Int();
      var hops := ReadHops(r, n);
      var res := VerifyChain(hops, (a: int, b: int) => CeqMode(mode, a, b), () => ResOf(al));
      out := match res { case ChainOk => "ok" case ChainBad(e) => ErrS(e) };
    }
    else if op == "th" || op == "th2" {
      // "th2" (recorded production facts) also carries each share's pqPkOk; "th" (the pinned synthetic corpus) leaves it true.
      var t := r.Int();
      var ns := r.Nat(); var es: seq<Signer<int>> := []; var k := 0;
      while k < ns { var ro := r.Int(); var ko := r.Bool(); var po := r.Bool(); var key := r.Int(); es := es + [Signer(RoleOf(ro), ko, po, key)]; k := k + 1; }
      var nsh := r.Nat(); var shs: seq<Share<int>> := []; k := 0;
      while k < nsh { var wf := r.Bool(); var ro := r.Int(); var key := r.Int(); var ak := r.Bool(); var pq := true; if op == "th2" { pq := r.Bool(); } var sg := r.Bool(); shs := shs + [Share(wf, RoleOf(ro), key, ak, pq, () => sg)]; k := k + 1; }
      var hb := r.Bool(); var bl: Option<Baseline<int>> := None;
      if hb { var his := r.Bool(); var h := r.Int(); var pk := r.Bool(); var ls := r.Bool(); bl := Some(Baseline(his, h, () => pk, () => ls)); }
      var v := Verify(es, shs, t, bl);
      out := BS(v.ok) + "|" + IS(v.count) + "|" + RolesS(v.roles) + "|" + ThReasonS(v.reason);
    }
    else if op == "rp" {
      var nowOk := r.Bool(); var vaOk := r.Bool(); var io := r.Bool(); var am := r.Bool(); var iatOk := r.Bool(); var expOk := r.Bool();
      var iat := r.Int(); var exp := r.Int(); var now := r.Int(); var skew := r.Int();
      var lo := r.Bool(); var co := r.Bool(); var cto := r.Bool(); var hn := r.Bool(); var no := r.Bool(); var rn := r.Bool(); var hc := r.Bool();
      var f := Facts(nowOk, vaOk, io, am, iatOk, expOk, iat, exp, now, skew, lo, co, cto, hn, no, rn, hc);
      out := DenyS(Pre(f)) + "|" + (match NonceStage(f) { case SkipNonce => "skip" case ConsumeNonce => "consume" case DenyNonce => "deny" }) + "|" + IS(RetainUntil(f))
        + "|" + DenyS(Decide(f, false, false)) + "," + DenyS(Decide(f, false, true)) + "," + DenyS(Decide(f, true, false)) + "," + DenyS(Decide(f, true, true));
    }
    else if op == "store" {
      var maxE := r.Nat(); var n := r.Nat();
      var s := Store(map[], map[], maxE);
      out := "";
      var k := 0;
      while k < n {
        var o := r.Str();
        if o == "C" { var key := r.Str(); var rt := r.Int(); var now := r.Int(); var x := ConsumeOnce(s, key, rt, now); s := x.0; out := out + OutS(x.1); }
        else if o == "P" { var now := r.Int(); var x := Apply(s, Prune(now)); s := x.0; out := out + OutS(x.1); }
        else { var st := r.Str(); var c := r.Int(); var x := AdvanceCounter(s, st, c); s := x.0; out := out + OutS(x.1); }
        k := k + 1;
      }
      out := out + "|" + IS(|s.seen|) + "|" + IS(|s.streams|);
    }
    else { out := "?"; }
  }

  method Run(path: string) {
    var rd := FileIO.ReadBytesFromFile(path);
    if rd.Failure? { print "ERR ", rd.error, "\n"; return; }
    var bytes := rd.value;
    var cur: string := "";
    var k := 0;
    while k < |bytes| {
      var b := bytes[k];
      if b == 10 {
        var o := RunCase(cur);
        print o, "\n";
        cur := "";
      } else { cur := cur + [(b as int) as char]; }
      k := k + 1;
    }
  }
}

method Main(args: seq<string>) {
  if |args| < 2 { print "usage: harness <casefile>\n"; return; }
  Harness.Run(args[1]);
}
