// WorkflowAdmit.dfy - the admission rule of a committed workflow (DAG) (track K5). Standalone; no assume / axiom / extern.
//
// The TypeScript reference (packages/pca/src/workflow.ts, admitStep) is a pure function over a signed workflow, the chain of
// signed step receipts so far and one request. This model keeps what the safety claims are about and abstracts what they are not
// about: signatures and digests are not modelled (a receipt "link" is the pair (step, seq) of its predecessor; the real link is a
// collision-resistant digest, an assumption outside this file), and each receipt carries ONE integer output.
// What is proved:
//   AdmittedIsPlanned      a step that is admitted is a step of the committed workflow (no step outside the DAG is admitted);
//   UnplannedDenied        the contrapositive;
//   AdmittedNotDone        a step is admitted at most once (no replay of a step);
//   AdmittedWithinBudget   an admission never exceeds the step budget;
//   AdmittedWithinCap      nor the cost cap (the spend so far plus this step's cost is at most the cap);
//   SpentAppend, RunInvariant  the spend of a run is the sum of its steps' costs, and running an admitted step keeps chain and cap;
//   AdmittedDepsMet        every dependency of an admitted step has an ok receipt, or is covered by a declared promise;
//   ReorderDenied          a missing dependency that no promise covers denies;
//   AdmittedEdgesHold      every edge into the admitted step whose source has a receipt is satisfied by the request's value;
//   ChainAppend            appending a correctly linked, not-yet-present receipt keeps the receipt chain valid;
//   ChainPrefix            every prefix of a valid chain is a valid chain;
//   ChainDistinct          a valid chain has at most one receipt per step.
module WorkflowAdmit {
  datatype Option<T> = None | Some(v: T)
  datatype Op = Eq | Le | Ge | Lt | Gt
  datatype Step = Step(id: string, deps: seq<string>, cost: nat)
  datatype Edge = Edge(from: string, to: string, op: Op, promise: bool)
  datatype Wf = Wf(steps: seq<Step>, edges: seq<Edge>, maxSteps: nat, cap: nat)
  datatype Rcpt = Rcpt(step: string, seqNo: nat, prev: Option<(string, nat)>, ok: bool, num: int)

  function RefOf(r: Rcpt): (string, nat) { (r.step, r.seqNo) }

  predicate HasStep(w: Wf, id: string) { exists i :: 0 <= i < |w.steps| && w.steps[i].id == id }
  predicate HasReceipt(rs: seq<Rcpt>, id: string) { exists i :: 0 <= i < |rs| && rs[i].step == id }
  predicate HasOkReceipt(rs: seq<Rcpt>, id: string) { exists i :: 0 <= i < |rs| && rs[i].step == id && rs[i].ok }
  ghost function NumOf(rs: seq<Rcpt>, id: string): int
    requires HasReceipt(rs, id)
  {
    var i :| 0 <= i < |rs| && rs[i].step == id;
    rs[i].num
  }

  predicate Rel(op: Op, req: int, src: int) {
    match op
    case Eq => req == src
    case Le => req <= src
    case Ge => req >= src
    case Lt => req < src
    case Gt => req > src
  }

  // The cost of the (first) step with this id; the sum over a run of receipts.
  function StepCost(ss: seq<Step>, id: string): nat decreases |ss| {
    if |ss| == 0 then 0 else if ss[0].id == id then ss[0].cost else StepCost(ss[1..], id)
  }
  function Spent(w: Wf, rs: seq<Rcpt>): nat decreases |rs| {
    if |rs| == 0 then 0 else Spent(w, rs[..|rs| - 1]) + StepCost(w.steps, rs[|rs| - 1].step)
  }

  predicate ChainOk(rs: seq<Rcpt>) {
    (forall i :: 0 <= i < |rs| ==> rs[i].seqNo == i)
    && (|rs| > 0 ==> rs[0].prev.None?)
    && (forall i :: 1 <= i < |rs| ==> rs[i].prev == Some(RefOf(rs[i - 1])))
    && (forall i, j :: 0 <= j < i < |rs| ==> rs[j].step != rs[i].step)
  }

  // The edges from `d` into `s` are all declared promises (and there is at least one).
  predicate PromiseCovered(w: Wf, d: string, s: string) {
    (exists k :: 0 <= k < |w.edges| && w.edges[k].from == d && w.edges[k].to == s)
    && (forall k :: 0 <= k < |w.edges| && w.edges[k].from == d && w.edges[k].to == s ==> w.edges[k].promise)
  }

  predicate DepsOk(w: Wf, rs: seq<Rcpt>, s: Step) {
    forall d :: d in s.deps ==> HasOkReceipt(rs, d) || (!HasReceipt(rs, d) && PromiseCovered(w, d, s.id))
  }

  // Every edge into `s` whose source already has a receipt holds for the request's value `p(edge)`.
  ghost predicate EdgesOk(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int) {
    forall k :: 0 <= k < |w.edges| && w.edges[k].to == s && HasReceipt(rs, w.edges[k].from) ==>
      Rel(w.edges[k].op, p(w.edges[k]), NumOf(rs, w.edges[k].from))
  }

  ghost predicate Admit(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int) {
    ChainOk(rs)
    && HasStep(w, s)
    && !HasReceipt(rs, s)
    && |rs| + 1 <= w.maxSteps
    && (exists i :: 0 <= i < |w.steps| && w.steps[i].id == s && Spent(w, rs) + StepCost(w.steps, s) <= w.cap)
    && (exists i :: 0 <= i < |w.steps| && w.steps[i].id == s && DepsOk(w, rs, w.steps[i]))
    && EdgesOk(w, rs, s, p)
  }

  lemma AdmittedIsPlanned(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int)
    requires Admit(w, rs, s, p)
    ensures HasStep(w, s)
  {
  }

  lemma UnplannedDenied(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int)
    requires !HasStep(w, s)
    ensures !Admit(w, rs, s, p)
  {
  }

  lemma AdmittedNotDone(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int)
    requires Admit(w, rs, s, p)
    ensures !HasReceipt(rs, s)
  {
  }

  lemma AdmittedWithinBudget(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int)
    requires Admit(w, rs, s, p)
    ensures |rs| + 1 <= w.maxSteps
  {
  }

  lemma AdmittedWithinCap(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int)
    requires Admit(w, rs, s, p)
    ensures Spent(w, rs) + StepCost(w.steps, s) <= w.cap
  {
    var i :| 0 <= i < |w.steps| && w.steps[i].id == s && Spent(w, rs) + StepCost(w.steps, s) <= w.cap;
  }

  lemma SpentAppend(w: Wf, rs: seq<Rcpt>, r: Rcpt)
    ensures Spent(w, rs + [r]) == Spent(w, rs) + StepCost(w.steps, r.step)
  {
    assert (rs + [r])[..|rs|] == rs;
    assert (rs + [r])[|rs|] == r;
  }

  // The invariant of a run: admitting a step and appending its receipt keeps the chain valid and the spend within the cap.
  lemma RunInvariant(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int, r: Rcpt)
    requires Admit(w, rs, s, p)
    requires r.step == s && r.seqNo == |rs| && (if |rs| == 0 then r.prev.None? else r.prev == Some(RefOf(rs[|rs| - 1])))
    ensures ChainOk(rs + [r])
    ensures Spent(w, rs + [r]) <= w.cap
    ensures |rs + [r]| <= w.maxSteps
  {
    ChainAppend(rs, r);
    SpentAppend(w, rs, r);
    AdmittedWithinCap(w, rs, s, p);
  }

  lemma AdmittedDepsMet(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int)
    requires Admit(w, rs, s, p)
    ensures exists i :: 0 <= i < |w.steps| && w.steps[i].id == s
              && forall d :: d in w.steps[i].deps ==> HasOkReceipt(rs, d) || (!HasReceipt(rs, d) && PromiseCovered(w, d, s))
  {
    var i :| 0 <= i < |w.steps| && w.steps[i].id == s && DepsOk(w, rs, w.steps[i]);
    assert forall d :: d in w.steps[i].deps ==> HasOkReceipt(rs, d) || (!HasReceipt(rs, d) && PromiseCovered(w, d, s));
  }

  // A step with a dependency that has no receipt and that no declared promise covers is not admitted (reorder is denied).
  lemma ReorderDenied(w: Wf, rs: seq<Rcpt>, s: string, i: int, d: string, p: Edge -> int)
    requires 0 <= i < |w.steps| && w.steps[i].id == s && d in w.steps[i].deps
    requires !HasReceipt(rs, d) && !PromiseCovered(w, d, s)
    requires forall j, k :: 0 <= j < |w.steps| && 0 <= k < |w.steps| && w.steps[j].id == s && w.steps[k].id == s ==> j == k
    ensures !Admit(w, rs, s, p)
  {
    if Admit(w, rs, s, p) {
      var j :| 0 <= j < |w.steps| && w.steps[j].id == s && DepsOk(w, rs, w.steps[j]);
      assert j == i;
      assert d in w.steps[j].deps;
      assert false;
    }
  }

  lemma AdmittedEdgesHold(w: Wf, rs: seq<Rcpt>, s: string, p: Edge -> int, k: int)
    requires Admit(w, rs, s, p)
    requires 0 <= k < |w.edges| && w.edges[k].to == s && HasReceipt(rs, w.edges[k].from)
    ensures Rel(w.edges[k].op, p(w.edges[k]), NumOf(rs, w.edges[k].from))
  {
  }

  lemma ChainDistinct(rs: seq<Rcpt>, i: int, j: int)
    requires ChainOk(rs) && 0 <= i < j < |rs|
    ensures rs[i].step != rs[j].step
  {
  }

  lemma ChainPrefix(rs: seq<Rcpt>, n: nat)
    requires ChainOk(rs) && n <= |rs|
    ensures ChainOk(rs[..n])
  {
    var t := rs[..n];
    forall i | 0 <= i < n ensures t[i] == rs[i] {}
    forall i | 0 <= i < |t| ensures t[i].seqNo == i { assert t[i] == rs[i]; }
    forall i | 1 <= i < |t| ensures t[i].prev == Some(RefOf(t[i - 1])) { assert t[i] == rs[i]; assert t[i - 1] == rs[i - 1]; }
    forall i, j | 0 <= j < i < |t| ensures t[j].step != t[i].step { assert t[i] == rs[i]; assert t[j] == rs[j]; }
  }

  lemma ChainAppend(rs: seq<Rcpt>, r: Rcpt)
    requires ChainOk(rs)
    requires r.seqNo == |rs|
    requires if |rs| == 0 then r.prev.None? else r.prev == Some(RefOf(rs[|rs| - 1]))
    requires !HasReceipt(rs, r.step)
    ensures ChainOk(rs + [r])
  {
    var all := rs + [r];
    forall i | 0 <= i < |rs| ensures all[i] == rs[i] {}
    assert all[|rs|] == r;
    forall i | 0 <= i < |all| ensures all[i].seqNo == i { if i < |rs| { assert all[i] == rs[i]; } }
    forall i | 1 <= i < |all| ensures all[i].prev == Some(RefOf(all[i - 1])) {
      if i < |rs| { assert all[i] == rs[i]; assert all[i - 1] == rs[i - 1]; } else { assert all[i - 1] == rs[|rs| - 1]; }
    }
    forall i, j | 0 <= j < i < |all| ensures all[j].step != all[i].step {
      if i < |rs| { assert all[i] == rs[i]; assert all[j] == rs[j]; }
      else {
        assert all[j] == rs[j];
        if rs[j].step == r.step { assert HasReceipt(rs, r.step); }
      }
    }
  }
}
