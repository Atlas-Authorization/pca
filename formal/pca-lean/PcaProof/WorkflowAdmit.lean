/-
  K5 theorem -- workflow (DAG) admission and the receipt chain (packages/pca/src/workflow.ts: admitStep, receiptError).
  Complements formal/dafny/WorkflowAdmit.dfy with a second, independent proof in a different system.

  Model. A workflow is a list of steps (id, dependency ids, cost) with a step cap and a cost cap; a run is the list of receipts so far
  (step, seqNo, ok, output number). `Admit` is the conjunction the TypeScript reference checks (planned, not yet run, within the step
  budget and the cost cap, every dependency has an ok receipt, every edge into the step holds). Digests and signatures are not modelled:
  a receipt link is the consecutive `seqNo` (the real link is a collision-resistant digest, an assumption outside this file).

  Results (no `sorry`, no axiom, core Lean only):
    * admit_planned / admit_not_done / admit_deps_ok / admit_edges_hold / admit_within_budget / admit_within_cost
    * chain_append     appending a receipt with the next seqNo and a fresh step keeps the chain valid, and conversely
    * chain_nodup      a valid chain has pairwise distinct steps
    * admit_run_invariant  running an admitted step keeps the chain valid and the cost within the cap (the invariant of a run)
-/
namespace PcaProof.WorkflowAdmit

structure Step where
  id   : Nat
  deps : List Nat
  cost : Nat

structure Rcpt where
  step  : Nat
  seqNo : Nat
  ok    : Bool
  num   : Int

structure Edge where
  src : Nat
  dst : Nat
  rel : Int → Int → Prop   -- request value → source output → holds

structure Wf where
  steps    : List Step
  edges    : List Edge
  maxSteps : Nat
  cap      : Nat

/-- Receipt chain: consecutive sequence numbers from `n`, and no step repeated. -/
def chainFrom : Nat → List Rcpt → Prop
  | _, [] => True
  | n, r :: rs => r.seqNo = n ∧ r.step ∉ rs.map Rcpt.step ∧ chainFrom (n + 1) rs

def Chain (rs : List Rcpt) : Prop := chainFrom 0 rs

def hasReceipt (rs : List Rcpt) (id : Nat) : Prop := id ∈ rs.map Rcpt.step
def hasOk (rs : List Rcpt) (id : Nat) : Prop := ∃ r ∈ rs, r.step = id ∧ r.ok = true

def stepCost (ss : List Step) (id : Nat) : Nat :=
  match ss.find? (fun s => s.id == id) with
  | some s => s.cost
  | none => 0

def spent (w : Wf) : List Rcpt → Nat
  | [] => 0
  | r :: rs => stepCost w.steps r.step + spent w rs

def Admit (w : Wf) (rs : List Rcpt) (s : Step) (req : Edge → Int) : Prop :=
  Chain rs
  ∧ s ∈ w.steps
  ∧ ¬ hasReceipt rs s.id
  ∧ rs.length + 1 ≤ w.maxSteps
  ∧ spent w rs + s.cost ≤ w.cap
  ∧ (∀ d ∈ s.deps, hasOk rs d)
  ∧ (∀ e ∈ w.edges, e.dst = s.id → ∀ r ∈ rs, r.step = e.src → e.rel (req e) r.num)

theorem admit_planned {w rs s req} (h : Admit w rs s req) : s ∈ w.steps := h.2.1
theorem admit_not_done {w rs s req} (h : Admit w rs s req) : ¬ hasReceipt rs s.id := h.2.2.1
theorem admit_within_budget {w rs s req} (h : Admit w rs s req) : rs.length + 1 ≤ w.maxSteps := h.2.2.2.1
theorem admit_within_cost {w rs s req} (h : Admit w rs s req) : spent w rs + s.cost ≤ w.cap := h.2.2.2.2.1
theorem admit_deps_ok {w rs s req} (h : Admit w rs s req) : ∀ d ∈ s.deps, hasOk rs d := h.2.2.2.2.2.1
theorem admit_edges_hold {w rs s req} (h : Admit w rs s req) :
    ∀ e ∈ w.edges, e.dst = s.id → ∀ r ∈ rs, r.step = e.src → e.rel (req e) r.num := h.2.2.2.2.2.2

/-- A step outside the workflow is never admitted. -/
theorem unplanned_denied {w rs s req} (h : s ∉ w.steps) : ¬ Admit w rs s req := fun a => h a.2.1

/-- A dependency without an ok receipt denies. -/
theorem reorder_denied {w rs s req d} (hd : d ∈ s.deps) (hn : ¬ hasOk rs d) : ¬ Admit w rs s req :=
  fun a => hn (a.2.2.2.2.2.1 d hd)

theorem chainFrom_append (rs : List Rcpt) (r : Rcpt) : ∀ n,
    chainFrom n (rs ++ [r]) ↔ chainFrom n rs ∧ r.seqNo = n + rs.length ∧ r.step ∉ rs.map Rcpt.step := by
  induction rs with
  | nil => intro n; simp [chainFrom]
  | cons x xs ih =>
    intro n
    have ih' := ih (n + 1)
    simp only [List.cons_append, chainFrom, List.map_cons, List.mem_cons, List.map_append, List.mem_append,
      List.length_cons, List.map_nil, List.not_mem_nil, or_false, ih']
    constructor
    · rintro ⟨h1, h2, h3, h4, h5⟩
      refine ⟨⟨h1, fun hm => h2 (Or.inl hm), h3⟩, by omega, ?_⟩
      intro hm
      rcases hm with hm | hm
      · exact h2 (Or.inr hm.symm)
      · exact h5 hm
    · rintro ⟨⟨h1, h2, h3⟩, h4, h5⟩
      refine ⟨h1, ?_, h3, by omega, fun hm => h5 (Or.inr hm)⟩
      intro hm
      rcases hm with hm | hm
      · exact h2 hm
      · exact h5 (Or.inl hm.symm)

theorem chain_append {rs : List Rcpt} {r : Rcpt} :
    Chain (rs ++ [r]) ↔ Chain rs ∧ r.seqNo = rs.length ∧ r.step ∉ rs.map Rcpt.step := by
  simpa [Chain] using chainFrom_append rs r 0

theorem chainFrom_nodup : ∀ (n : Nat) (rs : List Rcpt), chainFrom n rs → (rs.map Rcpt.step).Nodup
  | _, [], _ => by simp
  | n, r :: rs, h => by
    simp only [chainFrom] at h
    simp only [List.map_cons, List.nodup_cons]
    exact ⟨h.2.1, chainFrom_nodup (n + 1) rs h.2.2⟩

theorem chain_nodup {rs : List Rcpt} (h : Chain rs) : (rs.map Rcpt.step).Nodup := chainFrom_nodup 0 rs h

theorem spent_append (w : Wf) (rs : List Rcpt) (r : Rcpt) : spent w (rs ++ [r]) = spent w rs + stepCost w.steps r.step := by
  induction rs with
  | nil => simp [spent]
  | cons x xs ih => simp [spent, ih]; omega

/-- Running an admitted step (the receipt carries its id, the next sequence number) keeps the chain valid and the spend within the cap. -/
theorem admit_run_invariant {w rs s req} (h : Admit w rs s req) (hs : stepCost w.steps s.id = s.cost) :
    Chain (rs ++ [{ step := s.id, seqNo := rs.length, ok := true, num := 0 }])
    ∧ spent w (rs ++ [{ step := s.id, seqNo := rs.length, ok := true, num := 0 }]) ≤ w.cap := by
  refine ⟨?_, ?_⟩
  · rw [chain_append]
    exact ⟨h.1, rfl, h.2.2.1⟩
  · rw [spent_append]
    simp only
    rw [hs]
    exact h.2.2.2.2.1

end PcaProof.WorkflowAdmit
