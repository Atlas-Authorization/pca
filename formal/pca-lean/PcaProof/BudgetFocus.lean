/-
  BudgetFocus: the transfer argument behind the focus encoding of
  `formal/tamarin/pca_budget_v5_focus.spthy` ("any node is the root of its own meter").

  v5 is v4 plus copies of the allocation rules and the mid-debit rule in which one node's meter is the fact
  symbol `FCnt` instead of `Cnt`. The copies also carry extra labels (`Focus(n)`, `FDebited(s, n)`). A v5
  lemma about the focused node holds for every node of v4 if every v4 run can be replayed in v5 with that
  node focused and the same labels, up to the extra ones. This file proves the replay for an arbitrary
  multiset-rewriting system (Tamarin's semantics), given one per-instance hypothesis.

  Semantics. A state is a fact-count vector `Fact → Nat` (a multiset). A rule instance has premise and
  conclusion count vectors and a list of labels. It is enabled when its premises are present, and firing it
  takes the state `S` to `S - pre + post`. Persistent facts `!F` are premises that the instance also
  re-produces; `Fr`, `In`, `K`, `Debit`, ... are `other` facts, which the proof never inspects. A run is a
  list of instances, each one enabled in the state its predecessor produced.

  Renaming. `swap n` exchanges `Cnt(n, c)` and `FCnt(n, c)` and is the identity on every other fact
  (`swap_swap`: it is an involution). The hypothesis `Corr n erase ri ri'` says that the v5 instance `ri'`
  is the v4 instance `ri` with its facts renamed by `swap n`, and with the same labels once `erase` drops the
  focus-only labels.

  Theorems (no `sorry`):
    * `enabled_ren`, `fire_ren`: renaming commutes with enabledness and with firing.
    * `simulation`: every v4 run from `S` gives a v5 run, step by step, from `S ∘ swap n`. The i-th v5
      instance corresponds to the i-th v4 instance, so the label sequences agree up to `erase`
      (`simulation_labels`).
    * `simulation_from_empty`: Tamarin runs start from the empty state, which `swap` fixes, so a v5 run
      exists from the same initial state.

  Instantiation (read off the two theories, not extracted): fix the node `n` to focus.
    * A v4 instance that does not touch `Cnt(n, .)` maps to itself, and v5 contains every v4 rule.
    * `Alloc_Child_R/D` for `n` maps to `Alloc_Child_R/D_F`, with extra label `Focus(n)`.
    * `Debit_Mid` debiting `n` maps to `Debit_Mid_F`, with extra label `FDebited(s, n)`.
  `n`'s own allocation and debit instances are the only ones that produce or consume `Cnt(n, .)`, because `n`
  contains a fresh `~id`. So the hypothesis `hR` holds with `erase` = "drop Focus/FDebited". The replayed run
  contains exactly one `Focus` label, at `n`'s allocation (allocated once: Tamarin `nb_alloc_unique`), so it
  satisfies the v5 restriction `single_focus`. A v5 all-traces lemma about the focused node, for example
  `node_bound_focus_c2`, therefore holds for `n` in every v4 trace.
-/
namespace PcaProof.BudgetFocus

/-- Facts: the meter of a node, the FOCUSED meter of a node, and every other fact. -/
inductive Fact (Node Val Other : Type) where
  | cnt   (n : Node) (c : Val)
  | fcnt  (n : Node) (c : Val)
  | other (o : Other)

variable {Node Val Other Act : Type} [DecidableEq Node]

/-- The v5 renaming for the focused node `n`: swap `Cnt(n, c)` and `FCnt(n, c)`. -/
def swap (n : Node) : Fact Node Val Other → Fact Node Val Other
  | .cnt m c  => if m = n then .fcnt m c else .cnt m c
  | .fcnt m c => if m = n then .cnt m c else .fcnt m c
  | .other o  => .other o

theorem swap_swap (n : Node) (f : Fact Node Val Other) : swap n (swap n f) = f := by
  cases f with
  | cnt m c => by_cases h : m = n <;> simp [swap, h]
  | fcnt m c => by_cases h : m = n <;> simp [swap, h]
  | other o => rfl

/-- A state: how many copies of each fact are present. -/
abbrev State (Node Val Other : Type) := Fact Node Val Other → Nat

/-- A ground rule instance: consumed premises, produced conclusions, labels (action facts). -/
structure Inst (Node Val Other Act : Type) where
  pre  : State Node Val Other
  post : State Node Val Other
  acts : List Act

def enabled (S : State Node Val Other) (ri : Inst Node Val Other Act) : Prop :=
  ∀ f, ri.pre f ≤ S f

def fire (S : State Node Val Other) (ri : Inst Node Val Other Act) : State Node Val Other :=
  fun f => S f - ri.pre f + ri.post f

/-- A run of the rule set `R` from state `S`: every instance is a rule instance of `R` and enabled. -/
def Run (R : Inst Node Val Other Act → Prop) : State Node Val Other → List (Inst Node Val Other Act) → Prop
  | _, [] => True
  | S, ri :: rs => R ri ∧ enabled S ri ∧ Run R (fire S ri) rs

/-- `ri'` is `ri` with its facts renamed by `swap n`, and with the same labels up to `erase`. -/
structure Corr (n : Node) (erase : List Act → List Act)
    (ri ri' : Inst Node Val Other Act) : Prop where
  pre  : ∀ f, ri'.pre f = ri.pre (swap n f)
  post : ∀ f, ri'.post f = ri.post (swap n f)
  acts : erase ri'.acts = ri.acts

/-- Step-by-step correspondence of two runs. -/
inductive Sim (n : Node) (erase : List Act → List Act) :
    List (Inst Node Val Other Act) → List (Inst Node Val Other Act) → Prop
  | nil : Sim n erase [] []
  | cons {ri ri' rs rs'} : Corr n erase ri ri' → Sim n erase rs rs' → Sim n erase (ri :: rs) (ri' :: rs')

/-- The renamed state. -/
def ren (n : Node) (S : State Node Val Other) : State Node Val Other := fun f => S (swap n f)

theorem enabled_ren {n : Node} {erase : List Act → List Act} {S : State Node Val Other}
    {ri ri' : Inst Node Val Other Act} (hc : Corr n erase ri ri') (he : enabled S ri) :
    enabled (ren n S) ri' := by
  intro f
  rw [hc.pre f]
  exact he (swap n f)

theorem fire_ren {n : Node} {erase : List Act → List Act} {S : State Node Val Other}
    {ri ri' : Inst Node Val Other Act} (hc : Corr n erase ri ri') :
    fire (ren n S) ri' = ren n (fire S ri) := by
  funext f
  show S (swap n f) - ri'.pre f + ri'.post f = S (swap n f) - ri.pre (swap n f) + ri.post (swap n f)
  rw [hc.pre f, hc.post f]

/-- **Simulation.** If every rule instance of `R4` has a renamed counterpart in `R5`, then every `R4` run from `S`
    is matched, instance by instance, by an `R5` run from the renamed state. -/
theorem simulation (n : Node) (erase : List Act → List Act)
    (R4 R5 : Inst Node Val Other Act → Prop)
    (hR : ∀ ri, R4 ri → ∃ ri', R5 ri' ∧ Corr n erase ri ri') :
    ∀ (rs : List (Inst Node Val Other Act)) (S : State Node Val Other), Run R4 S rs →
      ∃ rs', Run R5 (ren n S) rs' ∧ Sim n erase rs rs' := by
  intro rs
  induction rs with
  | nil => intro S _; exact ⟨[], trivial, Sim.nil⟩
  | cons ri rs ih =>
    intro S h
    obtain ⟨hr, he, hrest⟩ := h
    obtain ⟨ri', hr', hc⟩ := hR ri hr
    obtain ⟨rs', hrun', hsim⟩ := ih (fire S ri) hrest
    refine ⟨ri' :: rs', ⟨hr', enabled_ren hc he, ?_⟩, Sim.cons hc hsim⟩
    rw [fire_ren hc]
    exact hrun'

/-- Corresponding runs have the same label sequence up to `erase`. -/
theorem simulation_labels {n : Node} {erase : List Act → List Act}
    {rs rs' : List (Inst Node Val Other Act)} (h : Sim n erase rs rs') :
    rs'.map (fun r => erase r.acts) = rs.map (fun r => r.acts) := by
  induction h with
  | nil => rfl
  | cons hc _ ih => rw [List.map_cons, List.map_cons, hc.acts, ih]

/-- Tamarin runs start from the empty multiset, which the renaming fixes. -/
theorem ren_empty (n : Node) : ren n (fun _ => 0 : State Node Val Other) = (fun _ => 0) := rfl

/-- **Transfer.** Every v4 run from the empty state is replayed by a v5 run from the empty state, with labels equal
    up to `erase`. -/
theorem simulation_from_empty (n : Node) (erase : List Act → List Act)
    (R4 R5 : Inst Node Val Other Act → Prop)
    (hR : ∀ ri, R4 ri → ∃ ri', R5 ri' ∧ Corr n erase ri ri')
    (rs : List (Inst Node Val Other Act)) (h : Run R4 (fun _ => 0) rs) :
    ∃ rs', Run R5 (fun _ => 0) rs' ∧ rs'.map (fun r => erase r.acts) = rs.map (fun r => r.acts) := by
  obtain ⟨rs', hrun, hsim⟩ := simulation n erase R4 R5 hR rs (fun _ => 0) h
  exact ⟨rs', hrun, simulation_labels hsim⟩

end PcaProof.BudgetFocus
