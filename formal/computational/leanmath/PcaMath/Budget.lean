import Mathlib

/-!
# Budget-tree sum invariants (the properties the Tamarin budget model could not prove)

Model of `packages/pca/src/risk.ts`:

* `subBudget(parent, alloc)`           -> `Act.allocate` : a child gets `alloc` only if `alloc <= parent.B`
  (parent *remaining*) ; the child's `B` is `alloc`.
* `debitConsolidatedPath(path, c)`     -> `Act.spend`    : every node on the root..leaf path must cover `c`;
  if ANY cannot nothing changes; otherwise EVERY node on the path is debited by `c` (atomically).
* `nz(c)` / `Number.isFinite`           -> negative or non-integer amounts are rejected (here: `c : Int`, rejected if `c < 0`).
* a spend id is accepted at most once   -> `used` set.
* recharge is by a human only: there is deliberately no `Act` that raises a `rem`.

All state transitions are sequential and atomic; an arbitrary interleaving of concurrent spends is therefore
an arbitrary list of `Act`s, and the theorems quantify over every list.
-/

namespace PcaMath.Budget

structure S where
  lim   : Nat → Nat          -- allocation (limit) of each node
  rem   : Nat → Nat          -- current remaining budget
  spent : Nat → Nat          -- cumulative debits that went through the node
  anc   : Nat → List Nat     -- the path leaf..root of each node
  nodes : Finset Nat
  used  : Finset Nat         -- spend ids already debited
  tot   : Nat                -- total of all accepted spends (ghost)

inductive Act
  | allocate (n p a : Nat)
  | spend (id n : Nat) (c : Int)

/-- initial state: only the root `0`, with limit `L`. -/
def S0 (L : Nat) : S where
  lim := fun n => if n = 0 then L else 0
  rem := fun n => if n = 0 then L else 0
  spent := fun _ => 0
  anc := fun n => if n = 0 then [0] else []
  nodes := {0}
  used := ∅
  tot := 0

open Classical in
noncomputable def step (s : S) : Act → S
  | .allocate n p a =>
      if n ∉ s.nodes ∧ p ∈ s.nodes ∧ a ≤ s.rem p then
        { s with
          lim := Function.update s.lim n a
          rem := Function.update s.rem n a
          spent := Function.update s.spent n 0
          anc := Function.update s.anc n (n :: s.anc p)
          nodes := insert n s.nodes }
      else s
  | .spend id n c =>
      if h : 0 ≤ c ∧ id ∉ s.used ∧ n ∈ s.nodes ∧ ∀ m ∈ s.anc n, c.toNat ≤ s.rem m then
        { s with
          rem := fun m => if m ∈ s.anc n then s.rem m - c.toNat else s.rem m
          spent := fun m => if m ∈ s.anc n then s.spent m + c.toNat else s.spent m
          used := insert id s.used
          tot := s.tot + c.toNat }
      else s

theorem step_alloc (s : S) (n p a : Nat) :
    step s (.allocate n p a) =
      if n ∉ s.nodes ∧ p ∈ s.nodes ∧ a ≤ s.rem p then
        { s with
          lim := Function.update s.lim n a
          rem := Function.update s.rem n a
          spent := Function.update s.spent n 0
          anc := Function.update s.anc n (n :: s.anc p)
          nodes := insert n s.nodes }
      else s := rfl

theorem step_spend (s : S) (id n : Nat) (c : Int) :
    step s (.spend id n c) =
      if h : 0 ≤ c ∧ id ∉ s.used ∧ n ∈ s.nodes ∧ ∀ m ∈ s.anc n, c.toNat ≤ s.rem m then
        { s with
          rem := fun m => if m ∈ s.anc n then s.rem m - c.toNat else s.rem m
          spent := fun m => if m ∈ s.anc n then s.spent m + c.toNat else s.spent m
          used := insert id s.used
          tot := s.tot + c.toNat }
      else s := rfl

noncomputable def run (s : S) : List Act → S
  | [] => s
  | a :: as => run (step s a) as

/-- the invariant -/
structure Inv (s : S) : Prop where
  root : 0 ∈ s.nodes
  conserve : ∀ n ∈ s.nodes, s.rem n + s.spent n = s.lim n
  anc_head : ∀ n ∈ s.nodes, ∃ l, s.anc n = n :: l
  anc_root : ∀ n ∈ s.nodes, 0 ∈ s.anc n
  anc_sub : ∀ n ∈ s.nodes, ∀ m ∈ s.anc n, m ∈ s.nodes
  tot_eq : s.tot = s.spent 0

theorem inv_init (L : Nat) : Inv (S0 L) where
  root := by simp [S0]
  conserve := by intro n hn; simp [S0] at hn; subst hn; simp [S0]
  anc_head := by intro n hn; simp [S0] at hn; subst hn; exact ⟨[], by simp [S0]⟩
  anc_root := by intro n hn; simp [S0] at hn; subst hn; simp [S0]
  anc_sub := by intro n hn m hm; simp [S0] at hn; subst hn; simpa [S0] using hm
  tot_eq := by simp [S0]

theorem inv_step (s : S) (h : Inv s) (a : Act) : Inv (step s a) := by
  classical
  cases a with
  | allocate n p a' =>
    rw [step_alloc]
    split_ifs with hc
    · obtain ⟨hn, hp, hrem⟩ := hc
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · simp [h.root]
      · intro m hm
        simp only [Finset.mem_insert] at hm
        rcases hm with rfl | hm
        · simp
        · have hne : m ≠ n := fun e => hn (e ▸ hm)
          simp [Function.update_of_ne hne, h.conserve m hm]
      · intro m hm
        simp only [Finset.mem_insert] at hm
        rcases hm with rfl | hm
        · exact ⟨s.anc p, by simp⟩
        · have hne : m ≠ n := fun e => hn (e ▸ hm)
          simpa [Function.update_of_ne hne] using h.anc_head m hm
      · intro m hm
        simp only [Finset.mem_insert] at hm
        rcases hm with rfl | hm
        · simp [h.anc_root p hp]
        · have hne : m ≠ n := fun e => hn (e ▸ hm)
          simpa [Function.update_of_ne hne] using h.anc_root m hm
      · intro m hm k hk
        simp only [Finset.mem_insert] at hm
        simp only [Finset.mem_insert]
        rcases hm with rfl | hm
        · simp at hk
          rcases hk with rfl | hk
          · simp
          · exact Or.inr (h.anc_sub p hp k hk)
        · have hne : m ≠ n := fun e => hn (e ▸ hm)
          have : k ∈ s.anc m := by simpa [Function.update_of_ne hne] using hk
          exact Or.inr (h.anc_sub m hm k this)
      · have hne : (0 : Nat) ≠ n := fun e => hn (e ▸ h.root)
        simp [Function.update_of_ne hne, h.tot_eq]
    · exact h
  | spend id n c =>
    rw [step_spend]
    split_ifs with hc
    · obtain ⟨hc0, hid, hn, hcov⟩ := hc
      refine ⟨h.root, ?_, ?_, ?_, ?_, ?_⟩
      · intro m hm
        simp only
        by_cases hmm : m ∈ s.anc n
        · simp only [hmm, if_true]
          have := h.conserve m hm
          have := hcov m hmm
          omega
        · simp only [hmm, if_false]; exact h.conserve m hm
      · intro m hm; exact h.anc_head m hm
      · intro m hm; exact h.anc_root m hm
      · intro m hm k hk; exact h.anc_sub m hm k hk
      · have h0 : 0 ∈ s.anc n := h.anc_root n hn
        simp [h0, h.tot_eq]
    · exact h

theorem inv_run (L : Nat) (as : List Act) : Inv (run (S0 L) as) := by
  suffices ∀ (s : S) (as : List Act), Inv s → Inv (run s as) from this _ _ (inv_init L)
  intro s as
  induction as generalizing s with
  | nil => intro h; exact h
  | cons a as ih => intro h; exact ih _ (inv_step s h a)

/-- (2) every node's cumulative spend is at most its allocation. -/
theorem node_bound (L : Nat) (as : List Act) (n : Nat) (hn : n ∈ (run (S0 L) as).nodes) :
    (run (S0 L) as).spent n ≤ (run (S0 L) as).lim n := by
  have := (inv_run L as).conserve n hn
  omega

theorem lim0_step (s : S) (h0 : 0 ∈ s.nodes) (a : Act) : (step s a).lim 0 = s.lim 0 ∧ 0 ∈ (step s a).nodes := by
  classical
  cases a with
  | allocate n p a' =>
    rw [step_alloc]; split_ifs with hc
    · have hne : (0 : Nat) ≠ n := fun e => hc.1 (e ▸ h0)
      simp [Function.update_of_ne hne, h0]
    · exact ⟨rfl, h0⟩
  | spend id n c =>
    rw [step_spend]; split_ifs with hc
    · exact ⟨rfl, h0⟩
    · exact ⟨rfl, h0⟩

theorem lim0_run (s : S) (h0 : 0 ∈ s.nodes) (as : List Act) : (run s as).lim 0 = s.lim 0 := by
  induction as generalizing s with
  | nil => rfl
  | cons a as ih =>
    have := lim0_step s h0 a
    simp only [run]
    rw [ih _ this.2, this.1]

/-- (1) the total of all accepted spends never exceeds the root limit, for every interleaving. -/
theorem root_bound (L : Nat) (as : List Act) : (run (S0 L) as).tot ≤ L := by
  have hi := inv_run L as
  have h0 := hi.conserve 0 hi.root
  have hl : (run (S0 L) as).lim 0 = L := by
    rw [lim0_run _ (by simp [S0]) as]; simp [S0]
  rw [hi.tot_eq]
  omega

/-- (3a) a negative amount is rejected (no state change). -/
theorem no_negative_spend (s : S) (id n : Nat) (c : Int) (hc : c < 0) : step s (.spend id n c) = s := by
  rw [step_spend, dif_neg]
  intro h; exact absurd h.1 (by omega)

/-- (3b) a spend id debits at most once: an id that is already used is rejected (no state change). -/
theorem no_double_spend (s : S) (id n : Nat) (c : Int) (hu : id ∈ s.used) : step s (.spend id n c) = s := by
  rw [step_spend, dif_neg]
  intro h; exact h.2.1 hu

/-- and an accepted spend marks its id as used. -/
theorem spend_marks_used (s : S) (id n : Nat) (c : Int) (h : step s (.spend id n c) ≠ s) :
    id ∈ (step s (.spend id n c)).used := by
  rw [step_spend] at h ⊢
  by_cases hc : 0 ≤ c ∧ id ∉ s.used ∧ n ∈ s.nodes ∧ ∀ m ∈ s.anc n, c.toNat ≤ s.rem m
  · rw [dif_pos hc]; simp
  · rw [dif_neg hc] at h; exact absurd rfl h

/-- (4) allocation monotone: an accepted allocation never exceeds the parent's remaining budget at that time. -/
theorem alloc_monotone (s : S) (n p a : Nat) (h : (step s (.allocate n p a)).nodes ≠ s.nodes) : a ≤ s.rem p := by
  classical
  simp only [step] at h
  split_ifs at h with hc
  · exact hc.2.2
  · exact absurd rfl h

/-! ## (5) The attack variants, as checked counter-examples (over `Int` so that overdraw is visible).

Root limit 10; two children each allocated 10 (the parent check `alloc <= remaining` passes for both
because allocation does not debit the parent).  Spending 10 through each child is accepted by the correct
semantics only for the first; the variants overspend the root. -/

/-- leaf-only debit: only the acting node is debited. -/
def leafOnly (rem : Fin 3 → Int) (leaf : Fin 3) (c : Int) : Fin 3 → Int :=
  fun m => if m = leaf then rem m - c else rem m

/-- no ancestor check: debit the whole path (root 0, leaf) but check only the leaf. -/
def noAncestorCheck (rem : Fin 3 → Int) (leaf : Fin 3) (c : Int) : Option (Fin 3 → Int) :=
  if c ≤ rem leaf then some (fun m => if m = leaf ∨ m = 0 then rem m - c else rem m) else none

/-- correct: check the whole path, debit the whole path. -/
def correct (rem : Fin 3 → Int) (leaf : Fin 3) (c : Int) : Option (Fin 3 → Int) :=
  if c ≤ rem leaf ∧ c ≤ rem 0 then some (fun m => if m = leaf ∨ m = 0 then rem m - c else rem m) else none

def start : Fin 3 → Int := fun m => 10   -- root and both children hold 10

/-- leaf-only debit: two children spend 10 each, total 20 > root limit 10, root untouched. -/
example : (leafOnly (leafOnly start 1 10) 2 10) 0 = 10 ∧ (10 : Int) + 10 > 10 := by decide

/-- dropping the ancestor check: the root is overdrawn (balance -10 < 0). -/
example : ∃ r, (noAncestorCheck start 1 10 >>= fun s1 => noAncestorCheck s1 2 10) = some r ∧ r 0 < 0 := by decide

/-- the correct semantics rejects the second spend. -/
example : (correct start 1 10 >>= fun s1 => correct s1 2 10) = none := by decide

/-- non-atomic debit: both spends pass the check against the same snapshot, then both debit. -/
example : let snap := start
          (snap 1 ≥ 10 ∧ snap 0 ≥ 10) ∧ (snap 2 ≥ 10 ∧ snap 0 ≥ 10) ∧
          ((fun m : Fin 3 => if m = 1 ∨ m = 0 then snap m - 10 else snap m) 0 - 10 < 0) := by decide

end PcaMath.Budget
