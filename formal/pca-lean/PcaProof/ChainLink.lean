/-
  ChainLink — the RECURSIVE hop-by-hop chain walk equals the fold definition of effective authority.

  This file justifies the encoding used by the unbounded Tamarin model
  `formal/tamarin/pca_actn_unbounded.spthy`.  There the verifier is a linear state machine
  `Walk_Start / Walk_Step / Walk_Finish`: ONE hop is processed per rule step, each step requires that hop's
  caveat to permit the action's verb, and the run is accepted iff the walk reaches the root with every hop
  having passed.  That is exactly the recursion `walk` / `tWalk` below (head hop checked, then recurse on the
  tail; empty list = reached the root = accepted).

  The Lean definitions of authority elsewhere (Attenuation.lean) are FOLDS:
      `Eff caveats a  :=  ∀ cav ∈ caveats, Satisfies cav a`     (conjunction of every caveat along the chain).

  Theorems (no `sorry`):
    * `walk_iff_eff`        — recursive walk over a caveat list  ↔  `Eff` (the fold).
    * `walkH_iff_eff_flatten` — same for chains whose hops each add a LIST of caveats (append-only chains).
    * `tWalk_iff_forall`, `tWalk_iff_eff` — the model-level abstraction used in Tamarin (a hop caveat is
      either `any` or a verb pin `cv = v`): the recursive walk accepts iff every hop permits the verb, and that
      is `Attenuation.Eff` of the corresponding concrete caveats (`any` ↦ no constraint, `verb w` ↦ `verb_in [w]`).
    * `walk_append`, `walk_prefix` — walking is compositional over append and monotone: if the walk over
      `p ++ s` accepts then the walk over the prefix `p` accepts (attenuation: extra hops only narrow).
    * `walkH_hops`          — for the append-only chain built by `Attenuation.hops`, the walk over the list
      of hop-added extensions of a hop equals `Eff` of that hop's cumulative caveat list.
-/
import PcaProof.Attenuation
namespace PcaProof.ChainLink
open PcaProof.Attenuation

/-- Recursive hop walk over one caveat per hop (head = current hop, tail = rest of chain towards the
    root; `[]` = root passed).  Mirrors Walk_Start/Walk_Step/Walk_Finish. -/
def walk : List Caveat → Action → Prop
  | [],      _ => True
  | c :: t,  a => Satisfies c a ∧ walk t a

/-- **The walk-style recursion equals the fold definition of effective authority.** -/
theorem walk_iff_eff (l : List Caveat) (a : Action) : walk l a ↔ Eff l a := by
  induction l with
  | nil =>
      constructor
      · intro _ cav hc; simp at hc
      · intro _; trivial
  | cons c t ih =>
      constructor
      · rintro ⟨h1, h2⟩ cav hc
        rcases List.mem_cons.mp hc with rfl | hc'
        · exact h1
        · exact (ih.mp h2) cav hc'
      · intro h
        exact ⟨h c (List.mem_cons_self ..), ih.mpr (fun cav hc => h cav (List.mem_cons_of_mem _ hc))⟩

theorem walk_append (p s : List Caveat) (a : Action) :
    walk (p ++ s) a ↔ walk p a ∧ walk s a := by
  induction p with
  | nil => simp [walk]
  | cons c t ih =>
      simp only [List.cons_append, walk, ih]
      constructor
      · rintro ⟨h1, h2, h3⟩; exact ⟨⟨h1, h2⟩, h3⟩
      · rintro ⟨⟨h1, h2⟩, h3⟩; exact ⟨h1, h2, h3⟩

/-- Extra hops only narrow: if the walk accepts `p ++ s` it accepts the prefix `p`. -/
theorem walk_prefix (p s : List Caveat) (a : Action) (h : walk (p ++ s) a) : walk p a :=
  ((walk_append p s a).mp h).1

/-- Chains whose hops each add a list of caveats (the append-only wire format). -/
def walkH : List (List Caveat) → Action → Prop
  | [],      _ => True
  | h :: t,  a => walk h a ∧ walkH t a

theorem walkH_iff_eff_flatten (hs : List (List Caveat)) (a : Action) :
    walkH hs a ↔ Eff hs.flatten a := by
  induction hs with
  | nil =>
      constructor
      · intro _ cav hc; simp at hc
      · intro _; trivial
  | cons h t ih =>
      simp only [walkH, List.flatten_cons]
      calc walk h a ∧ walkH t a ↔ walk h a ∧ walk t.flatten a := by
            rw [ih, walk_iff_eff t.flatten a]
        _ ↔ walk (h ++ t.flatten) a := (walk_append _ _ _).symm
        _ ↔ Eff (h ++ t.flatten) a := walk_iff_eff _ _

/-- For the append-only chain of `Attenuation.hops`: walking the root caveats then each extension
    equals `Eff` of root ++ all extensions (the cumulative caveat list of the LAST hop). -/
theorem walkH_cumulative (root : List Caveat) (exts : List (List Caveat)) (a : Action) :
    walkH (root :: exts) a ↔ Eff (root ++ exts.flatten) a := by
  calc walkH (root :: exts) a ↔ walk root a ∧ Eff exts.flatten a := by
        simp only [walkH]; rw [walkH_iff_eff_flatten]
    _ ↔ walk root a ∧ walk exts.flatten a := by rw [walk_iff_eff exts.flatten a]
    _ ↔ walk (root ++ exts.flatten) a := (walk_append _ _ _).symm
    _ ↔ Eff (root ++ exts.flatten) a := walk_iff_eff _ _

/-! ## The model-level abstraction used in the Tamarin files -/

/-- Tamarin hop caveat: `any` (unrestricted) or a verb pin. -/
inductive TCav where
  | any
  | verb (v : Nat)
deriving Repr, DecidableEq

/-- `ChkCav`: `(cv = v) | (cv = 'any')`. -/
def TPermits : TCav → Nat → Prop
  | .any,    _ => True
  | .verb w, v => w = v

/-- Recursive verifier walk of the Tamarin model (Walk_Start/Step/Finish). -/
def tWalk : List TCav → Nat → Prop
  | [],      _ => True
  | c :: t,  v => TPermits c v ∧ tWalk t v

theorem tWalk_iff_forall (l : List TCav) (v : Nat) : tWalk l v ↔ ∀ c ∈ l, TPermits c v := by
  induction l with
  | nil => simp [tWalk]
  | cons c t ih => simp [tWalk, ih]

/-- Concrete caveats of a Tamarin hop caveat: `any` imposes nothing, `verb w` is `verb_in [w]`. -/
def toCav : TCav → List Caveat
  | .any    => []
  | .verb w => [Caveat.verb_in [w]]

/-- **Tamarin's walk accepts the verb iff the corresponding concrete chain's effective authority
    (conjunction of all caveats, `Attenuation.Eff`) contains the action.** -/
theorem toCav_eff (c : TCav) (a : Action) : Eff (toCav c) a ↔ TPermits c a.verb := by
  cases c with
  | any => simp [toCav, Eff, TPermits]
  | verb w =>
      simp only [toCav, Eff, Satisfies, TPermits, List.mem_singleton, forall_eq]
      constructor
      · intro h; simpa using h.symm
      · intro h; simpa using h.symm

theorem tWalk_iff_eff (l : List TCav) (a : Action) :
    tWalk l a.verb ↔ Eff (l.flatMap toCav) a := by
  rw [tWalk_iff_forall]
  constructor
  · intro h cav hc
    obtain ⟨c, hcl, hcc⟩ := List.mem_flatMap.mp hc
    exact (toCav_eff c a).mpr (h c hcl) cav hcc
  · intro h c hc
    rw [← toCav_eff]
    intro cav hcc
    exact h cav (List.mem_flatMap.mpr ⟨c, hc, hcc⟩)

/-- Extra hops only narrow (model level). -/
theorem tWalk_prefix (p s : List TCav) (v : Nat) (h : tWalk (p ++ s) v) : tWalk p v := by
  rw [tWalk_iff_forall] at h ⊢
  intro c hc; exact h c (List.mem_append_left s hc)

end PcaProof.ChainLink
