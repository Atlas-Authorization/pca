import Mathlib

/-!
# OT-extension hash layer: definitions of the ideal-cipher game (R4-12)

`D` is the block space (128-bit strings, an additive group of characteristic 2: `+` is XOR), `V` indexes the
independent correlations `Delta_v` (one per OT channel; `V = Unit` is the single-key game).

The primitive is an ideal cipher: a uniformly random permutation `pi` of `D`, with forward and inverse queries.
The hash is the TMMO tweakable hash `H(x, t) = pi(pi(x) + t) + pi(x)` (full 128-bit output; the code's `low64`
truncation is a post-processing, see `OtIcm.lean`).

An adversary is a (possibly adaptive, possibly randomised -- randomness is a parameter we fix) decision tree whose
nodes are oracle queries.  The oracles are `P z = pi z`, `Pi w = pi^{-1} w`, and the correlated hash oracle
`H v x t = H(x + Delta_v, t)` (real world) or `R v x t` for a uniformly random function `R` (ideal world).
-/

open Finset

namespace PcaMath.OtDefs

inductive Qry (V D : Type) : Type
  | P (z : D)
  | Pi (w : D)
  | H (v : V) (x t : D)
  deriving DecidableEq

inductive Adv (V D : Type) : Type
  | done (b : Bool)
  | ask (q : Qry V D) (k : D → Adv V D)

variable {V D : Type}

/-- run the adversary against an oracle; returns the transcript and the output bit. -/
def Adv.play : Adv V D → (Qry V D → D) → List (Qry V D × D) × Bool
  | .done b, _ => ([], b)
  | .ask q k, O => ((q, O q) :: ((k (O q)).play O).1, ((k (O q)).play O).2)

/-- query budget: at most `kp` permutation queries (`P`/`Pi`) and `kh` hash queries on every path. -/
def Adv.Bdd : Adv V D → ℕ → ℕ → Prop
  | .done _, _, _ => True
  | .ask (.P _) k, p, h => 0 < p ∧ ∀ d, (k d).Bdd (p - 1) h
  | .ask (.Pi _) k, p, h => 0 < p ∧ ∀ d, (k d).Bdd (p - 1) h
  | .ask (.H _ _ _) k, p, h => 0 < h ∧ ∀ d, (k d).Bdd p (h - 1)

/-- real world oracle for `(pi, Delta)` -/
def oX [AddCommGroup D] (π : Equiv.Perm D) (Δ : V → D) : Qry V D → D
  | .P z => π z
  | .Pi w => π.symm w
  | .H v x t => π (π (x + Δ v) + t) + π (x + Δ v)

/-- ideal world oracle for `(pi, R)` -/
def oY (π : Equiv.Perm D) (R : V × D × D → D) : Qry V D → D
  | .P z => π z
  | .Pi w => π.symm w
  | .H v x t => R (v, x, t)

/-- `τ` is the transcript of a run of `A` (all answers arbitrary). -/
inductive IsPath : Adv V D → List (Qry V D × D) → Bool → Prop
  | done (b : Bool) : IsPath (.done b) [] b
  | ask (q : Qry V D) (k : D → Adv V D) (d : D) (τ : List (Qry V D × D)) (b : Bool) :
      IsPath (k d) τ b → IsPath (.ask q k) ((q, d) :: τ) b

/-- Replay lemma: running `A` against `O` yields `(τ, b)` iff `(τ, b)` is a path of `A` all of whose answers
are those of `O`. -/
theorem play_eq_iff (A : Adv V D) (O : Qry V D → D) (τ : List (Qry V D × D)) (b : Bool) :
    A.play O = (τ, b) ↔ IsPath A τ b ∧ ∀ e ∈ τ, O e.1 = e.2 := by
  induction A generalizing τ with
  | done b' =>
    constructor
    · intro h
      simp only [Adv.play, Prod.mk.injEq] at h
      obtain ⟨h1, h2⟩ := h
      subst h1; subst h2
      exact ⟨IsPath.done _, by simp⟩
    · rintro ⟨hp, _⟩
      cases hp
      rfl
  | ask q k ih =>
    constructor
    · intro h
      simp only [Adv.play, Prod.mk.injEq] at h
      obtain ⟨h1, h2⟩ := h
      subst h1
      have := (ih (O q) ((k (O q)).play O).1).mp (by rw [← h2])
      refine ⟨IsPath.ask q k (O q) _ b this.1, ?_⟩
      intro e he
      rcases List.mem_cons.mp he with rfl | he
      · rfl
      · exact this.2 e he
    · rintro ⟨hp, hall⟩
      cases hp with
      | ask _ _ d τ' _ hk =>
        have hd : O q = d := hall (q, d) (List.mem_cons_self)
        subst hd
        have := (ih (O q) τ').mpr ⟨hk, fun e he => hall e (List.mem_cons_of_mem _ he)⟩
        simp only [Adv.play, this]

/-- the permutation pairs `(z, w)` (meaning `pi z = w`) revealed by a transcript -/
def eSet [DecidableEq D] (ents : List (Qry V D × D)) : Finset (D × D) :=
  (ents.filterMap fun e => match e.1 with
    | .P z => some (z, e.2)
    | .Pi w => some (e.2, w)
    | .H _ _ _ => none).toFinset

/-- the hash entries `((v, x, t), o)` revealed by a transcript -/
def hSet [DecidableEq V] [DecidableEq D] (ents : List (Qry V D × D)) : Finset ((V × D × D) × D) :=
  (ents.filterMap fun e => match e.1 with
    | .P _ => none
    | .Pi _ => none
    | .H v x t => some ((v, x, t), e.2)).toFinset

end PcaMath.OtDefs
