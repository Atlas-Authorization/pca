/-
  PCA action kit: the trait algebra (docs/pca/specs/action-kit.md section 3.4), theorems T1 .. T7.

  Written against core Lean 4 only (no Mathlib API): a set is a predicate `Nat → Prop`, a profile is a record of four
  naturals (risk, reversibility rank, blast, escalation tier) and three sets (caveats, context, param rules).
  `packages/pca-actions/src/traits.ts` implements exactly this algebra on finite sets; the TypeScript code is checked
  against it by the property tests and the shared vectors (formal/dafny/TraitExpand.dfy proves the same statements on
  executable sets).

    T1  (Profile, le, join, bot) is a bounded join-semilattice: join is the least upper bound, bot is least.
    T2  traits only add: S ⊆ S' → F(S) ≤ F(S'); adding a trait never lowers the effective profile.
    T3  inheritance: every trait in the closure of T(d) contributes its floor to eff(d).
    T4  the floor decision is antitone in the profile, so Dec = meet(policy, floor) never rises when the profile does.
    T5  a custom trait whose floor extends what it implies adds nothing but itself; core floors are unchanged by any
        extension (a custom trait cannot weaken a core one).
    T6  registry growth: an action outside the pinned set is never allowed, a prohibit match always denies, prohibit
        coverage only grows, and the decision for an old action does not change when the registry grows.
    T7  positive selectors are monotone in the trait set; a negated selector is not (so allow selectors forbid `not`).
    T8  unconfirmed means maximally dangerous: a def without a valid signed human confirmation has the TOP trait set as its
        effective traits, whatever machine-authored input says; no machine-only input lowers it; the final decision for an
        unconfirmed def is at most the decision for any confirmed version of it (antitone); forbid selectors cover it and
        allow selectors never do.

  Every statement is fully proved; nothing is assumed beyond Lean's three standard axioms.
-/
namespace PcaIntent.TraitAlg

/-! ### sets as predicates -/

abbrev SSub (a b : Nat → Prop) : Prop := ∀ x, a x → b x
abbrev SUn (a b : Nat → Prop) : Nat → Prop := fun x => a x ∨ b x
abbrev SEmp : Nat → Prop := fun _ => False

theorem sub_refl (a : Nat → Prop) : SSub a a := fun _ h => h
theorem sub_trans {a b c : Nat → Prop} (h1 : SSub a b) (h2 : SSub b c) : SSub a c := fun x h => h2 x (h1 x h)
theorem sub_un_left (a b : Nat → Prop) : SSub a (SUn a b) := fun _ h => Or.inl h
theorem sub_un_right (a b : Nat → Prop) : SSub b (SUn a b) := fun _ h => Or.inr h
theorem un_sub {a b c : Nat → Prop} (h1 : SSub a c) (h2 : SSub b c) : SSub (SUn a b) c :=
  fun x h => Or.elim h (h1 x) (h2 x)
theorem emp_sub (a : Nat → Prop) : SSub SEmp a := fun _ h => False.elim h

/-! ### the maximum on naturals (explicit, so the proofs need no library lemma names) -/

def mx (a b : Nat) : Nat := if a ≤ b then b else a

theorem le_mx_left (a b : Nat) : a ≤ mx a b := by
  unfold mx
  split <;> omega

theorem le_mx_right (a b : Nat) : b ≤ mx a b := by
  unfold mx
  split <;> omega

theorem mx_le {a b c : Nat} (h1 : a ≤ c) (h2 : b ≤ c) : mx a b ≤ c := by
  unfold mx
  split <;> omega

/-! ### T1: the profile lattice -/

structure Profile where
  risk : Nat
  rev : Nat
  blast : Nat
  esc : Nat
  cav : Nat → Prop
  ctx : Nat → Prop
  pr : Nat → Prop

abbrev Profile.le (p q : Profile) : Prop :=
  p.risk ≤ q.risk ∧ p.rev ≤ q.rev ∧ p.blast ≤ q.blast ∧ p.esc ≤ q.esc ∧
  SSub p.cav q.cav ∧ SSub p.ctx q.ctx ∧ SSub p.pr q.pr

def Profile.join (p q : Profile) : Profile where
  risk := mx p.risk q.risk
  rev := mx p.rev q.rev
  blast := mx p.blast q.blast
  esc := mx p.esc q.esc
  cav := SUn p.cav q.cav
  ctx := SUn p.ctx q.ctx
  pr := SUn p.pr q.pr

def Profile.bot : Profile where
  risk := 0
  rev := 0
  blast := 0
  esc := 0
  cav := SEmp
  ctx := SEmp
  pr := SEmp

/-- Equivalence of profiles (mutual `le`); equality of the set components would need function extensionality. -/
abbrev Profile.eqv (p q : Profile) : Prop := p.le q ∧ q.le p

theorem le_refl' (p : Profile) : p.le p :=
  ⟨Nat.le_refl _, Nat.le_refl _, Nat.le_refl _, Nat.le_refl _, sub_refl _, sub_refl _, sub_refl _⟩

theorem le_trans' {p q r : Profile} (h1 : p.le q) (h2 : q.le r) : p.le r := by
  obtain ⟨a1, a2, a3, a4, a5, a6, a7⟩ := h1
  obtain ⟨b1, b2, b3, b4, b5, b6, b7⟩ := h2
  exact ⟨Nat.le_trans a1 b1, Nat.le_trans a2 b2, Nat.le_trans a3 b3, Nat.le_trans a4 b4,
    sub_trans a5 b5, sub_trans a6 b6, sub_trans a7 b7⟩

theorem le_join_left (p q : Profile) : p.le (p.join q) :=
  ⟨le_mx_left _ _, le_mx_left _ _, le_mx_left _ _, le_mx_left _ _,
    sub_un_left _ _, sub_un_left _ _, sub_un_left _ _⟩

theorem le_join_right (p q : Profile) : q.le (p.join q) :=
  ⟨le_mx_right _ _, le_mx_right _ _, le_mx_right _ _, le_mx_right _ _,
    sub_un_right _ _, sub_un_right _ _, sub_un_right _ _⟩

/-- The join is the LEAST upper bound. -/
theorem join_le {p q r : Profile} (h1 : p.le r) (h2 : q.le r) : (p.join q).le r := by
  obtain ⟨a1, a2, a3, a4, a5, a6, a7⟩ := h1
  obtain ⟨b1, b2, b3, b4, b5, b6, b7⟩ := h2
  exact ⟨mx_le a1 b1, mx_le a2 b2, mx_le a3 b3, mx_le a4 b4, un_sub a5 b5, un_sub a6 b6, un_sub a7 b7⟩

theorem bot_le (p : Profile) : Profile.bot.le p :=
  ⟨Nat.zero_le _, Nat.zero_le _, Nat.zero_le _, Nat.zero_le _, emp_sub _, emp_sub _, emp_sub _⟩

theorem join_comm (p q : Profile) : (p.join q).eqv (q.join p) :=
  ⟨join_le (le_join_right q p) (le_join_left q p), join_le (le_join_right p q) (le_join_left p q)⟩

theorem join_idem (p : Profile) : (p.join p).eqv p :=
  ⟨join_le (le_refl' p) (le_refl' p), le_join_left p p⟩

theorem join_bot (p : Profile) : (p.join Profile.bot).eqv p :=
  ⟨join_le (le_refl' p) (bot_le p), le_join_left p Profile.bot⟩

theorem join_assoc (p q r : Profile) : ((p.join q).join r).eqv (p.join (q.join r)) := by
  constructor
  · exact join_le
      (join_le (le_join_left p (q.join r)) (le_trans' (le_join_left q r) (le_join_right p (q.join r))))
      (le_trans' (le_join_right q r) (le_join_right p (q.join r)))
  · exact join_le
      (le_trans' (le_join_left p q) (le_join_left (p.join q) r))
      (join_le (le_trans' (le_join_right p q) (le_join_left (p.join q) r)) (le_join_right (p.join q) r))

theorem join_mono {p p' q q' : Profile} (h1 : p.le p') (h2 : q.le q') : (p.join q).le (p'.join q') :=
  join_le (le_trans' h1 (le_join_left p' q')) (le_trans' h2 (le_join_right p' q'))

/-- A partial order: antisymmetry holds up to `eqv` (that is the definition of `eqv`). -/
theorem le_antisymm' {p q : Profile} (h1 : p.le q) (h2 : q.le p) : p.eqv q := ⟨h1, h2⟩

/-! ### the trait registry, closure and floors -/

/-- A registry: `imp t u` says trait `t` implies trait `u`; `floor t` is the restriction floor of `t`. -/
structure Reg where
  imp : Nat → Nat → Prop
  floor : Nat → Profile

/-- The closure of a set of traits under `imp`. -/
inductive InCl (R : Reg) (S : Nat → Prop) : Nat → Prop
  | base {t : Nat} : S t → InCl R S t
  | step {t u : Nat} : InCl R S t → R.imp t u → InCl R S u

/-- `p` is F_R(S): the least upper bound of the floors of every trait in the closure of S. -/
abbrev IsF (R : Reg) (S : Nat → Prop) (p : Profile) : Prop :=
  (∀ t, InCl R S t → (R.floor t).le p) ∧ (∀ q, (∀ t, InCl R S t → (R.floor t).le q) → p.le q)

theorem incl_mono {R : Reg} {S S' : Nat → Prop} (h : SSub S S') {t : Nat} (ht : InCl R S t) : InCl R S' t := by
  induction ht with
  | base hs => exact InCl.base (h _ hs)
  | step _ himp ih => exact InCl.step ih himp

/-- The closure is idempotent. -/
theorem incl_idem {R : Reg} {S : Nat → Prop} {t : Nat} (ht : InCl R (InCl R S) t) : InCl R S t := by
  induction ht with
  | base hs => exact hs
  | step _ himp ih => exact InCl.step ih himp

theorem isF_unique {R : Reg} {S : Nat → Prop} {p p' : Profile} (h : IsF R S p) (h' : IsF R S p') : p.eqv p' :=
  ⟨h.2 p' h'.1, h'.2 p h.1⟩

/-- A finite closure has an F: the fold of `join` over its floors. -/
theorem lub_list (f : Nat → Profile) (L : List Nat) :
    ∃ p : Profile, (∀ t, t ∈ L → (f t).le p) ∧ (∀ q : Profile, (∀ t, t ∈ L → (f t).le q) → p.le q) := by
  induction L with
  | nil => exact ⟨Profile.bot, fun t ht => by simp at ht, fun q _ => bot_le q⟩
  | cons a L ih =>
    obtain ⟨p, hp1, hp2⟩ := ih
    refine ⟨(f a).join p, ?_, ?_⟩
    · intro t ht
      rcases List.mem_cons.mp ht with h | h
      · rw [h]
        exact le_join_left _ _
      · exact le_trans' (hp1 t h) (le_join_right _ _)
    · intro q hq
      exact join_le (hq a (by simp)) (hp2 q (fun t ht => hq t (by simp [ht])))

theorem isF_exists {R : Reg} {S : Nat → Prop} (L : List Nat) (hL : ∀ t, InCl R S t ↔ t ∈ L) : ∃ p, IsF R S p := by
  obtain ⟨p, hp1, hp2⟩ := lub_list R.floor L
  exact ⟨p, fun t ht => hp1 t ((hL t).mp ht), fun q hq => hp2 q (fun t ht => hq t ((hL t).mpr ht))⟩

/-- T2: S ⊆ S' implies F(S) ≤ F(S'). -/
theorem F_mono {R : Reg} {S S' : Nat → Prop} {p p' : Profile} (hS : SSub S S') (hp : IsF R S p) (hp' : IsF R S' p') :
    p.le p' :=
  hp.2 p' (fun t ht => hp'.1 t (incl_mono hS ht))

/-! ### defs, effective profiles, T2 and T3 -/

/-- A def reduced to what the algebra reads: its declared profile and its trait set T(d) (declared and implied). -/
structure Def where
  decl : Profile
  traits : Nat → Prop

def Def.addTrait (d : Def) (t : Nat) : Def where
  decl := d.decl
  traits := SUn d.traits (fun x => x = t)

/-- `e` is eff_R(d) = decl(d) ⊔ F_R(T(d)). -/
abbrev IsEff (R : Reg) (d : Def) (e : Profile) : Prop :=
  ∃ f, IsF R d.traits f ∧ e = d.decl.join f

/-- T2: adding a trait never lowers the effective profile. -/
theorem T2_addTrait {R : Reg} {d : Def} {t : Nat} {e e' : Profile} (he : IsEff R d e) (he' : IsEff R (d.addTrait t) e') :
    e.le e' := by
  obtain ⟨f, hf, rfl⟩ := he
  obtain ⟨f', hf', rfl⟩ := he'
  exact join_mono (le_refl' d.decl) (F_mono (sub_un_left d.traits (fun x => x = t)) hf hf')

/-- T2 for many traits: a larger declared set gives a larger effective profile. -/
theorem T2_sub {R : Reg} {d d' : Def} {e e' : Profile} (hdecl : d.decl = d'.decl) (hS : SSub d.traits d'.traits)
    (he : IsEff R d e) (he' : IsEff R d' e') : e.le e' := by
  obtain ⟨f, hf, rfl⟩ := he
  obtain ⟨f', hf', rfl⟩ := he'
  rw [hdecl]
  exact join_mono (le_refl' d'.decl) (F_mono hS hf hf')

/-- T3: every trait in the closure of T(d) contributes its floor to eff(d). -/
theorem T3_inherit {R : Reg} {d : Def} {e : Profile} (he : IsEff R d e) {t : Nat} (ht : InCl R d.traits t) :
    (R.floor t).le e := by
  obtain ⟨f, hf, rfl⟩ := he
  exact le_trans' (hf.1 t ht) (le_join_right _ _)

/-- The declared profile is also below eff(d): a declared value below a floor is clamped, never honoured. -/
theorem T3_decl {R : Reg} {d : Def} {e : Profile} (he : IsEff R d e) : d.decl.le e := by
  obtain ⟨f, _, rfl⟩ := he
  exact le_join_left _ _

/-- T3 corollary: a trait tagged on a new def is inherited with no change to any policy. -/
theorem T3_tagged {R : Reg} {d : Def} {t : Nat} {e : Profile} (he : IsEff R (d.addTrait t) e) : (R.floor t).le e :=
  T3_inherit he (InCl.base (Or.inr rfl))

/-- The implication table is monotone: more effects, roles or tags give more traits. -/
theorem implied_mono (impl : Nat → Nat → Prop) {A A' : Nat → Prop} (h : SSub A A') :
    SSub (fun u => ∃ a, A a ∧ impl a u) (fun u => ∃ a, A' a ∧ impl a u) := by
  intro u hu
  obtain ⟨a, ha, hi⟩ := hu
  exact ⟨a, h a ha, hi⟩

/-! ### T4: the floor decision is antitone -/

structure Grant where
  cav : Nat → Prop
  maxEsc : Nat
  pre : Nat

open Classical in
/-- 0 = deny, 1 = escalate, 2 = allow. -/
noncomputable def fd (g : Grant) (c : Nat → Prop) (ρ : Profile) : Nat :=
  if g.maxEsc < ρ.esc then 0
  else if (SSub ρ.cav g.cav ∧ SSub ρ.ctx c ∧ ρ.esc ≤ g.pre) then 2
  else 1

theorem fd_antitone (g : Grant) (c : Nat → Prop) {ρ ρ' : Profile} (h : ρ.le ρ') : fd g c ρ' ≤ fd g c ρ := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h
  unfold fd
  by_cases a : g.maxEsc < ρ'.esc
  · rw [if_pos a]
    exact Nat.zero_le _
  · rw [if_neg a]
    by_cases b : g.maxEsc < ρ.esc
    · exfalso
      omega
    · rw [if_neg b]
      by_cases d : (SSub ρ'.cav g.cav ∧ SSub ρ'.ctx c ∧ ρ'.esc ≤ g.pre)
      · rw [if_pos d]
        have d' : SSub ρ.cav g.cav ∧ SSub ρ.ctx c ∧ ρ.esc ≤ g.pre :=
          ⟨sub_trans h5 d.1, sub_trans h6 d.2.1, Nat.le_trans h4 d.2.2⟩
        rw [if_pos d']
        all_goals omega
      · rw [if_neg d]
        by_cases d' : (SSub ρ.cav g.cav ∧ SSub ρ.ctx c ∧ ρ.esc ≤ g.pre)
        · rw [if_pos d']
          all_goals omega
        · rw [if_neg d']
          all_goals omega

/-- The final decision is the meet (minimum) of the policy decision and the floor decision. -/
theorem dec_antitone (g : Grant) (c : Nat → Prop) (pol : Nat) {ρ ρ' : Profile} (h : ρ.le ρ') :
    min pol (fd g c ρ') ≤ min pol (fd g c ρ) := by
  have hf := fd_antitone g c h
  first
    | omega
    | exact Nat.le_min.mpr ⟨Nat.min_le_left _ _, Nat.le_trans (Nat.min_le_right _ _) hf⟩

/-- T4 end to end: tagging a def with another trait never raises the decision. -/
theorem T4_tagging {R : Reg} {d : Def} {t : Nat} {e e' : Profile} (g : Grant) (c : Nat → Prop) (pol : Nat)
    (he : IsEff R d e) (he' : IsEff R (d.addTrait t) e') :
    min pol (fd g c e') ≤ min pol (fd g c e) :=
  dec_antitone g c pol (T2_addTrait he he')

/-! ### T5: custom traits cannot weaken the core -/

/-- The acceptance test for a registry: every trait's floor is at least the floor of each trait it implies. -/
abbrev Accepts (R : Reg) : Prop := ∀ t u, R.imp t u → (R.floor u).le (R.floor t)

theorem accepted_closure_floor {R : Reg} (hA : Accepts R) {S : Nat → Prop} {t : Nat} (ht : InCl R S t) :
    ∃ s, S s ∧ (R.floor t).le (R.floor s) := by
  induction ht with
  | base hs => exact ⟨_, hs, le_refl' _⟩
  | step _ himp ih =>
    obtain ⟨s, hs, hle⟩ := ih
    exact ⟨s, hs, le_trans' (hA _ _ himp) hle⟩

/-- In an accepting registry the closure adds nothing to F: F(S) is the least upper bound of the floors of S itself. -/
theorem isF_direct {R : Reg} (hA : Accepts R) {S : Nat → Prop} {p : Profile}
    (h1 : ∀ s, S s → (R.floor s).le p) (h2 : ∀ q, (∀ s, S s → (R.floor s).le q) → p.le q) : IsF R S p := by
  constructor
  · intro t ht
    obtain ⟨s, hs, hle⟩ := accepted_closure_floor hA ht
    exact le_trans' hle (h1 s hs)
  · intro q hq
    exact h2 q (fun s hs => hq s (InCl.base hs))

/-- `R'` extends `R` over the core predicate `C`: same floors, same implications, and the core is closed under them. -/
structure Extends (C : Nat → Prop) (R R' : Reg) : Prop where
  floor_eq : ∀ t, C t → R'.floor t = R.floor t
  imp_eq : ∀ t u, C t → (R'.imp t u ↔ R.imp t u)
  closed : ∀ t u, C t → R.imp t u → C u

theorem incl_ext_to_core {C : Nat → Prop} {R R' : Reg} (hx : Extends C R R') {S : Nat → Prop} (hS : SSub S C) {t : Nat}
    (ht : InCl R' S t) : InCl R S t ∧ C t := by
  induction ht with
  | base hs => exact ⟨InCl.base hs, hS _ hs⟩
  | step _ himp ih =>
    obtain ⟨hr, hc⟩ := ih
    have himp' : R.imp _ _ := (hx.imp_eq _ _ hc).mp himp
    exact ⟨InCl.step hr himp', hx.closed _ _ hc himp'⟩

theorem incl_core_to_ext {C : Nat → Prop} {R R' : Reg} (hx : Extends C R R') {S : Nat → Prop} (hS : SSub S C) {t : Nat}
    (ht : InCl R S t) : InCl R' S t := by
  induction ht with
  | base hs => exact InCl.base hs
  | step hr himp ih =>
    have hc : C _ := (incl_ext_to_core hx hS ih).2
    exact InCl.step ih ((hx.imp_eq _ _ hc).mpr himp)

/-- Extending the registry does not change the closure of a core set. -/
theorem incl_ext_iff {C : Nat → Prop} {R R' : Reg} (hx : Extends C R R') {S : Nat → Prop} (hS : SSub S C) (t : Nat) :
    InCl R' S t ↔ InCl R S t :=
  ⟨fun h => (incl_ext_to_core hx hS h).1, fun h => incl_core_to_ext hx hS h⟩

/-- T5: for a core set S the floor is the same in the extended registry. -/
theorem T5_core_preserved {C : Nat → Prop} {R R' : Reg} (hx : Extends C R R') {S : Nat → Prop} (hS : SSub S C)
    {p p' : Profile} (hp : IsF R S p) (hp' : IsF R' S p') : p.eqv p' := by
  have floor_le : ∀ t, InCl R S t → (R.floor t).le p' := by
    intro t ht
    have hc : C t := (incl_ext_to_core hx hS (incl_core_to_ext hx hS ht)).2
    have := hp'.1 t ((incl_ext_iff hx hS t).mpr ht)
    rw [hx.floor_eq t hc] at this
    exact this
  have floor_le' : ∀ t, InCl R' S t → (R'.floor t).le p := by
    intro t ht
    obtain ⟨hr, hc⟩ := incl_ext_to_core hx hS ht
    rw [hx.floor_eq t hc]
    exact hp.1 t hr
  exact ⟨hp.2 p' floor_le, hp'.2 p floor_le'⟩

/-- T5, the soundness statement: adding custom traits to a core set never lowers the floor of the core part. -/
theorem T5_custom_cannot_lower {C : Nat → Prop} {R R' : Reg} (hx : Extends C R R') {S X : Nat → Prop} (hS : SSub S C)
    {p p' : Profile} (hp : IsF R S p) (hp' : IsF R' (SUn S X) p') : p.le p' := by
  have hq : IsF R' S p := by
    constructor
    · intro t ht
      obtain ⟨hr, hc⟩ := incl_ext_to_core hx hS ht
      rw [hx.floor_eq t hc]
      exact hp.1 t hr
    · intro q hq
      have key : ∀ t, InCl R S t → (R.floor t).le q := by
        intro t ht
        have hc : C t := (incl_ext_to_core hx hS (incl_core_to_ext hx hS ht)).2
        have h2 := hq t (incl_core_to_ext hx hS ht)
        rw [hx.floor_eq t hc] at h2
        exact h2
      exact hp.2 q key
  exact F_mono (sub_un_left S X) hq hp'

/-! ### T7: selectors -/

inductive Sel
  | trait (t : Nat)
  | allOf (ts : List Nat)
  | anyOf (ts : List Nat)
  | conj (a b : Sel)
  | neg (a : Sel)

/-- Does the selector match an action whose trait closure is `T`? -/
def Sel.holds : Sel → (Nat → Prop) → Prop
  | .trait t, T => T t
  | .allOf ts, T => ∀ t, t ∈ ts → T t
  | .anyOf ts, T => ∃ t, t ∈ ts ∧ T t
  | .conj a b, T => Sel.holds a T ∧ Sel.holds b T
  | .neg a, T => ¬ Sel.holds a T

/-- No negation anywhere (the typing rule for allow selectors). -/
def Sel.positive : Sel → Prop
  | .neg _ => False
  | .conj a b => Sel.positive a ∧ Sel.positive b
  | _ => True

/-- T7: a positive selector stays matched when traits are added. -/
theorem matches_mono {T T' : Nat → Prop} (hs : SSub T T') (s : Sel) (hp : s.positive) (hm : s.holds T) :
    s.holds T' := by
  induction s with
  | trait t =>
    simp only [Sel.holds] at hm ⊢
    exact hs t hm
  | allOf ts =>
    simp only [Sel.holds] at hm ⊢
    intro t ht
    exact hs t (hm t ht)
  | anyOf ts =>
    simp only [Sel.holds] at hm ⊢
    obtain ⟨t, ht, h⟩ := hm
    exact ⟨t, ht, hs t h⟩
  | conj a b iha ihb =>
    simp only [Sel.positive] at hp
    simp only [Sel.holds] at hm ⊢
    exact ⟨iha hp.1 hm.1, ihb hp.2 hm.2⟩
  | neg a _ =>
    exact absurd hp (by simp [Sel.positive])

/-- A negated selector is NOT monotone: tagging can switch it off. This is why allow selectors forbid `not`. -/
theorem not_selector_not_mono :
    ∃ T T' : Nat → Prop, SSub T T' ∧ (Sel.neg (Sel.trait 0)).holds T ∧ ¬ (Sel.neg (Sel.trait 0)).holds T' := by
  refine ⟨SEmp, fun x => x = 0, fun x h => False.elim h, ?_, ?_⟩
  · simp [Sel.holds, SEmp]
  · simp [Sel.holds]

/-! ### T6: registry growth -/

structure Pol where
  pinned : Nat → Prop
  allow : List Sel
  prohibit : List Sel

open Classical in
/-- Policy decision for an action (verb `v`, trait closure `T`): 0 deny, 1 escalate, 2 allow. -/
noncomputable def pdec (p : Pol) (escalateNew : Bool) (v : Nat) (T : Nat → Prop) : Nat :=
  if (∃ s, s ∈ p.prohibit ∧ s.holds T) then 0
  else if ¬ p.pinned v then (if escalateNew = true then 1 else 0)
  else if (∃ s, s ∈ p.allow ∧ s.holds T) then 2 else 0

/-- T6(b): an action outside the pinned set is never allowed. -/
theorem new_action_not_allowed (p : Pol) (e : Bool) (v : Nat) (T : Nat → Prop) (h : ¬ p.pinned v) : pdec p e v T ≠ 2 := by
  unfold pdec
  by_cases h1 : (∃ s, s ∈ p.prohibit ∧ s.holds T)
  · rw [if_pos h1]
    omega
  · rw [if_neg h1, if_pos h]
    cases e <;> simp

/-- T6(a'): a matching prohibit selector always denies. -/
theorem prohibit_denies (p : Pol) (e : Bool) (v : Nat) (T : Nat → Prop) (h : ∃ s, s ∈ p.prohibit ∧ s.holds T) :
    pdec p e v T = 0 := by
  unfold pdec
  rw [if_pos h]

/-- T6(a): the set of actions a prohibit predicate covers only grows with the registry. -/
theorem prohibit_cover_grows {A A' : Nat → Prop} (hA : SSub A A') (P : Nat → Prop) :
    SSub (fun a => A a ∧ P a) (fun a => A' a ∧ P a) :=
  fun a h => ⟨hA a h.1, h.2⟩

/-- T6(c): growing the registry (extending it over the core) leaves the decision of an old action unchanged. -/
theorem growth_stable {C : Nat → Prop} {R R' : Reg} (hx : Extends C R R') {S : Nat → Prop} (hS : SSub S C)
    (p : Pol) (e : Bool) (v : Nat) : pdec p e v (InCl R' S) = pdec p e v (InCl R S) := by
  have h : InCl R' S = InCl R S := funext (fun t => propext (incl_ext_iff hx hS t))
  rw [h]

/-! ### T8: unconfirmed means maximally dangerous -/

/-- The top element of the trait lattice of a registry: every trait. -/
def Top : Nat → Prop := fun _ => True

/-- A def with a confirmation status. `machine` is everything machine-authored (declared by an importer, inferred by a pack,
suggested by a rule, added by a union, proposed by a model): METADATA ONLY, never read by the effective set. `signed` is the trait
set a pinned reviewer signed (meaningful only when `confirmed`, which the verifier decides from the signature). -/
structure CDef where
  decl : Profile
  machine : Nat → Prop
  confirmed : Bool
  signed : Nat → Prop

/-- The effective trait set: what the reviewer signed when confirmed, the TOP otherwise. -/
def CDef.effTraits (d : CDef) : Nat → Prop := fun t => if d.confirmed = true then d.signed t else True

/-- The def as the algebra reads it. -/
def CDef.asDef (d : CDef) : Def where
  decl := d.decl
  traits := d.effTraits

/-- (1) unconfirmed implies the effective trait set is the top: every trait is in it. -/
theorem unconfirmed_is_top (d : CDef) (h : d.confirmed = false) (t : Nat) : d.effTraits t := by
  simp [CDef.effTraits, h]

/-- Confirmed: the effective trait set is exactly the signed one. -/
theorem confirmed_is_signed (d : CDef) (h : d.confirmed = true) (t : Nat) : d.effTraits t ↔ d.signed t := by
  simp [CDef.effTraits, h]

/-- (2) no machine-only input can lower the effective traits: the machine set is not read, so changing it changes nothing. -/
theorem no_machine_input_lowers (d : CDef) (m : Nat → Prop) : ({ d with machine := m } : CDef).effTraits = d.effTraits := rfl

/-- (2') for an unconfirmed def NOTHING but the declaration matters: any machine set and any `signed` set give the top. -/
theorem unconfirmed_ignores_inputs (d : CDef) (h : d.confirmed = false) (m s : Nat → Prop) (t : Nat) :
    ({ d with machine := m, signed := s } : CDef).effTraits t :=
  unconfirmed_is_top { d with machine := m, signed := s } h t

/-- Every trait of the registry contributes its floor to the effective profile of an unconfirmed def. -/
theorem unconfirmed_inherits {R : Reg} (d : CDef) (h : d.confirmed = false) {e : Profile} (he : IsEff R d.asDef e) (t : Nat) :
    (R.floor t).le e :=
  T3_inherit he (InCl.base (unconfirmed_is_top d h t))

/-- (3a) the effective profile of an unconfirmed def is at least the profile of EVERY confirmed version of it. -/
theorem unconfirmed_above_confirmed {R : Reg} (d c : CDef) (hd : d.confirmed = false) (hdecl : c.decl = d.decl)
    {e e' : Profile} (he : IsEff R d.asDef e) (he' : IsEff R c.asDef e') : e'.le e :=
  T2_sub (R := R) (d := c.asDef) (d' := d.asDef) hdecl (fun t _ => unconfirmed_is_top d hd t) he' he

/-- (3b) the floor decision for an unconfirmed def is at most the one for any confirmed version. -/
theorem unconfirmed_floor_antitone {R : Reg} (d c : CDef) (hd : d.confirmed = false) (hdecl : c.decl = d.decl)
    {e e' : Profile} (he : IsEff R d.asDef e) (he' : IsEff R c.asDef e') (g : Grant) (ctx : Nat → Prop) :
    fd g ctx e ≤ fd g ctx e' :=
  fd_antitone g ctx (unconfirmed_above_confirmed d c hd hdecl he he')

/-- Revoking a confirmation (a changed def or registry digest makes the attestation stale) never lowers the profile. -/
theorem stale_never_lowers {R : Reg} (c : CDef) {e e' : Profile} (he : IsEff R c.asDef e)
    (he' : IsEff R ({ c with confirmed := false } : CDef).asDef e') : e.le e' :=
  T2_sub (R := R) (d := c.asDef) (d' := ({ c with confirmed := false } : CDef).asDef) rfl
    (fun t _ => unconfirmed_is_top { c with confirmed := false } rfl t) he he'

open Classical in
/-- The policy decision for an UNCONFIRMED action (it depends on no trait closure): a forbid / cap selector (any prohibit entry)
covers it whatever it says, an allow selector never does, and an action outside the pinned set escalates or is denied. -/
noncomputable def pdecU (p : Pol) (escalateNew : Bool) (v : Nat) : Nat :=
  if 0 < p.prohibit.length then 0
  else if ¬ p.pinned v then (if escalateNew = true then 1 else 0)
  else 0

open Classical in
/-- The policy decision with a confirmation status. -/
noncomputable def pdecC (p : Pol) (escalateNew : Bool) (v : Nat) (T : Nat → Prop) (confirmed : Bool) : Nat :=
  if confirmed = true then pdec p escalateNew v T else pdecU p escalateNew v

/-- An allow selector never admits an unconfirmed action. -/
theorem unconfirmed_never_allowed (p : Pol) (e : Bool) (v : Nat) : pdecU p e v ≠ 2 := by
  unfold pdecU
  split
  · omega
  · split
    · cases e <;> simp
    · omega

/-- A forbid / cap selector denies an unconfirmed action, whatever its content: no carve-out and no classifier miss exempts it. -/
theorem prohibit_covers_unconfirmed (p : Pol) (e : Bool) (v : Nat) (h : 0 < p.prohibit.length) : pdecU p e v = 0 := by
  unfold pdecU
  rw [if_pos h]

/-- (3c) the policy decision for an unconfirmed action is at most the one for the same action once confirmed (any closure). -/
theorem unconfirmed_policy_antitone (p : Pol) (e : Bool) (v : Nat) (T : Nat → Prop) : pdecU p e v ≤ pdec p e v T := by
  by_cases h1 : 0 < p.prohibit.length
  · rw [prohibit_covers_unconfirmed p e v h1]
    exact Nat.zero_le _
  · have hnone : ¬ (∃ s, s ∈ p.prohibit ∧ s.holds T) := by
      intro hex
      obtain ⟨s, hs, _⟩ := hex
      apply h1
      cases hl : p.prohibit with
      | nil =>
        rw [hl] at hs
        simp at hs
      | cons a l => simp
    unfold pdecU pdec
    rw [if_neg h1, if_neg hnone]
    by_cases h2 : ¬ p.pinned v
    · rw [if_pos h2, if_pos h2]
      first | exact Nat.le_refl _ | skip
    · rw [if_neg h2, if_neg h2]
      exact Nat.zero_le _

/-- (3) END TO END: the final decision (meet of the policy decision and the floor decision) for an unconfirmed def is at most
the one for any confirmed version of it. Unconfirmed is treated the same or stricter, never looser. -/
theorem unconfirmed_final_antitone {R : Reg} (d c : CDef) (hd : d.confirmed = false) (hdecl : c.decl = d.decl)
    {e e' : Profile} (he : IsEff R d.asDef e) (he' : IsEff R c.asDef e') (g : Grant) (ctx : Nat → Prop)
    (p : Pol) (esc : Bool) (v : Nat) (T : Nat → Prop) :
    min (pdecU p esc v) (fd g ctx e) ≤ min (pdec p esc v T) (fd g ctx e') := by
  have h1 := unconfirmed_policy_antitone p esc v T
  have h2 := unconfirmed_floor_antitone d c hd hdecl he he' g ctx
  first
    | omega
    | exact Nat.le_min.mpr ⟨Nat.le_trans (Nat.min_le_left _ _) h1, Nat.le_trans (Nat.min_le_right _ _) h2⟩

/-! ### the confirmation applies only to the facts the reviewer saw -/

/-- The def as the verifier sees it: the confirmation counts only if it signs exactly the digest of the PRESENTED facts. -/
def CDef.withFacts (d : CDef) (signedFacts presented : Nat) : CDef :=
  { d with confirmed := d.confirmed && decide (signedFacts = presented) }

/-- A mismatch between the presented facts and the confirmed facts makes the def unconfirmed, whatever the signature says. -/
theorem facts_mismatch_unconfirmed (d : CDef) (s p : Nat) (h : s ≠ p) : (d.withFacts s p).confirmed = false := by
  simp [CDef.withFacts, h]

/-- ... so its effective traits are the top. -/
theorem facts_mismatch_is_top (d : CDef) (s p : Nat) (h : s ≠ p) (t : Nat) : (d.withFacts s p).effTraits t :=
  unconfirmed_is_top _ (facts_mismatch_unconfirmed d s p h) t

/-- When the facts match, the status is exactly the validity of the confirmation. -/
theorem facts_match_keeps_status (d : CDef) (s p : Nat) (h : s = p) : (d.withFacts s p).confirmed = d.confirmed := by
  simp [CDef.withFacts, h]

/-- Editing the facts of a confirmed def never lowers its effective profile. -/
theorem facts_edit_never_lowers {R : Reg} (d : CDef) (s p : Nat) (h : s ≠ p) {e e' : Profile} (he : IsEff R d.asDef e)
    (he' : IsEff R (d.withFacts s p).asDef e') : e.le e' :=
  T2_sub (R := R) (d := d.asDef) (d' := (d.withFacts s p).asDef) rfl
    (fun t _ => facts_mismatch_is_top d s p h t) he he'

end PcaIntent.TraitAlg
