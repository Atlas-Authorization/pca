/-!
# N-version meet (goal-to-decision spec F3): the enforced policy is no broader than ANY reading

A reading is a set of grants (a verb and a predicate over actions), a set of prohibitions and a set of guards
(validity and aggregate bounds, evaluated on the action together with its history, abstracted to a predicate).
`Allow` is the reference semantics of section 3.2 restricted to the Allow set: some grant matches the action's verb
and holds, no prohibition fires, every guard holds.

`meet2 g h` is the compiler's merge: the grant cross product on equal verbs with conjoined predicates, the union of
prohibitions and the union of guards (the minimum of caps is a guard that is the conjunction of both caps).

* `allow_meet2_left/right`: `Allow (meet2 g h) a → Allow g a` and `→ Allow h a`.
* `allow_meetList`: for a fold over any list of readings, the allowed action is allowed by EVERY reading.
  So if one interpreter is faithful, k-1 wrong or hostile interpreters cannot widen the enforced policy. No
  independence assumption is used: independence matters only for how often disagreement is DETECTED.
-/
namespace PcaIntent.Meet

structure Grant (α : Type) where
  verb : Nat
  pred : α → Bool

structure Goal (α : Type) where
  grants : List (Grant α)
  prohibits : List (α → Bool)
  guards : List (α → Bool)

/-- Allow set: a grant matches the verb and holds, no prohibition fires, every guard holds. -/
def Allow {α : Type} (vb : α → Nat) (g : Goal α) (a : α) : Prop :=
  (∃ gr ∈ g.grants, gr.verb = vb a ∧ gr.pred a = true) ∧
    (∀ p ∈ g.prohibits, p a = false) ∧ (∀ q ∈ g.guards, q a = true)

def meetGrants {α : Type} (xs ys : List (Grant α)) : List (Grant α) :=
  xs.flatMap fun x => ys.filterMap fun y =>
    if x.verb = y.verb then some ⟨x.verb, fun a => x.pred a && y.pred a⟩ else none

def meet2 {α : Type} (g h : Goal α) : Goal α :=
  ⟨meetGrants g.grants h.grants, g.prohibits ++ h.prohibits, g.guards ++ h.guards⟩

theorem mem_meetGrants {α : Type} {xs ys : List (Grant α)} {m : Grant α} (hm : m ∈ meetGrants xs ys) :
    ∃ x ∈ xs, ∃ y ∈ ys, x.verb = y.verb ∧ m.verb = x.verb ∧ ∀ a, m.pred a = (x.pred a && y.pred a) := by
  unfold meetGrants at hm
  rw [List.mem_flatMap] at hm
  obtain ⟨x, hx, hm⟩ := hm
  rw [List.mem_filterMap] at hm
  obtain ⟨y, hy, hxy⟩ := hm
  have hxy' : (if x.verb = y.verb then some (⟨x.verb, fun a => x.pred a && y.pred a⟩ : Grant α) else none) = some m := hxy
  by_cases h : x.verb = y.verb
  · rw [if_pos h] at hxy'
    have hm' := Option.some.inj hxy'
    subst hm'
    exact ⟨x, hx, y, hy, h, rfl, fun a => rfl⟩
  · rw [if_neg h] at hxy'
    cases hxy'

theorem allow_meet2_left {α : Type} (vb : α → Nat) (g h : Goal α) (a : α) (hA : Allow vb (meet2 g h) a) :
    Allow vb g a := by
  obtain ⟨⟨m, hm, hv, hp⟩, hpro, hgu⟩ := hA
  obtain ⟨x, hx, y, hy, hxy, hmv, hmp⟩ := mem_meetGrants hm
  have e : (x.pred a && y.pred a) = true := by rw [← hmp a]; exact hp
  simp only [Bool.and_eq_true] at e
  refine ⟨⟨x, hx, Eq.trans hmv.symm hv, e.1⟩, ?_, ?_⟩
  · intro p hp'
    exact hpro p (List.mem_append.mpr (Or.inl hp'))
  · intro q hq
    exact hgu q (List.mem_append.mpr (Or.inl hq))

theorem allow_meet2_right {α : Type} (vb : α → Nat) (g h : Goal α) (a : α) (hA : Allow vb (meet2 g h) a) :
    Allow vb h a := by
  obtain ⟨⟨m, hm, hv, hp⟩, hpro, hgu⟩ := hA
  obtain ⟨x, hx, y, hy, hxy, hmv, hmp⟩ := mem_meetGrants hm
  have e : (x.pred a && y.pred a) = true := by rw [← hmp a]; exact hp
  simp only [Bool.and_eq_true] at e
  refine ⟨⟨y, hy, Eq.trans hxy.symm (Eq.trans hmv.symm hv), e.2⟩, ?_, ?_⟩
  · intro p hp'
    exact hpro p (List.mem_append.mpr (Or.inr hp'))
  · intro q hq
    exact hgu q (List.mem_append.mpr (Or.inr hq))

def meetList {α : Type} (g : Goal α) : List (Goal α) → Goal α
  | [] => g
  | h :: t => meetList (meet2 g h) t

theorem allow_meetList {α : Type} (vb : α → Nat) (a : α) :
    ∀ (l : List (Goal α)) (g : Goal α), Allow vb (meetList g l) a → Allow vb g a ∧ ∀ h ∈ l, Allow vb h a
  | [], g, hA => ⟨hA, by intro h hh; cases hh⟩
  | h :: t, g, hA => by
      have ih := allow_meetList vb a t (meet2 g h) hA
      obtain ⟨h1, h2⟩ := ih
      refine ⟨allow_meet2_left vb g h a h1, ?_⟩
      intro x hx
      rcases List.mem_cons.mp hx with hx' | hx'
      · rw [hx']
        exact allow_meet2_right vb g h a h1
      · exact h2 x hx'

/-- The headline: whatever the merged policy allows, every reading allows. -/
theorem allow_meet_subset {α : Type} (vb : α → Nat) (gs : List (Goal α)) (g0 : Goal α) (a : α)
    (hA : Allow vb (meetList g0 gs) a) : ∀ g ∈ g0 :: gs, Allow vb g a := by
  obtain ⟨h0, hs⟩ := allow_meetList vb a gs g0 hA
  intro g hg
  rcases List.mem_cons.mp hg with hg' | hg'
  · rw [hg']; exact h0
  · exact hs g hg'

end PcaIntent.Meet
