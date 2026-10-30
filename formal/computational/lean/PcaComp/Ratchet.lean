/-!
  Capability ratchet (`pca-ratchet`, `ggm.ts`): forward secrecy of the puncturable GGM key tree, and the precise
  statement that there is NO post-compromise security.

  Model. Leaf keys of a depth-`d` binary tree are PRF outputs along the leaf's path: the key at path `p ++ [b]` is
  `PRF(key at p, b)`. A STATE is a list of tree nodes (an antichain). The adversary who obtains a state derives exactly
  the nodes below its members (a parent yields its children; a child does not yield the parent: this symbolic
  one-wayness is the PRF assumption NA-HMAC, same as the computational GG-2 in `leanmath/PcaMath/Ratchet.lean`). Signing
  at leaf `l` PUNCTURES the state: the node covering `l` is replaced by the siblings along the path to `l`.

  PROVED (every depth, every sequence of punctures):
    * `punct_covers`: the punctured state covers exactly the previously covered leaves except `l`;
    * `punct_antichain`: the state stays an antichain (so the invariant composes);
    * `forward_secrecy`: after any sequence of punctures, a state derives NO spent leaf key (the adversary who obtains
      only the new state cannot re-sign a spent action);
    * `no_pcs`: it derives EVERY unspent leaf key (a state compromise reveals all future keys; the construction does
      not heal, so post-compromise security is not a property of the ratchet and is not claimed anywhere).
  ASSUMED: NA-HMAC (the PRF), through the definition of what a state derives. Not modelled: a copy of the state taken
  BEFORE the signing can sign again (the README states this limit), and the Merkle commitment and signatures at the
  leaves (L4.1, C-1).

  Core Lean only, no `sorry`.
-/
namespace PcaComp.Ratchet

abbrev Path := List Bool

/-- the leaf keys a state derives: everything at or below one of its nodes -/
def Covers (F : List Path) (l : Path) : Prop := ∃ q, q ∈ F ∧ q <+: l

/-- siblings along the remainder `r` below node `q` -/
def sibs : Path → Path → List Path
  | _, [] => []
  | q, b :: r => (q ++ [!b]) :: sibs (q ++ [b]) r

theorem sibs_ext (r q : Path) : ∀ s, s ∈ sibs q r → q <+: s := by
  induction r generalizing q with
  | nil => intro s h; simp [sibs] at h
  | cons b r ih =>
      intro s h
      simp only [sibs, List.mem_cons] at h
      rcases h with h | h
      · subst h; exact List.prefix_append _ _
      · exact (List.prefix_append q [b]).trans (ih _ _ h)

theorem sibs_iff (r q m : Path) (hl : m.length = r.length) :
    (∃ s, s ∈ sibs q r ∧ s <+: q ++ m) ↔ m ≠ r := by
  induction r generalizing q m with
  | nil =>
      have : m = [] := List.length_eq_zero_iff.mp hl
      subst this; simp [sibs]
  | cons b r ih =>
      cases m with
      | nil => simp at hl
      | cons c m =>
          have hl' : m.length = r.length := by simpa using hl
          have key : (∃ s, s ∈ sibs (q ++ [b]) r ∧ s <+: (q ++ [b]) ++ m) ↔ m ≠ r := ih (q ++ [b]) m hl'
          simp only [sibs, List.mem_cons, exists_eq_or_imp]
          cases b <;> cases c <;>
            simp [List.append_assoc, List.prefix_append_right_inj] at * <;> simp_all

/-- a state is an antichain: no node is below another -/
def Antichain (F : List Path) : Prop := ∀ a, a ∈ F → ∀ b, b ∈ F → a <+: b → a = b

/-- puncture at `l`: drop the node(s) above `l`, add the siblings along the path from the covering node `q` -/
def punct (F : List Path) (q l : Path) : List Path :=
  F.filter (fun n => !(decide (n <+: l))) ++ sibs q (l.drop q.length)

theorem prefix_cmp {a b l : Path} (ha : a <+: l) (hb : b <+: l) : a <+: b ∨ b <+: a := by
  by_cases hle : a.length ≤ b.length
  · exact Or.inl (List.prefix_of_prefix_length_le ha hb hle)
  · exact Or.inr (List.prefix_of_prefix_length_le hb ha (by omega))

theorem sibs_anti (r q : Path) : ∀ a, a ∈ sibs q r → ∀ b, b ∈ sibs q r → a <+: b → a = b := by
  induction r generalizing q with
  | nil => intro a h; simp [sibs] at h
  | cons c r ih =>
      intro a ha b hb hab
      simp only [sibs, List.mem_cons] at ha hb
      rcases ha with rfl | ha <;> rcases hb with rfl | hb
      · rfl
      · have h2 := sibs_ext r (q ++ [c]) _ hb
        rcases prefix_cmp hab h2 with h3 | h3 <;>
        · rw [List.prefix_append_right_inj] at h3
          cases c <;> simp at h3
      · have h2 := sibs_ext r (q ++ [c]) _ ha
        have h3 := h2.trans hab
        rw [List.prefix_append_right_inj] at h3
        cases c <;> simp at h3
      · exact ih _ _ ha _ hb hab

theorem prefix_split {q l : Path} (h : q <+: l) : l = q ++ l.drop q.length := by
  obtain ⟨m, rfl⟩ := h
  simp

/-- Puncturing the node `q` that covers `l` keeps the state an antichain. -/
theorem punct_antichain (F : List Path) (hA : Antichain F) (q l : Path) (hq : q ∈ F) (hql : q <+: l) :
    Antichain (punct F q l) := by
  intro a ha b hb hab
  simp only [punct, List.mem_append, List.mem_filter, Bool.not_eq_true', decide_eq_false_iff_not] at ha hb
  rcases ha with ⟨haF, hal⟩ | ha <;> rcases hb with ⟨hbF, hbl⟩ | hb
  · exact hA a haF b hbF hab
  · have hqb := sibs_ext _ _ _ hb
    rcases prefix_cmp hab hqb with h | h
    · have e := hA a haF q hq h; subst e; exact absurd hql hal
    · have e := hA q hq a haF h; subst e; exact absurd hql hal
  · have hqa := sibs_ext _ _ _ ha
    have hqb : q <+: b := hqa.trans hab
    have e := hA q hq b hbF hqb; subst e; exact absurd hql hbl
  · exact sibs_anti _ _ a ha b hb hab

/-- Exact coverage after a puncture: the leaves of the (full) depth of `l` covered afterwards are those covered
    before, except `l`. -/
theorem punct_covers (F : List Path) (hA : Antichain F) (q l : Path) (hq : q ∈ F) (hql : q <+: l)
    (x : Path) (hx : x.length = l.length) :
    Covers (punct F q l) x ↔ Covers F x ∧ x ≠ l := by
  have hl := prefix_split hql
  constructor
  · rintro ⟨n, hn, hnx⟩
    simp only [punct, List.mem_append, List.mem_filter, Bool.not_eq_true', decide_eq_false_iff_not] at hn
    rcases hn with ⟨hnF, hnl⟩ | hn
    · refine ⟨⟨n, hnF, hnx⟩, ?_⟩
      rintro rfl; exact hnl hnx
    · have hqn := sibs_ext _ _ _ hn
      have hqx : q <+: x := hqn.trans hnx
      refine ⟨⟨q, hq, hqx⟩, ?_⟩
      have hxs := prefix_split hqx
      have hlen : (x.drop q.length).length = (l.drop q.length).length := by simp [hx]
      have := (sibs_iff (l.drop q.length) q (x.drop q.length) hlen).mp ⟨n, hn, by rw [← hxs]; exact hnx⟩
      intro hxl
      apply this
      subst hxl
      exact rfl
  · rintro ⟨⟨n, hnF, hnx⟩, hxl⟩
    by_cases hnl : n <+: l
    · have hnq : n = q := by
        rcases prefix_cmp hnl hql with h | h
        · exact hA n hnF q hq h
        · exact (hA q hq n hnF h).symm
      subst hnq
      have hxs := prefix_split hnx
      have hlen : (x.drop n.length).length = (l.drop n.length).length := by simp [hx]
      have hne : x.drop n.length ≠ l.drop n.length := by
        intro h; apply hxl; rw [hxs, hl, h]
      obtain ⟨s, hs, hsx⟩ := (sibs_iff (l.drop n.length) n (x.drop n.length) hlen).mpr hne
      exact ⟨s, by simp only [punct, List.mem_append]; exact Or.inr hs, by rw [hxs]; exact hsx⟩
    · exact ⟨n, by simp only [punct, List.mem_append, List.mem_filter, Bool.not_eq_true', decide_eq_false_iff_not]; exact Or.inl ⟨hnF, hnl⟩, hnx⟩

/-- States reachable from a fresh tree of depth `d` (one root node, nothing spent) by signing, i.e. puncturing, leaves
    that are still available. `S` is the list of spent leaves. -/
inductive Reach (d : Nat) : List Path → List Path → Prop
  | init : Reach d [[]] []
  | step {F S : List Path} (q l : Path) : Reach d F S → l.length = d → q ∈ F → q <+: l →
      Reach d (punct F q l) (l :: S)

theorem reach_inv {d : Nat} {F S : List Path} (h : Reach d F S) :
    Antichain F ∧ ∀ x : Path, x.length = d → (Covers F x ↔ x ∉ S) := by
  induction h with
  | init =>
      refine ⟨?_, ?_⟩
      · intro a ha b hb _; simp at ha hb; rw [ha, hb]
      · intro x _; simp [Covers]
  | @step F S q l _ hl hq hql ih =>
      refine ⟨punct_antichain F ih.1 q l hq hql, ?_⟩
      intro x hx
      rw [punct_covers F ih.1 q l hq hql x (by omega), ih.2 x hx]
      simp only [List.mem_cons, not_or]
      exact and_comm

/-- FORWARD SECRECY: whoever obtains only the current state derives the key of no spent leaf. -/
theorem forward_secrecy {d : Nat} {F S : List Path} (h : Reach d F S) (l : Path) (hl : l.length = d) (hs : l ∈ S) :
    ¬ Covers F l := fun hc => ((reach_inv h).2 l hl).mp hc hs

/-- NO POST-COMPROMISE SECURITY: the same state derives the key of EVERY unspent leaf, so a state compromise exposes
    all future signatures; the ratchet does not heal, and nothing claims it does. -/
theorem no_pcs {d : Nat} {F S : List Path} (h : Reach d F S) (l : Path) (hl : l.length = d) (hu : l ∉ S) :
    Covers F l := ((reach_inv h).2 l hl).mpr hu

end PcaComp.Ratchet
