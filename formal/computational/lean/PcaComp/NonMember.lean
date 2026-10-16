/-!
  Soundness of the sorted-set NON-MEMBERSHIP proof of `revocation.ts` (`verifyNonMembership`, `leafOk`), with the
  hash-collision escape made explicit: a deterministic extractor that turns any accepted non-membership proof for an
  id that IS in the committed set into a collision of one of the three SHA-256 uses (leaf hash `0x00 || id`, node hash
  `0x01 || l || r`, size-bound root `pca-revset/v1\0 || canonical{size, tree}`). With domain-separated inputs each is a
  SHA-256 collision, so  Pr[accept a revoked id] <= Adv_CR(SHA-256)  (tightness 1: the extractor runs the verifier
  once and reads the collision off two paths).

  The set is any strictly sorted list `S` (the publisher's `RevocationSet` keeps ids sorted by UTF-8 order and
  distinct). The honest tree's inclusion paths are taken as a hypothesis (`hcomp`): every leaf `S[i]` has a path whose
  side list is `sides i |S|` and which folds to the tree root `T`; that is completeness of the tree builder, proved
  for the concrete RFC 6962-style tree in `formal/dafny/Merkle.dfy` (`InclComplete`, `InclPathShape`). `sides` is
  `expectedSides`: the verifier checks the path's sides against it, so two accepted paths for the same index and size
  have the same sides. The epoch's authenticity (that `R`, `size` are what the publisher signed) is the CryptoVerif
  result `formal/cryptoverif/revocation_epoch.cv`.

  Core Lean only, no `sorry`.
-/
namespace PcaComp.NonMember

variable {K α β : Type}

/-- one step: side `true` = 'L' (sibling on the left: node(sib, h)), `false` = 'R' (node(h, sib)) -/
def step (H : α → α → α) (s x : α) : Bool → α
  | true => H s x
  | false => H x s

/-- fold a leaf hash up a path, leaf-to-root (the loop of `leafOk`) -/
def foldRoot (H : α → α → α) : α → List (α × Bool) → α
  | x, [] => x
  | x, (s, d) :: π => foldRoot H (step H s x d) π

def CollH (H : α → α → α) : Prop := ∃ a b c d : α, (a, b) ≠ (c, d) ∧ H a b = H c d
def CollF (f : K → α) : Prop := ∃ x y : K, x ≠ y ∧ f x = f y
def CollB (B : Nat → α → β) : Prop := ∃ (n : Nat) (t : α) (n' : Nat) (t' : α), (n, t) ≠ (n', t') ∧ B n t = B n' t'

/-- binding: two paths with the same side lists that fold to the same root start from the same leaf hash, unless the
    node hash has a collision -/
theorem fold_binding (H : α → α → α) :
    ∀ (π π' : List (α × Bool)) (x y : α), π.map Prod.snd = π'.map Prod.snd →
      foldRoot H x π = foldRoot H y π' → x = y ∨ CollH H
  | [], [], x, y, _, h => Or.inl h
  | [], _ :: _, _, _, hd, _ => by simp at hd
  | _ :: _, [], _, _, hd, _ => by simp at hd
  | (s, d) :: π, (s', d') :: π', x, y, hd, h => by
      simp only [List.map_cons, List.cons.injEq] at hd
      obtain ⟨hdd, hrest⟩ := hd
      subst hdd
      simp only [foldRoot] at h
      rcases fold_binding H π π' _ _ hrest h with he | hc
      · by_cases hxy : x = y
        · exact Or.inl hxy
        · right
          cases d
          · exact ⟨x, s, y, s', fun e => hxy (congrArg Prod.fst e), he⟩
          · exact ⟨s, x, s', y, fun e => hxy (congrArg Prod.snd e), he⟩
      · exact Or.inr hc

theorem length_of_getElem? {S : List K} {j : Nat} {k : K} (h : S[j]? = some k) : j < S.length := by
  by_cases hj : j < S.length
  · exact hj
  · rw [List.getElem?_eq_none (Nat.le_of_not_lt hj)] at h
    cases h

/-- a leaf proof: the claimed leaf id, its index and its path -/
structure LeafPf (K α : Type) where
  key : K
  idx : Nat
  path : List (α × Bool)

section
variable (lt : K → K → Prop) (H : α → α → α) (leafH : K → α) (B : Nat → α → β) (sides : Nat → Nat → List Bool)
  (E : α)

/-- `leafOk(root, size, id, proof)` -/
def InclOk (R : β) (size : Nat) (l : LeafPf K α) : Prop :=
  l.idx < size ∧ l.path.map Prod.snd = sides l.idx size ∧ B size (foldRoot H (leafH l.key) l.path) = R

/-- `verifyNonMembership(root, {size, lo?, hi?}, id)`, case by case as in the code -/
def NMOk (R : β) (size : Nat) (lo hi : Option (LeafPf K α)) (k : K) : Prop :=
  (size = 0 ∧ lo = none ∧ hi = none ∧ R = B 0 E) ∨
  (∃ l h, lo = some l ∧ hi = some h ∧ lt l.key k ∧ lt k h.key ∧
      InclOk H leafH B sides R size l ∧ InclOk H leafH B sides R size h ∧ h.idx = l.idx + 1) ∨
  (∃ l, lo = some l ∧ hi = none ∧ lt l.key k ∧ InclOk H leafH B sides R size l ∧ l.idx = size - 1) ∨
  (∃ h, lo = none ∧ hi = some h ∧ lt k h.key ∧ InclOk H leafH B sides R size h ∧ h.idx = 0)

/-- what the extractor outputs -/
def Bad : Prop := CollH H ∨ CollF leafH ∨ CollB B

variable {lt H leafH B sides E}

/-- an accepted leaf proof against the honest root sits at its index in `S`, or a collision is found -/
theorem leaf_at (S : List K) (T : α) (R : β) (size : Nat)
    (hsz : size = S.length) (hR : R = if S.length = 0 then B 0 E else B S.length T)
    (hcomp : ∀ (i : Nat) (a : K), S[i]? = some a → ∃ p : List (α × Bool), p.map Prod.snd = sides i S.length ∧ foldRoot H (leafH a) p = T)
    (l : LeafPf K α) (hl : InclOk H leafH B sides R size l) :
    Bad H leafH B ∨ S[l.idx]? = some l.key := by
  obtain ⟨hi, hs, hr⟩ := hl
  subst hsz
  have hne : S.length ≠ 0 := by omega
  rw [if_neg hne] at hR
  rw [hR] at hr
  obtain ⟨a, ha⟩ : ∃ a, S[l.idx]? = some a := ⟨S[l.idx], List.getElem?_eq_getElem hi⟩
  obtain ⟨p, hps, hpt⟩ := hcomp l.idx a ha
  by_cases ht : foldRoot H (leafH l.key) l.path = T
  · rcases fold_binding H l.path p (leafH l.key) (leafH a) (by rw [hs, hps]) (by rw [ht, hpt]) with he | hc
    · by_cases hk : l.key = a
      · right; rw [ha, hk]
      · exact Or.inl (Or.inr (Or.inl ⟨l.key, a, hk, he⟩))
    · exact Or.inl (Or.inl hc)
  · exact Or.inl (Or.inr (Or.inr ⟨S.length, _, S.length, T, fun e => ht (congrArg Prod.snd e), hr⟩))

/-- **Non-membership soundness.** If the verifier accepts a non-membership proof for `k` against the publisher's
    root of a strictly sorted set `S` (size and root as signed), and `k ∈ S`, then the extractor finds a collision. -/
theorem nonmember_sound
    (lt_irrefl : ∀ a, ¬ lt a a) (lt_trans : ∀ a b c, lt a b → lt b c → lt a c)
    (S : List K) (T : α) (R : β) (size : Nat)
    (hsort : ∀ (i j : Nat) (a b : K), i < j → S[i]? = some a → S[j]? = some b → lt a b)
    (hsz : size = S.length) (hR : R = if S.length = 0 then B 0 E else B S.length T)
    (hcomp : ∀ (i : Nat) (a : K), S[i]? = some a → ∃ p : List (α × Bool), p.map Prod.snd = sides i S.length ∧ foldRoot H (leafH a) p = T)
    (lo hi : Option (LeafPf K α)) (k : K)
    (hacc : NMOk lt H leafH B sides E R size lo hi k) (hmem : k ∈ S) :
    Bad H leafH B := by
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hmem
  have hjl := length_of_getElem? hj
  rcases hacc with ⟨h0, -, -, hr⟩ | ⟨l, h, -, -, hlk, hkh, hl, hh, hidx⟩ | ⟨l, -, -, hlk, hl, hidx⟩ | ⟨h, -, -, hkh, hh, hidx⟩
  · -- an empty-set proof: the signed size is |S| = 0, so k cannot be in S
    exfalso; omega
  · rcases leaf_at S T R size hsz hR hcomp l hl with hb | hl'
    · exact hb
    rcases leaf_at S T R size hsz hR hcomp h hh with hb | hh'
    · exact hb
    rw [hidx] at hh'
    exfalso
    rcases Nat.lt_trichotomy j l.idx with hlt | heq | hgt
    · exact lt_irrefl _ (lt_trans _ _ _ (hsort j l.idx k l.key hlt hj hl') hlk)
    · subst heq; rw [hj] at hl'; cases hl'; exact lt_irrefl _ hlk
    · rcases Nat.lt_or_ge j (l.idx + 1 + 1) with hle | hge
      · have : j = l.idx + 1 := by omega
        subst this; rw [hj] at hh'; cases hh'; exact lt_irrefl _ hkh
      · exact lt_irrefl _ (lt_trans _ _ _ hkh (hsort (l.idx + 1) j h.key k (by omega) hh' hj))
  · rcases leaf_at S T R size hsz hR hcomp l hl with hb | hl'
    · exact hb
    exfalso
    rw [hidx, hsz] at hl'
    rcases Nat.lt_or_ge j (S.length - 1) with hlt | hge
    · exact lt_irrefl _ (lt_trans _ _ _ (hsort j (S.length - 1) k l.key hlt hj hl') hlk)
    · have : j = S.length - 1 := by omega
      subst this; rw [hj] at hl'; cases hl'; exact lt_irrefl _ hlk
  · rcases leaf_at S T R size hsz hR hcomp h hh with hb | hh'
    · exact hb
    exfalso
    rw [hidx] at hh'
    rcases Nat.eq_zero_or_pos j with hz | hpos
    · subst hz; rw [hj] at hh'; cases hh'; exact lt_irrefl _ hkh
    · exact lt_irrefl _ (lt_trans _ _ _ hkh (hsort 0 j h.key k hpos hh' hj))

end
end PcaComp.NonMember
