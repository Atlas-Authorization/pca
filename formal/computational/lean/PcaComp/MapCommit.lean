import PcaComp.NonMember

/-!
  Binding of the committed Intent Map (`packages/pca/src/intent-map-commit.ts`, conformance rule 19; spec 3.10a step 2),
  for maps of ANY size, with an explicit collision extractor.

  The map's leaves are triples (kind, salt, leaf value) hashed as `L (kind, salt, value)` =
  SHA-256(TAG_kind || salt || strictCanonical(value)) (the tags are distinct and NUL-terminated, the salt has fixed
  length, the JSON is strict canonical: `L` is SHA-256 on an injective encoding, so a collision of `L` is a SHA-256
  collision). Nodes are `H l r` = SHA-256(TAG_NODE || l || r), and `map_commit = Cm n root` =
  SHA-256(TAG_COMMIT || u64be(n) || root). An opening at (index, size, path) is accepted when the path's sides are those
  RFC 9162 fixes for (index, size) and `Cm size (fold) = C` (`opens` in the code).

  `open_binding`: an opening accepted against the commitment of the honest map `M` is the honest leaf at that index
  (same kind, same salt, same value), or the extractor outputs a collision of `H`, `L` or `Cm`. Since the size is
  hashed into C, a disclosure that claims another size is also a collision.
  `z0_binding`: the three openings that `decideMapDisclosure` (Z0) and the guest (Z1) check (header, the action's cell,
  metrics at n - 2) are the principal's leaves, or there is a collision. So `in_grant` and `residual_risk_ppm` are the
  committed values.
  Completeness of the honest builder (`hcomp`: every leaf has a path of the right sides folding to the root) is the
  builder's correctness (`mapTree.path` / RFC 9162), as in `NonMember.lean`. Core Lean, no `sorry`.
-/
namespace PcaComp.MapCommit

open PcaComp.NonMember

variable {K α β : Type}

/-- **Binding.** -/
theorem open_binding (H : α → α → α) (L : K → α) (Cm : Nat → α → β) (sides : Nat → Nat → List Bool)
    (M : List K) (T : α) (hne : M.length ≠ 0)
    (hcomp : ∀ (i : Nat) (a : K), M[i]? = some a → ∃ p : List (α × Bool), p.map Prod.snd = sides i M.length ∧ foldRoot H (L a) p = T)
    (size : Nat) (o : LeafPf K α)
    (hidx : o.idx < size) (hs : o.path.map Prod.snd = sides o.idx size)
    (hC : Cm size (foldRoot H (L o.key) o.path) = Cm M.length T) :
    Bad H L Cm ∨ M[o.idx]? = some o.key := by
  by_cases hsz : size = M.length
  · subst hsz
    exact leaf_at (E := T) M T (Cm M.length T) M.length rfl (by rw [if_neg hne]) hcomp o ⟨hidx, hs, hC⟩
  · exact Or.inl (Or.inr (Or.inr ⟨size, _, M.length, T, fun e => hsz (congrArg Prod.fst e), hC⟩))

/-- **Z0 / Z1 binding.** The header, cell and metrics openings the disclosure check accepts are the committed leaves. -/
theorem z0_binding (H : α → α → α) (L : K → α) (Cm : Nat → α → β) (sides : Nat → Nat → List Bool)
    (M : List K) (T : α) (hne : M.length ≠ 0)
    (hcomp : ∀ (i : Nat) (a : K), M[i]? = some a → ∃ p : List (α × Bool), p.map Prod.snd = sides i M.length ∧ foldRoot H (L a) p = T)
    (size : Nat) (oh oc om : LeafPf K α)
    (hh : oh.idx < size ∧ oh.path.map Prod.snd = sides oh.idx size ∧ Cm size (foldRoot H (L oh.key) oh.path) = Cm M.length T)
    (hc : oc.idx < size ∧ oc.path.map Prod.snd = sides oc.idx size ∧ Cm size (foldRoot H (L oc.key) oc.path) = Cm M.length T)
    (hm : om.idx < size ∧ om.path.map Prod.snd = sides om.idx size ∧ Cm size (foldRoot H (L om.key) om.path) = Cm M.length T) :
    Bad H L Cm ∨ (M[oh.idx]? = some oh.key ∧ M[oc.idx]? = some oc.key ∧ M[om.idx]? = some om.key) := by
  rcases open_binding H L Cm sides M T hne hcomp size oh hh.1 hh.2.1 hh.2.2 with b | e1
  · exact Or.inl b
  rcases open_binding H L Cm sides M T hne hcomp size oc hc.1 hc.2.1 hc.2.2 with b | e2
  · exact Or.inl b
  rcases open_binding H L Cm sides M T hne hcomp size om hm.1 hm.2.1 hm.2.2 with b | e3
  · exact Or.inl b
  exact Or.inr ⟨e1, e2, e3⟩

end PcaComp.MapCommit
