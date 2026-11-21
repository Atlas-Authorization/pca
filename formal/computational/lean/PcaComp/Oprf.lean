/-!
  OPRF / VOPRF (RFC 9497) as used by `pca-oprf` for private revocation checks and private rate limits.

  Model: the prime-order group is written in the EXPONENT: an element is the scalar `a` standing for `g^a`, in a
  scalar FIELD `F` (a hypothesis of every theorem, not an axiom). Group operations are field operations: composing
  elements is addition, raising to a scalar is multiplication. This is the standard algebraic core; the hardness of
  discrete log, which the exponent view cannot express, enters only as the named assumptions below.

  PROVED:
    * `oblivious`: PERFECT obliviousness. For any two inputs `x, y` (hash-to-group images `hx, hy`, nonzero) the map
      `r -> r * hx * hy^-1` is a bijection of the nonzero blinds and sends the blinded element of `y` to that of `x`
      (`hy * phi(r) = hx * r`), so the distribution of the blinded element the server sees is the same for every input.
    * `unblind_correct`: unblinding the server's answer `k * (h * r)` with `r^-1` gives `k * h`, the PRF value.
    * `dleq_special_soundness`: two accepting DLEQ transcripts with the same commitments and different challenges force
      `Z = x * B` for the committed key `pk = x`. So a VOPRF answer that passes the proof check is the PRF under the
      key the client pinned, not under another key (the verifiability the private-revocation composition needs).
    * `prf_binding` / `revocation_set_sound`: a revocation-set hit identifies the id, up to a collision of the
      finalisation hash or of hash-to-group.
  ASSUMED (named): NA-OMDL (one-more discrete log; the OPRF output is pseudorandom, Jarecki, Kiayias, Krawczyk, Xu
  2016; RFC 9497 security notes), NA-ROM for hash-to-group and Finalize, and the Fiat-Shamir extraction that turns
  "an accepting DLEQ proof" into "two accepting transcripts" (forking lemma, RP-3 in the ledger). The POPRF `info`
  binding and the blind-sampling implementation are not modelled.

  Core Lean only, no `sorry`.
-/
namespace PcaComp.Oprf

open Lean.Grind

variable {F : Type} [Field F]

/-- the blinded element the server sees for hash-to-group image `h` and blind `r` -/
def blind (h r : F) : F := h * r

/-- the coupling of blinds: sends input `y`'s blind to the blind that gives input `x`'s blinded element -/
def phi (hx hy r : F) : F := r * hx * hy⁻¹

def psi (hx hy r : F) : F := r * hy * hx⁻¹

theorem oblivious (hx hy r : F) (nx : hx ≠ 0) (ny : hy ≠ 0) :
    blind hy (phi hx hy r) = blind hx r := by
  unfold blind phi; grind

theorem phi_psi (hx hy r : F) (nx : hx ≠ 0) (ny : hy ≠ 0) : psi hx hy (phi hx hy r) = r := by
  unfold psi phi; grind

theorem psi_phi (hx hy r : F) (nx : hx ≠ 0) (ny : hy ≠ 0) : phi hx hy (psi hx hy r) = r := by
  unfold psi phi; grind

theorem phi_ne_zero (hx hy r : F) (nx : hx ≠ 0) (ny : hy ≠ 0) (nr : r ≠ 0) : phi hx hy r ≠ 0 := by
  intro h
  have e := (phi_psi hx hy r nx ny).symm
  rw [h] at e
  unfold psi at e
  apply nr
  rw [e]; grind

theorem unblind_correct (k h r : F) (nr : r ≠ 0) : (k * blind h r) * r⁻¹ = k * h := by
  unfold blind; grind

/-! ### DLEQ special soundness (the VOPRF proof) -/

/-- A DLEQ transcript for statement `(pk = x, B, Z)` under commitments `(a1, a2)`, challenge `c`, response `s`:
    `s = a1 + c x` (against the generator) and `s B = a2 + c Z` (against `B`). -/
def DleqOk (x b z a1 a2 c s : F) : Prop := s = a1 + c * x ∧ s * b = a2 + c * z

theorem dleq_special_soundness (x b z a1 a2 c c' s s' : F)
    (h1 : DleqOk x b z a1 a2 c s) (h2 : DleqOk x b z a1 a2 c' s') (hc : c - c' ≠ 0) : z = x * b := by
  obtain ⟨e1, e2⟩ := h1
  obtain ⟨e3, e4⟩ := h2
  have hx : (c - c') * (z - x * b) = 0 := by grind
  have hinv : (c - c')⁻¹ * (c - c') = 1 := by grind
  grind

/-! ### Private revocation: a hit identifies the id -/

/-- the OPRF value of identifier `i` under key `k`: finalisation hash of the input and the unblinded element -/
def prf {I O : Type} (fin : I × F → O) (h : I → F) (k : F) (i : I) : O := fin (i, k * h i)

def Coll {α β : Type} (H : α → β) : Prop := ∃ x y, x ≠ y ∧ H x = H y

theorem prf_binding {I O : Type} (fin : I × F → O) (h : I → F) (k : F) (hk : k ≠ 0) (i j : I)
    (e : prf fin h k i = prf fin h k j) : i = j ∨ Coll fin ∨ Coll h := by
  by_cases hij : i = j
  · exact Or.inl hij
  · by_cases hp : (i, k * h i) = (j, k * h j)
    · exact Or.inl (by simpa using (Prod.mk.inj hp).1)
    · exact Or.inr (Or.inl ⟨_, _, hp, e⟩)

/-- Membership of `prf k id` in the published set `R = { prf k r | r revoked }` means `id` is revoked, or the
    finalisation hash has a collision, or hash-to-group has one. -/
theorem revocation_set_sound {I O : Type} (fin : I × F → O) (h : I → F) (k : F) (hk : k ≠ 0)
    (revoked : List I) (i : I) (hit : prf fin h k i ∈ revoked.map (prf fin h k)) :
    i ∈ revoked ∨ Coll fin ∨ Coll h := by
  obtain ⟨j, hj, e⟩ := List.mem_map.mp hit
  rcases prf_binding fin h k hk j i e with rfl | c | c
  · exact Or.inl hj
  · exact Or.inr (Or.inl c)
  · exact Or.inr (Or.inr c)

end PcaComp.Oprf
