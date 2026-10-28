/-!
  KEM combiner (`kem.ts`: X25519 + ML-KEM with a HKDF combiner over both shared secrets and both ciphertexts; X-Wing).

  WHAT IS PROVED (symbolic, Dolev-Yao, the combiner hash is a free constructor = a random oracle): the hybrid key
  `K* = H(ss1* || ss2* || c1* || c2*)` of the challenge encapsulation cannot be derived by an adversary that

    * knows both challenge ciphertexts,
    * can call the hybrid decapsulation oracle on EVERY ciphertext pair other than the challenge pair (and so learns
      `H(ss1(c1) || ss2(c2) || c1 || c2)` for each, including pairs that reuse one challenge component), and
    * is handed the shared secret of ONE component in the clear (that component is fully broken),

  as long as the OTHER component's challenge shared secret stays underivable. So the hybrid key is secret if EITHER
  component is (`hybrid_secret_if_kem1_secret`, `hybrid_secret_if_kem2_secret`). `combiner_binding` is the
  transcript-binding half: the key commits to the whole input, up to a collision of the combiner hash.

  WHAT IS ASSUMED (named; NOT mechanised here): the symbolic hypothesis "a component's challenge secret is underivable"
  stands for the component's IND-CCA security (NA-MLKEM for ML-KEM-768/1024 after the Fujisaki-Okamoto transform,
  NA-GDH for the X25519 DH-KEM), and the passage from this symbolic secrecy to computational IND-CCA of the hybrid is
  the published combiner theorem (Giacon, Heuer, Poettering PKC 2018; Bindel, Brendel, Fischlin, Goncalves, Stebila
  PQCrypto 2019; X-Wing, Barbosa et al. 2024) with the hash as a random oracle (NA-ROM). It is a model of the
  combiner's logic, not of the code and not a computational reduction.

  Core Lean only, no `sorry`.
-/
namespace PcaComp.Kem

inductive T where
  | atom : Nat → T
  | pair : T → T → T
  | hash : T → T
  deriving DecidableEq

/-- `s` does not occur bare (outside a hash) in the term -/
def Clean (s : Nat) : T → Prop
  | .atom n => n ≠ s
  | .pair a b => Clean s a ∧ Clean s b
  | .hash _ => True

/-- `K` is neither the term nor a pair-component (at any depth) of it -/
def NoK (K : T) : T → Prop
  | .atom n => T.atom n ≠ K
  | .pair a b => T.pair a b ≠ K ∧ NoK K a ∧ NoK K b
  | .hash a => T.hash a ≠ K

/-- the adversary's derivations from a knowledge set `Γ`: pairing, projection, hashing (random oracle) -/
inductive Der (Γ : T → Prop) : T → Prop
  | ax {t : T} : Γ t → Der Γ t
  | pair {a b : T} : Der Γ a → Der Γ b → Der Γ (.pair a b)
  | fst {a b : T} : Der Γ (.pair a b) → Der Γ a
  | snd {a b : T} : Der Γ (.pair a b) → Der Γ b
  | hash {a : T} : Der Γ a → Der Γ (.hash a)

/-- the hybrid key of a transcript: shared secrets then ciphertexts, hashed -/
def key (s1 s2 c1 c2 : T) : T := .hash (.pair s1 (.pair s2 (.pair c1 c2)))

/-- If every known term is `s`-clean and never contains `K`, so is every derivable term, provided `K = H(..s..)`
    has `s` as one of its two secret inputs. -/
theorem der_inv (s : Nat) (s1 s2 c1 c2 : T) (hs : s1 = .atom s ∨ s2 = .atom s)
    (Γ : T → Prop) (hΓ : ∀ t, Γ t → Clean s t ∧ NoK (key s1 s2 c1 c2) t) :
    ∀ t, Der Γ t → Clean s t ∧ NoK (key s1 s2 c1 c2) t := by
  intro t d
  induction d with
  | ax h => exact hΓ _ h
  | pair _ _ iha ihb =>
      exact ⟨⟨iha.1, ihb.1⟩, by simp [key], iha.2, ihb.2⟩
  | fst _ ih => exact ⟨ih.1.1, ih.2.2.1⟩
  | snd _ ih => exact ⟨ih.1.2, ih.2.2.2⟩
  | hash _ ih =>
      refine ⟨trivial, ?_⟩
      intro heq
      simp only [key, T.hash.injEq] at heq
      subst heq
      rcases hs with h | h
      · subst h; exact ih.1.1 rfl
      · subst h; exact ih.1.2.1 rfl

/-- the key is underivable when the knowledge set is clean in one secret input -/
theorem key_underivable (s : Nat) (s1 s2 c1 c2 : T) (hs : s1 = .atom s ∨ s2 = .atom s)
    (Γ : T → Prop) (hΓ : ∀ t, Γ t → Clean s t ∧ NoK (key s1 s2 c1 c2) t) :
    ¬ Der Γ (key s1 s2 c1 c2) := by
  intro d
  have := (der_inv s s1 s2 c1 c2 hs Γ hΓ _ d).2
  exact this rfl

/-! ### The hybrid game -/

/-- ciphertext atoms (public) -/
def ct (c : Nat) : T := .atom (1000 + c)

/-- component shared secrets: the challenge ciphertext `cs i` of component `i` encapsulates the hidden atom `i`;
    every other ciphertext decapsulates to a value the decapsulation oracle gives away (a fresh public atom) -/
def ssf (i cstar c : Nat) : T := if c = cstar then .atom i else .atom (100000 + 2 * c + i)

/-- challenge parameters: hidden secrets are atoms 1 and 2, challenge ciphertexts 3 and 4 -/
abbrev K0 : T := key (.atom 1) (.atom 2) (ct 3) (ct 4)

/-- the hybrid decapsulation oracle on `(c1, c2)` -/
def oracle (c1 c2 : Nat) : T := key (ssf 1 3 c1) (ssf 2 4 c2) (ct c1) (ct c2)

theorem atoms_ne {a b : Nat} (h : a ≠ b) : T.atom a ≠ T.atom b := by simp [h]

theorem oracle_ne (c1 c2 : Nat) (h : ¬(c1 = 3 ∧ c2 = 4)) : oracle c1 c2 ≠ K0 := by
  intro heq
  simp only [oracle, K0, key, T.hash.injEq, T.pair.injEq] at heq
  obtain ⟨e1, e2, e3, e4⟩ := heq
  simp only [ssf, ct, T.atom.injEq] at e1 e2 e3 e4
  apply h
  constructor
  · omega
  · omega

/-- knowledge when component 2 is broken (its challenge secret is public): both challenge ciphertexts, atom 2,
    and the hybrid oracle everywhere except at the challenge pair -/
def Γ2 (t : T) : Prop :=
  t = ct 3 ∨ t = ct 4 ∨ t = .atom 2 ∨ ∃ c1 c2, ¬(c1 = 3 ∧ c2 = 4) ∧ t = oracle c1 c2

/-- knowledge when component 1 is broken -/
def Γ1 (t : T) : Prop :=
  t = ct 3 ∨ t = ct 4 ∨ t = .atom 1 ∨ ∃ c1 c2, ¬(c1 = 3 ∧ c2 = 4) ∧ t = oracle c1 c2

theorem Γ2_inv : ∀ t, Γ2 t → Clean 1 t ∧ NoK K0 t := by
  intro t h
  rcases h with h | h | h | ⟨c1, c2, hn, h⟩
  · subst h; simp [ct, Clean, NoK, K0, key]
  · subst h; simp [ct, Clean, NoK, K0, key]
  · subst h; simp [Clean, NoK, K0, key]
  · subst h; exact ⟨by simp [oracle, key, Clean], oracle_ne c1 c2 hn⟩

theorem Γ1_inv : ∀ t, Γ1 t → Clean 2 t ∧ NoK K0 t := by
  intro t h
  rcases h with h | h | h | ⟨c1, c2, hn, h⟩
  · subst h; simp [ct, Clean, NoK, K0, key]
  · subst h; simp [ct, Clean, NoK, K0, key]
  · subst h; simp [Clean, NoK, K0, key]
  · subst h; exact ⟨by simp [oracle, key, Clean], oracle_ne c1 c2 hn⟩

/-- Component 2 totally broken (its challenge secret handed over, decapsulation oracle open), component 1's
    challenge secret underivable: the hybrid key is still underivable. -/
theorem hybrid_secret_if_kem1_secret : ¬ Der Γ2 K0 :=
  key_underivable 1 (.atom 1) (.atom 2) (ct 3) (ct 4) (Or.inl rfl) Γ2 Γ2_inv

/-- Component 1 totally broken, component 2's challenge secret underivable: the hybrid key is underivable. -/
theorem hybrid_secret_if_kem2_secret : ¬ Der Γ1 K0 :=
  key_underivable 2 (.atom 1) (.atom 2) (ct 3) (ct 4) (Or.inr rfl) Γ1 Γ1_inv

/-- Sanity: the model has teeth. If BOTH challenge secrets leak, the key is derivable. -/
theorem both_broken_derivable (Γ : T → Prop) (h1 : Γ (.atom 1)) (h2 : Γ (.atom 2)) (h3 : Γ (ct 3)) (h4 : Γ (ct 4)) :
    Der Γ K0 :=
  .hash (.pair (.ax h1) (.pair (.ax h2) (.pair (.ax h3) (.ax h4))))

/-! ### Transcript binding (collision escape) -/

def Coll {α β : Type} (H : α → β) : Prop := ∃ x y, x ≠ y ∧ H x = H y

/-- The combiner hash binds `(ss1, ss2, c1, c2)`: two different inputs with one key are a hash collision. -/
theorem combiner_binding {β : Type} (H : (List Nat) → β) (x y : List Nat) (h : H x = H y) : x = y ∨ Coll H := by
  by_cases hxy : x = y
  · exact Or.inl hxy
  · exact Or.inr ⟨x, y, hxy, h⟩

end PcaComp.Kem
