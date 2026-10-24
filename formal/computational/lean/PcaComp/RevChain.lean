/-!
  The APPEND-ONLY session revocation chain (packages/pca/src/intent-revocation.ts checkSessionRevocation step f,
  commit 5e718f47; the evidence verifier chains a bundle's epochs the same way, packages/pca-evidence/src/verify.ts).

  A verifier that tracks the last accepted epoch accepts a new one only if: its number is not smaller (no rollback),
  every id of the last list is in the new list (no drop), and an equal number has an equal root (no equivocation).
  For ANY sequence of epochs it accepts one after another (`Accepted`):
  * `chain_sub`   : every later list contains every earlier list;
  * `never_readmit` : an id revoked in an accepted epoch is refused by every later accepted epoch (step g);
  * `chain_num` / `chain_root` : numbers never decrease, and two accepted epochs with the same number have the same root.
  Combined with CryptoVerif `revocation_epoch.cv` (every accepted epoch is the authority's) and the list/root binding
  (Dafny `Merkle.dfy` RootInj: two lists with one root give a SHA-256 collision), an honest authority's revocation can
  never be undone at a tracking verifier, and a dishonest authority's equivocation is two signed statements.
  Core Lean, no `sorry`.
-/
namespace PcaComp.RevChain

variable {K R : Type}

structure Ep (K R : Type) where
  num : Nat
  root : R
  ids : List K

/-- the tracked-state check of step f (last → current) -/
def StepOk (last cur : Ep K R) : Prop :=
  last.num ≤ cur.num ∧ (∀ x ∈ last.ids, x ∈ cur.ids) ∧ (cur.num = last.num → cur.root = last.root)

/-- a sequence of epochs a tracking verifier accepted one after another -/
inductive Accepted : List (Ep K R) → Prop
  | nil : Accepted []
  | one (e : Ep K R) : Accepted [e]
  | cons (e f : Ep K R) (rest : List (Ep K R)) : StepOk e f → Accepted (f :: rest) → Accepted (e :: f :: rest)

theorem Accepted.head {e f : Ep K R} {rest : List (Ep K R)} (h : Accepted (e :: f :: rest)) : StepOk e f := by
  cases h; assumption
theorem Accepted.tail {e f : Ep K R} {rest : List (Ep K R)} (h : Accepted (e :: f :: rest)) : Accepted (f :: rest) := by
  cases h; assumption

theorem chain_sub : ∀ (e : Ep K R) (es : List (Ep K R)), Accepted (e :: es) →
    ∀ f ∈ es, ∀ x ∈ e.ids, x ∈ f.ids
  | _, [], _, f, hf, _, _ => by simp at hf
  | e, f1 :: rest, h, f, hf, x, hx => by
      have h1 : StepOk e f1 := h.head
      have h2 : Accepted (f1 :: rest) := h.tail
      rcases List.mem_cons.mp hf with rfl | hr
      · exact h1.2.1 x hx
      · exact chain_sub f1 rest h2 f hr x (h1.2.1 x hx)

theorem chain_num : ∀ (e : Ep K R) (es : List (Ep K R)), Accepted (e :: es) → ∀ f ∈ es, e.num ≤ f.num
  | _, [], _, f, hf => by simp at hf
  | e, f1 :: rest, h, f, hf => by
      have h1 : StepOk e f1 := h.head
      have h2 : Accepted (f1 :: rest) := h.tail
      rcases List.mem_cons.mp hf with rfl | hr
      · exact h1.1
      · exact Nat.le_trans h1.1 (chain_num f1 rest h2 f hr)

theorem chain_root : ∀ (e : Ep K R) (es : List (Ep K R)), Accepted (e :: es) →
    ∀ f ∈ es, f.num = e.num → f.root = e.root
  | _, [], _, f, hf, _ => by simp at hf
  | e, f1 :: rest, h, f, hf, hn => by
      have h1 : StepOk e f1 := h.head
      have h2 : Accepted (f1 :: rest) := h.tail
      rcases List.mem_cons.mp hf with rfl | hr
      · exact h1.2.2 hn
      · have hle := chain_num f1 rest h2 f hr
        have hf1 : f1.num = e.num := Nat.le_antisymm (hn ▸ hle) h1.1
        rw [chain_root f1 rest h2 f hr (by rw [hn, hf1]), h1.2.2 hf1]

/-- an id revoked in an accepted epoch is never admitted by a later accepted epoch (step g refuses ids in the list) -/
theorem never_readmit (e : Ep K R) (es : List (Ep K R)) (h : Accepted (e :: es)) (x : K) (hx : x ∈ e.ids) :
    ∀ f ∈ es, ¬ (x ∉ f.ids) :=
  fun f hf hn => hn (chain_sub e es h f hf x hx)

end PcaComp.RevChain
