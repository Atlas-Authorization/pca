import Mathlib
import PcaMath.FameGgm
import PcaMath.FameGgmSec

open PcaMath.FameGgm PcaMath.FameSec

namespace PcaMath.FameMain

variable {F : Type} [Field F] [Fintype F] {Y J : Type} {Q : ℕ}
  [Fintype Y] [Fintype J] [DecidableEq Y] [DecidableEq J]

open Classical in
/-- **FAME CPA security in the type-3 generic bilinear group model** (selective policy, adaptive key queries):
advantage at most `36 m^2 / |F|`, `m = 6 + 3|Y| + n (3 + 3|Y|)`. -/
theorem fame_ggm_cpa (M : Y → J → F) (j0 : J)
    (adv : PcaMath.GgmTransfer.Adv F ((Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2)) (Finset Y))
    (hkeys : ∀ hist k, adv.next hist = PcaMath.GgmTransfer.Op.kq k → Sh M j0 k) (n : ℕ) :
    |((Finset.univ.filter (fun x : Var Y J Q → F =>
          PcaMath.GgmTransfer.result (prm M j0) (PcaMath.GgmTransfer.eqoR x) adv
            (L0 M j0 (TA : P F Y J Q)) n = true)).card : ℚ)
        / (Fintype.card F : ℚ) ^ Fintype.card (Var Y J Q)
      - ((Finset.univ.filter (fun x : Var Y J Q → F =>
          PcaMath.GgmTransfer.result (prm M j0) (PcaMath.GgmTransfer.eqoR x) adv
            (L0 M j0 (TB : P F Y J Q)) n = true)).card : ℚ)
        / (Fintype.card F : ℚ) ^ Fintype.card (Var Y J Q)|
      ≤ 36 * ((6 + 3 * Fintype.card Y + n * (3 + 3 * Fintype.card Y) : ℕ) : ℚ) ^ 2 / Fintype.card F :=
  fame_ggm_cpa_prob_of M j0 (fun held h => fameB M j0 held h) adv hkeys n

end PcaMath.FameMain
