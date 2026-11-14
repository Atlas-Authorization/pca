/-
  PcaProof — machine-checked PCA safety proofs (mirrors formal/pca/*.tla and the shipped
  packages/pca/src decision/verify logic).

  Four theorems:
    * PcaProof.TrustBudget  — Theorem 1, trust-budget safety   (TrustBudget.tla / risk.ts)
    * PcaProof.Attenuation  — Theorem 2, attenuation monotonicity (Attenuation.tla / capability.ts)
    * PcaProof.PolicyVM     — Theorem 3, Policy-VM operational semantics (risk.ts / policy-vm.ts)
                              + REFINEMENT of the admission DECISION to Theorem 1, and a link to
                              Theorem 2's attenuation.
    * PcaProof.Verifier     — Theorem 4, verifier-pipeline small-step semantics (pcactn.ts
                              verifyPCActnCore) + soundness / fail-closed / monotonicity.

  Theorems 3 & 4 close part of the "no mechanized link between the proofs and the code
  semantics" audit gap: they formalize the shipped decision/verify logic AS A SEMANTICS
  and prove the safety properties of THAT semantics (and that it refines Theorems 1/2).
  The remaining model↔code last mile is documented honestly in
  `formal/refinement/README.md`.

  Self-contained: core Lean 4 + `omega` only, no mathlib.
-/
import PcaProof.TrustBudget
import PcaProof.Attenuation
import PcaProof.PolicyVM
import PcaProof.Verifier
import PcaProof.Replay
import PcaProof.ChainLink
import PcaProof.BudgetFocus
import PcaProof.WorkflowAdmit
