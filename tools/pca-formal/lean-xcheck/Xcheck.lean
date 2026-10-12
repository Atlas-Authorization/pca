/-
  Executable counterparts of the Lean PCA models, with machine-checked links to the Props they implement, used for
  exhaustive small-scope cross-checking against the TypeScript implementation (tools/pca-formal/lean-xcheck/compare.ts).

    satB / effB     decide `Attenuation.Satisfies` / `Attenuation.Eff`        (theorems satB_iff, effB_iff)
    stepR           the consume / tick / prune / advance machine of `Replay`   (theorems consume_sound, adv_sound)
    grantRefBoundStatus  is already computable (Verifier.lean)
-/
import PcaProof.Attenuation
import PcaProof.Replay
import PcaProof.Verifier

namespace Xcheck
open PcaProof PcaProof.Attenuation

def satB : Caveat → Action → Bool
  | .verb_in s, a => s.contains a.verb
  | .resource_in s, a => s.contains a.resource
  | .max_blast c, a => decide (a.blast ≤ c)

theorem satB_iff (c : Caveat) (a : Action) : satB c a = true ↔ Satisfies c a := by
  cases c <;> simp [satB, Satisfies]

def effB (hop : List Caveat) (a : Action) : Bool := hop.all (fun c => satB c a)

theorem effB_iff (hop : List Caveat) (a : Action) : effB hop a = true ↔ Eff hop a := by
  simp [effB, Eff, List.all_eq_true, satB_iff]

/-! ## replay machine -/

structure R where
  clock : Nat
  store : List (Nat × Nat)
  last  : List (Nat × Nat)
deriving Repr

inductive Op where
  | tick (d : Nat)
  | consume (k r : Nat)
  | prune
  | adv (s c : Nat)
deriving Repr

def liveB (s : List (Nat × Nat)) (k now : Nat) : Bool := s.any (fun e => e.1 == k && decide (now ≤ e.2))

theorem liveB_iff (s : List (Nat × Nat)) (k now : Nat) : liveB s k now = true ↔ Replay.live s k now := by
  simp [liveB, Replay.live, List.any_eq_true]

def lookup (l : List (Nat × Nat)) (k : Nat) : Option Nat := (l.find? (fun e => e.1 == k)).map (·.2)

def setLast (l : List (Nat × Nat)) (k c : Nat) : List (Nat × Nat) := (k, c) :: l.filter (fun e => e.1 != k)

def stepR (st : R) : Op → R × String
  | .tick d => ({ st with clock := st.clock + d }, "t")
  | .consume k r =>
      if decide (st.clock ≤ r) && !liveB st.store k st.clock then ({ st with store := (k, r) :: st.store }, "T") else (st, "F")
  | .prune => ({ st with store := st.store.filter (fun e => decide (st.clock ≤ e.2)) }, "p")
  | .adv s c =>
      match lookup st.last s with
      | some l => if decide (l < c) then ({ st with last := setLast st.last s c }, "T") else (st, "F")
      | none => ({ st with last := setLast st.last s c }, "T")

/-- A successful `consume` step is exactly an instance of `Replay.NStep.consume` (for every ghost log). -/
theorem consume_sound (st : R) (k r : Nat) (log : List (Nat × Nat × Nat))
    (h : (stepR st (.consume k r)).2 = "T") :
    Replay.NStep (α := Nat) ⟨st.store, st.clock, log⟩ ⟨(k, r) :: st.store, st.clock, (k, r, st.clock) :: log⟩ := by
  unfold stepR at h
  by_cases hc : (decide (st.clock ≤ r) && !liveB st.store k st.clock) = true
  · simp at hc
    obtain ⟨h1, h2⟩ := hc
    exact Replay.NStep.consume ⟨st.store, st.clock, log⟩ k r h1 (fun hl => by
      have := (liveB_iff st.store k st.clock).2 hl
      simp [this] at h2)
  · simp [hc] at h

/-- A refused `consume` leaves the state unchanged and corresponds to `Replay.NStep.refuse`. -/
theorem consume_refuse (st : R) (k r : Nat) (h : (stepR st (.consume k r)).2 = "F") : (stepR st (.consume k r)).1 = st := by
  unfold stepR at *
  by_cases hc : (decide (st.clock ≤ r) && !liveB st.store k st.clock) = true
  · simp [hc] at h
  · simp [hc]

theorem prune_sound (st : R) (log : List (Nat × Nat × Nat)) :
    Replay.NStep (α := Nat) ⟨st.store, st.clock, log⟩ ⟨(stepR st .prune).1.store, st.clock, log⟩ := by
  simp [stepR]
  exact Replay.NStep.prune ⟨st.store, st.clock, log⟩

/-- A successful `advance` satisfies the hypothesis of `Replay.CStep.adv`. -/
theorem adv_sound (st : R) (s c : Nat) (h : (stepR st (.adv s c)).2 = "T") :
    ∀ l, lookup st.last s = some l → l < c := by
  intro l hl
  by_cases hlt : l < c
  · exact hlt
  · simp [stepR, hl, hlt] at h

def genSeqs : Nat → List Op → List (List Op)
  | 0, _ => [[]]
  | n+1, ops => [] :: (ops.flatMap fun o => (genSeqs n ops).map (o :: ·))

def opName : Op → String
  | .tick d => s!"t{d}"
  | .consume k r => s!"c{k}.{r}"
  | .prune => "p"
  | .adv s c => s!"a{s}.{c}"

def ops : List Op :=
  [.tick 1, .tick 2] ++ ((List.range 2).flatMap fun k => [1, 3, 5].map fun r => Op.consume k r) ++ [.prune]
    ++ ((List.range 2).flatMap fun s => (List.range 3).map fun c => Op.adv s c)

def runSeq (os : List Op) : String :=
  let (_, out) := os.foldl (fun (acc : R × String) o => let (st', r) := stepR acc.1 o; (st', acc.2 ++ r)) ({ clock := 0, store := [], last := [] }, "")
  out

/-! ## attenuation table -/

def alpha : List (String × Caveat) :=
  [("V1", .verb_in [1]), ("V12", .verb_in [1, 2]), ("V23", .verb_in [2, 3]), ("R1", .resource_in [1]), ("R12", .resource_in [1, 2]),
   ("B0", .max_blast 0), ("B1", .max_blast 1)]

def extOpts : List (String × List Caveat) := ("-", []) :: alpha.map fun (n, c) => (n, [c])

def actions : List Action :=
  (List.range 3).flatMap fun v => (List.range 2).flatMap fun r => (List.range 3).map fun b => ⟨v + 1, r + 1, b⟩

def bits (hop : List Caveat) : String := String.ofList (actions.map fun a => if effB hop a then '1' else '0')

def genExts : Nat → List (List (String × List Caveat))
  | 0 => [[]]
  | n+1 => [] :: (extOpts.flatMap fun o => (genExts n).map (o :: ·))

def gStatus : Verifier.CheckStatus → String
  | .pass => "pass" | .fail => "fail" | .notEnforced => "ne"

def main : IO Unit := do
  -- attenuation table
  for (rn, rc) in extOpts do
    for exts in genExts 3 do
      let names := exts.map (·.1)
      let hopsL := Attenuation.hops rc (exts.map (·.2))
      IO.println s!"EFF root={rn} exts={names}|{String.intercalate "," (hopsL.map bits)}"
  -- replay table
  for sq in genSeqs 4 ops do
    IO.println s!"REPLAY {sq.map opName}|{runSeq sq}"
  -- grant_ref_bound table
  for g in ["", "a", "b"] do
    for ids in [[], ["a"], ["b"], ["c"], ["a", "b"], ["b", "a"], ["a", "a"], ["b", "c"]] do
      IO.println s!"GREF g={g} ids={ids}|{gStatus (Verifier.grantRefBoundStatus g ids)}"

end Xcheck


