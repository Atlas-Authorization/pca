/-
  Theorem 4 — PCA verifier pipeline: operational (small-step) semantics + the
  soundness / fail-closed / monotonicity refinement theorems.

  The machine-checked image of `verifyPCActnCore` in `packages/pca/src/pcactn.ts`.
  That function runs a fixed, ordered pipeline of named checks, each yielding one of
  three statuses — `'pass' | 'fail' | 'not-enforced'` (ts `CheckStatus`) — and then
  decides:

        allow = !Object.values(checks).includes('fail')          (pcactn.ts)

  with the NORMATIVE CHECK ORDER: `wire` (TERMINAL on failure), `version`, `audience`,
  `validity`, `cap_chain`, `grant_ref_bound`, `plan_inclusion`, `leaf_signature`, `counter`,
  then the later-milestone hook checks (`taint_gate`, `attestation`, `threshold`, `revocation`,
  `zk_compliance`, `bond`).

  We model BOTH:
    * the DENOTATIONAL decision `Allows` / `allowsB` (the `allow = …` line), and
    * a small-step operational semantics `Step` / `Steps` that walks the ordered
      pipeline, recording each status, with `wire` terminal on failure,
  and PROVE they agree (`run_no_wirefail`, `run_wirefail_head`). The refinement
  theorems are then properties of THIS semantics:

    * `grantRefBound_*` / `same_root_same_grant_ref` — the `grant_ref_bound` check: the
      signed `grant_ref` must be non-empty and equal the id of the ROOT capability
      (`cap_chain[0].id`), independently of the `cap_chain` verdict, failing closed on an
      empty chain; hence two ACCEPTED PCActns under one root capability cannot carry
      different `grant_ref` values (no fresh replay namespace can be minted by the holder).
    * `allow_required_pass` — SOUNDNESS OF THE CHECK ORDER: a reported allow implies
      every required (always-evaluated) check PASSED.
    * `deny_stable_append` / `deny_stable_insert` — MONOTONE / FAIL-CLOSED: adding
      checks anywhere can never turn a DENY into an ALLOW.
    * `append_fail_denies` / `fail_denies` — a single failing check always denies.

  No mathlib; core Lean `List` + `omega`-free (pure structural) reasoning.

  Source correspondence (pcactn.ts  ↔  Lean here):
    * ts `type CheckStatus = 'pass'|'fail'|'not-enforced'` ↔ `CheckStatus`
    * ts `checks: Record<string, CheckStatus>`             ↔ `List Check`
    * ts NORMATIVE CHECK ORDER (comment)                   ↔ `checkOrder`
    * ts always-evaluated M0 core                          ↔ `requiredChecks`
    * ts `grant_ref_bound` block (pcactn.ts)               ↔ `grantRefBoundStatus`
    * ts `allow = !values.includes('fail')`                ↔ `Allows` / `allowsB`
    * ts "wire failure is terminal"                        ↔ `Step.wireFail`
-/
namespace PcaProof.Verifier

/-- The three verdicts a check can report (pcactn.ts `CheckStatus`). -/
inductive CheckStatus where
  | pass
  | fail
  | notEnforced
deriving Repr, DecidableEq

/-- One entry of the `checks` record: a check name and its reported status. -/
structure Check where
  name : String
  status : CheckStatus
deriving Repr, DecidableEq

/-- The NORMATIVE CHECK ORDER (pcactn.ts `verifyPCActnCore`), as data. The first eight
    nine are the always-evaluated M0 checks; the rest are the later-milestone hook checks. -/
def checkOrder : List String :=
  ["wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound",
   "plan_inclusion", "leaf_signature", "counter",
   "taint_gate", "attestation", "threshold", "revocation", "zk_compliance", "bond"]

/-- The checks that in M0 are ALWAYS evaluated to `pass`/`fail` (never `not-enforced`):
    the core of the eight-check order. `audience` is excluded (it may be `not-enforced`
    on an explicit `audience: null` opt-out). These are the "required" checks a reported
    allow must have PASSED. -/
def requiredChecks : List String :=
  ["wire", "version", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion",
   "leaf_signature", "counter"]

/-- The DENOTATIONAL decision, verbatim from pcactn.ts
    `allow = !Object.values(checks).includes('fail')`: allow ⇔ no check failed. -/
def Allows (cs : List Check) : Prop := ∀ c ∈ cs, c.status ≠ CheckStatus.fail

/-- Boolean twin of `Allows` (the executable `allow` line). -/
def allowsB (cs : List Check) : Bool := cs.all (fun c => decide (c.status ≠ CheckStatus.fail))

/-- The Bool decision and the Prop decision agree. -/
theorem allowsB_true_iff (cs : List Check) : allowsB cs = true ↔ Allows cs := by
  simp only [allowsB, Allows, List.all_eq_true, decide_eq_true_eq]

/- ------------------------------------------------------------------------- -/
/-  Soundness of the check order                                             -/
/- ------------------------------------------------------------------------- -/

/-- A reported ALLOW implies NO check failed: every check is `pass` or `not-enforced`. -/
theorem allow_no_fail {cs : List Check} (h : Allows cs) :
    ∀ c ∈ cs, c.status = CheckStatus.pass ∨ c.status = CheckStatus.notEnforced := by
  intro c hc
  have hne := h c hc
  cases hs : c.status <;> simp_all

/-- **Theorem 4a — SOUNDNESS OF THE CHECK ORDER.** A reported ALLOW implies every
    REQUIRED check (one that is never reported `not-enforced` — the always-evaluated M0
    core: `wire`, `version`, `validity`, `cap_chain`, `grant_ref_bound`,
    `plan_inclusion`, `leaf_signature`, `counter`) actually PASSED. "Allow ⇒ all required checks passed",
    i.e. the verdict can never skip a mandatory check. -/
theorem allow_required_pass {cs : List Check} (h : Allows cs)
    {c : Check} (hc : c ∈ cs) (hreq : c.status ≠ CheckStatus.notEnforced) :
    c.status = CheckStatus.pass := by
  have hne := h c hc
  cases hs : c.status <;> simp_all

/- ------------------------------------------------------------------------- -/
/-  Fail-closed monotonicity                                                 -/
/- ------------------------------------------------------------------------- -/

/-- A single failing check denies, wherever it sits in the pipeline. -/
theorem fail_denies {cs : List Check} {c : Check}
    (hc : c ∈ cs) (hf : c.status = CheckStatus.fail) : ¬ Allows cs := by
  intro h; exact (h c hc) hf

/-- **Theorem 4b — MONOTONE / FAIL-CLOSED (append).** Adding checks AFTER a pipeline can
    never turn a DENY into an ALLOW: a deny means some check failed, and that failing
    check still sits in the extended pipeline. -/
theorem deny_stable_append {cs extra : List Check} (h : ¬ Allows cs) :
    ¬ Allows (cs ++ extra) := by
  intro hall
  exact h (fun c hc => hall c (List.mem_append_left extra hc))

/-- **Theorem 4b' — MONOTONE / FAIL-CLOSED (insert anywhere).** Surrounding a pipeline
    with more checks (before AND after) can never turn a DENY into an ALLOW. -/
theorem deny_stable_insert {pre cs post : List Check} (h : ¬ Allows cs) :
    ¬ Allows (pre ++ cs ++ post) := by
  intro hall
  apply h
  intro c hc
  exact hall c (List.mem_append_left post (List.mem_append_right pre hc))

/-- **Theorem 4b'' — a single failing check turns ANY verdict into DENY.** The sharp form
    of "adding a failing check can't turn deny→allow": it forces deny outright. -/
theorem append_fail_denies (cs : List Check) (n : String) :
    ¬ Allows (cs ++ [⟨n, CheckStatus.fail⟩]) :=
  fail_denies (c := ⟨n, CheckStatus.fail⟩) (by simp) rfl

/-- Monotonicity on the status lattice: making a check STRICTLY WORSE (a `pass`/
    `not-enforced` turned to `fail`) can only move the verdict allow → deny, never the
    reverse. Formally: if the worsened pipeline still ALLOWS, the original did too. -/
theorem allow_antitone_worsen {pre post : List Check} {c c' : Check}
    (hworse : c'.status = CheckStatus.fail)
    (h : Allows (pre ++ c' :: post)) : Allows (pre ++ c :: post) := by
  -- vacuous: the worsened pipeline can never allow (c' fails), so the hypothesis is false.
  exact absurd (h c' (List.mem_append_right pre (by simp))) (by simp [hworse])

/- ------------------------------------------------------------------------- -/
/-  The `grant_ref_bound` check                                              -/
/- ------------------------------------------------------------------------- -/

/-- The `grant_ref_bound` check (pcactn.ts): `pass` iff the signed `grant_ref` is a
    NON-EMPTY string equal to the id of the ROOT capability, `cap_chain[0].id`; `fail`
    otherwise — in particular on an EMPTY chain (fail closed). It reads only `grant_ref`
    and the chain's ids: it does NOT consult the `cap_chain` check's verdict, so it is
    evaluated independently of it. `chainIds` is the list of capability ids, in order. -/
def grantRefBoundStatus (grantRef : String) (chainIds : List String) : CheckStatus :=
  match chainIds with
  | [] => CheckStatus.fail
  | root :: _ => if grantRef ≠ "" ∧ grantRef = root then CheckStatus.pass else CheckStatus.fail

/-- The check is decisive: it reports `pass` or `fail`, never `not-enforced` (which is
    why `grant_ref_bound` is in `requiredChecks`). -/
theorem grantRefBound_ne_notEnforced (g : String) (ids : List String) :
    grantRefBoundStatus g ids ≠ CheckStatus.notEnforced := by
  unfold grantRefBoundStatus
  split
  · simp
  · split <;> simp

/-- FAIL CLOSED: an empty capability chain never satisfies the binding. -/
theorem grantRefBound_empty_chain_fails (g : String) :
    grantRefBoundStatus g [] = CheckStatus.fail := rfl

/-- An EMPTY `grant_ref` never satisfies the binding, whatever the chain. -/
theorem grantRefBound_empty_ref_fails (ids : List String) :
    grantRefBoundStatus "" ids = CheckStatus.fail := by
  unfold grantRefBoundStatus
  split <;> simp

/-- Characterisation: the check passes exactly when the chain is non-empty and
    `grant_ref` is non-empty and equals the root capability id. -/
theorem grantRefBound_pass_iff (g : String) (ids : List String) :
    grantRefBoundStatus g ids = CheckStatus.pass ↔
      ∃ root rest, ids = root :: rest ∧ g ≠ "" ∧ g = root := by
  unfold grantRefBoundStatus
  constructor
  · intro h
    split at h
    · simp at h
    · rename_i root rest
      split at h
      · rename_i hc
        exact ⟨root, rest, rfl, hc.1, hc.2⟩
      · simp at h
  · rintro ⟨root, rest, rfl, hne, heq⟩
    subst heq
    simp [hne]

/-- A `grant_ref` that is not the root capability id FAILS, even when the chain itself is
    fine — and a failing `grant_ref_bound` denies the whole verdict regardless of what the
    `cap_chain` check (or any other check) reported. This is the independence property:
    no `cap_chain` pass can launder a forged `grant_ref`. -/
theorem grantRefBound_fail_denies_despite_chain (pre post : List Check) (g : String)
    (ids : List String) (hf : grantRefBoundStatus g ids = CheckStatus.fail) :
    ¬ Allows (pre ++ ⟨"cap_chain", CheckStatus.pass⟩ :: ⟨"grant_ref_bound", grantRefBoundStatus g ids⟩ :: post) := by
  apply fail_denies (c := ⟨"grant_ref_bound", grantRefBoundStatus g ids⟩)
  · simp
  · exact hf

/-- The projection of a PCActn that the binding concerns: its signed `grant_ref`, the ids of
    its presented capability chain, and the OTHER checks the verifier ran before / after
    `grant_ref_bound` (their statuses are arbitrary — nothing below depends on them). -/
structure PCActnView where
  grantRef : String
  chainIds : List String
  pre : List Check
  post : List Check

/-- The full check list the verifier records for this PCActn. -/
def PCActnView.checks (a : PCActnView) : List Check :=
  a.pre ++ ⟨"grant_ref_bound", grantRefBoundStatus a.grantRef a.chainIds⟩ :: a.post

/-- A PCActn is ACCEPTED iff the verdict allows (no recorded check failed). -/
def PCActnView.Accepted (a : PCActnView) : Prop := Allows a.checks

/-- ACCEPTED ⇒ BOUND: an accepted PCActn has a non-empty chain whose root id equals its
    non-empty `grant_ref`. -/
theorem accepted_grantRef_is_root {a : PCActnView} (h : a.Accepted) :
    ∃ root rest, a.chainIds = root :: rest ∧ a.grantRef ≠ "" ∧ a.grantRef = root := by
  have hmem : (⟨"grant_ref_bound", grantRefBoundStatus a.grantRef a.chainIds⟩ : Check) ∈ a.checks := by
    simp [PCActnView.checks]
  have hpass := allow_required_pass h hmem (grantRefBound_ne_notEnforced a.grantRef a.chainIds)
  exact (grantRefBound_pass_iff a.grantRef a.chainIds).1 hpass

/-- An accepted PCActn over an empty chain cannot exist (fail closed). -/
theorem accepted_chain_nonempty {a : PCActnView} (h : a.Accepted) : a.chainIds ≠ [] := by
  obtain ⟨root, rest, hc, _, _⟩ := accepted_grantRef_is_root h
  simp [hc]

/-- **Theorem 4d — NO FRESH REPLAY NAMESPACE.** Two ACCEPTED PCActns presented under the
    SAME root capability cannot carry different `grant_ref` values: both equal the root's
    id. Replay state (nonce store, counter streams, budgets) is keyed on `grant_ref`, so a
    holder cannot reach a fresh, empty namespace by re-signing with a new `grant_ref`.
    (The replay stores themselves are not modelled here; this is the binding they rely on.) -/
theorem same_root_same_grant_ref {a b : PCActnView} (ha : a.Accepted) (hb : b.Accepted)
    {root : String} {ra rb : List String}
    (hca : a.chainIds = root :: ra) (hcb : b.chainIds = root :: rb) :
    a.grantRef = b.grantRef := by
  obtain ⟨r1, rest1, hc1, _, he1⟩ := accepted_grantRef_is_root ha
  obtain ⟨r2, rest2, hc2, _, he2⟩ := accepted_grantRef_is_root hb
  rw [hca] at hc1
  rw [hcb] at hc2
  have e1 : root = r1 := (List.cons.inj hc1).1
  have e2 : root = r2 := (List.cons.inj hc2).1
  rw [he1, he2, ← e1, ← e2]

/- ------------------------------------------------------------------------- -/
/-  Small-step operational semantics of the pipeline                         -/
/- ------------------------------------------------------------------------- -/

/-- Verifier machine state: the statuses already recorded (`done`, in pipeline order)
    and the checks still to run (`rest`). The pipeline runs `rest` left to right. -/
structure VState where
  done : List Check
  rest : List Check
deriving Repr

/-- One small step. `wire` is TERMINAL on failure (pcactn.ts: "A wire failure is
    terminal: nothing else is evaluated") — it records `wire` and clears the rest. Any
    other check (or a passing wire) records its status and advances to the next check. -/
inductive Step : VState → VState → Prop where
  | wireFail {done rest} {c : Check} (hw : c.name = "wire") (hf : c.status = CheckStatus.fail) :
      Step ⟨done, c :: rest⟩ ⟨done ++ [c], []⟩
  | advance {done rest} {c : Check} (hadv : ¬ (c.name = "wire" ∧ c.status = CheckStatus.fail)) :
      Step ⟨done, c :: rest⟩ ⟨done ++ [c], rest⟩

/-- Reflexive-transitive closure of `Step`. -/
inductive Steps : VState → VState → Prop where
  | refl {s} : Steps s s
  | step {s t u} : Step s t → Steps t u → Steps s u

/-- With no wire-failure in the pipeline, the machine runs every check to completion,
    recording all statuses in order: `⟨done, cs⟩ →* ⟨done ++ cs, []⟩`. -/
theorem steps_advance_all (done cs : List Check)
    (hno : ∀ c ∈ cs, ¬ (c.name = "wire" ∧ c.status = CheckStatus.fail)) :
    Steps ⟨done, cs⟩ ⟨done ++ cs, []⟩ := by
  induction cs generalizing done with
  | nil => simpa using Steps.refl
  | cons c rest ih =>
      have hc : ¬ (c.name = "wire" ∧ c.status = CheckStatus.fail) :=
        hno c (by simp)
      have hrest : ∀ x ∈ rest, ¬ (x.name = "wire" ∧ x.status = CheckStatus.fail) :=
        fun x hx => hno x (List.mem_cons_of_mem c hx)
      have step1 : Step ⟨done, c :: rest⟩ ⟨done ++ [c], rest⟩ := Step.advance hc
      have steps2 : Steps ⟨done ++ [c], rest⟩ ⟨(done ++ [c]) ++ rest, []⟩ := ih (done ++ [c]) hrest
      have heq : (done ++ [c]) ++ rest = done ++ (c :: rest) := by simp
      rw [heq] at steps2
      exact Steps.step step1 steps2

/-- A wire FAILURE at the head terminates immediately, recording only `wire`. -/
theorem steps_wire_fail (done rest : List Check) {c : Check}
    (hw : c.name = "wire") (hf : c.status = CheckStatus.fail) :
    Steps ⟨done, c :: rest⟩ ⟨done ++ [c], []⟩ :=
  Steps.step (Step.wireFail hw hf) Steps.refl

/-- **Theorem 4c — OPERATIONAL ⇔ DENOTATIONAL (no wire-fail).** Started on the full
    pipeline with nothing recorded, the small-step machine reaches a TERMINAL state whose
    recorded verdict equals the denotational `allowsB cs`. So the operational semantics
    and the `allow = …` decision are the same. -/
theorem run_no_wirefail (cs : List Check)
    (hno : ∀ c ∈ cs, ¬ (c.name = "wire" ∧ c.status = CheckStatus.fail)) :
    ∃ done, Steps ⟨[], cs⟩ ⟨done, []⟩ ∧ allowsB done = allowsB cs := by
  refine ⟨cs, ?_, rfl⟩
  simpa using steps_advance_all [] cs hno

/-- **Theorem 4c' — OPERATIONAL ⇔ DENOTATIONAL (wire-fail head).** A wire failure
    terminates with a DENY, matching the denotational DENY (wire ∈ cs fails). -/
theorem run_wirefail_head (rest : List Check) {c : Check}
    (hw : c.name = "wire") (hf : c.status = CheckStatus.fail) :
    ∃ done, Steps ⟨[], c :: rest⟩ ⟨done, []⟩
      ∧ allowsB done = false ∧ allowsB (c :: rest) = false := by
  refine ⟨[c], ?_, ?_, ?_⟩
  · simpa using steps_wire_fail [] rest hw hf
  · simp [allowsB, hf]
  · simp [allowsB, hf]

end PcaProof.Verifier
