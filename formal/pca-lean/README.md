# PCA formal proofs in Lean 4 — trust-budget safety & attenuation monotonicity

Machine-**proved** (not just model-checked) versions of the two PCA safety
invariants that `formal/pca/*.tla` already verifies with TLC. Where TLC checks
the invariants exhaustively over *finite* bounds, these Lean theorems **prove**
them for all states, all risk levels, all timings, and chains of any length.

- **Theorem 1 — trust-budget safety** — `PcaProof/TrustBudget.lean`
  (mirrors `formal/pca/TrustBudget.tla` + `packages/pca/src/risk.ts`).
- **Theorem 2 — attenuation monotonicity** — `PcaProof/Attenuation.lean`
  (mirrors `formal/pca/Attenuation.tla` + `packages/pca/src/capability.ts`).

## Self-contained — no mathlib

The proofs use only **core Lean 4** (`Int`, `List`) and the `omega` linear-
arithmetic decision procedure (shipped with the toolchain). There is **no
mathlib dependency**, so `lake build` works offline once the pinned toolchain
(`lean-toolchain` → `leanprover/lean4:v4.34.1`) is present. Budgets are modelled
over `Int` (as in the TLA integer grid) so that "budget never goes negative" is
a genuine theorem rather than a `Nat` typing artefact.

## How to check

```sh
cd formal/pca-lean
elan toolchain install "$(cat lean-toolchain)"   # once, if not already present
lake build                                       # builds + checks all proofs
```

A successful `lake build` *is* the proof check: Lean refuses to compile a file
containing an unproved goal. To confirm no theorem secretly rests on `sorry`:

```sh
lake env lean -e 'import PcaProof; open PcaProof; #print axioms TrustBudget.trust_budget_safety'
# ⇒ depends on axioms: [propext, Quot.sound]   (Lean's standard axioms; NOT sorryAx)
```

## Theorem 1 — trust-budget safety (`TrustBudget.lean`)

The admission controller as a state machine `St = (B, sumRisk)` with a Lyapunov
potential `Φ = κ·sumRisk + B`. A metered machine action conserves `Φ` exactly
(because the debit `κ·R` equals the accrued cost); passive leak only lowers it;
nothing but a human recharge raises `B`. Hence `κ·sumRisk ≤ Φ ≤ B₀ ≤ bMax`.

| Lean (`PcaProof.TrustBudget`) | TLA+ (`TrustBudget.tla`) | `risk.ts` |
|---|---|---|
| `structure St (B, sumRisk)` | `VARIABLES B, sumRisk` | `TrustBudget.B`, metered risk sum |
| `cost κ R = κ * R` | `Cost(R) == Kappa * R` | `cost(r, kappa)` |
| `stepMachine` + gate `cost κ R ≤ u.B` on `Reach.machine` | `MachineAction` metered branch (`t<3 ∧ B≥c`) | `admit()` gate + `debit()` |
| `stepLeak L s = max 0 (B − L)` | `Tick` (floors at 0) | `leak()` (`max(0, …)`) |
| `recharge`, `rechargeFull` | `RechargeHuman`, `RechargeFull` | `recharge()`, `rechargeFull()` |
| `phi κ s = κ * sumRisk + B` | (the telescoping quantity in the safety proof) | the invariant arithmetic in `safetyBound()` docstring |
| `Reach` (machine + leak only) | trajectory between two human recharges | — |
| `phi_machine_eq`, `phi_leak_le`, `reach_inv` | TLC’s inductive invariant | — |
| **`trust_budget_safety : κ * s.sumRisk ≤ bMax`** | **`SafetyInvariant == Kappa*sumRisk ≤ Bmax`** | **`safetyBound()`** (`Σr ≤ bMax/κ`) |
| **`trust_budget_safety_div : s.sumRisk ≤ bMax / κ`** | the header bound `Σ r(Aᵢ) ≤ bMax/κ` | `safetyBound()` return value |
| **`reach_budget_nonneg : 0 ≤ s.B`** | `BudgetBounds` (`0 ≤ B`) | `debit` floor at 0 / `admit` gate |
| `recharge_resets` (closes the checkpoint loop) | `RechargeHuman` resets `sumRisk ← 0`, keeps `B ≤ Bmax` | `recharge()` `min(bMax, …)` |

Key statements (all proved, `sorry`-free):

```lean
theorem trust_budget_safety {κ bMax : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitBmax : init.B ≤ bMax) (hInitS : init.sumRisk = 0)
    (h : Reach κ init s) : κ * s.sumRisk ≤ bMax

theorem trust_budget_safety_div {κ bMax : Int} {init s : St}
    (hκ : 0 < κ)
    (hInitB : 0 ≤ init.B) (hInitBmax : init.B ≤ bMax) (hInitS : init.sumRisk = 0)
    (h : Reach κ init s) : s.sumRisk ≤ bMax / κ

theorem reach_budget_nonneg {κ : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitS : 0 ≤ init.sumRisk)
    (h : Reach κ init s) : 0 ≤ s.B
```

`Reach.machine` quantifies over **every** risk level `R ≥ 0` and the timing of
every action/leak, so the bound holds against a maximally adversarial (even fully
compromised) agent — the same adversary the TLA model gives TLC.

## Theorem 2 — attenuation monotonicity (`Attenuation.lean`)

A capability hop is a `List Caveat` of conjunctive constraints; its *effective
authority* `Eff` is the set of `Action`s satisfying every caveat. `verifyChain`'s
shipped structural rule (child = parent with caveats **appended**, an exact
prefix) is modelled by `hops`, and we prove authority only ever narrows.

| Lean (`PcaProof.Attenuation`) | TLA+ (`Attenuation.tla`) | `capability.ts` / `predicates.ts` |
|---|---|---|
| `structure Action (verb, resource, blast)` | `Actions == [verb, resource, blast]` | action under test |
| `inductive Caveat (verb_in / resource_in / max_blast)` | `Caveats` (same three kinds) | `predicates.ts` constraint families |
| `Satisfies : Caveat → Action → Prop` | `Satisfies(cav, a)` | per-caveat predicate |
| `Eff hop a = ∀ cav ∈ hop, Satisfies cav a` | `Eff(caveatSeq)` | effective authority of a hop |
| `EffSub child parent` (`Eff child ⊆ Eff parent`) | `⊆` on `Eff` | — |
| `IsPrefix p c = ∃ s, c = p ++ s` | `IsPrefix(s, t)` | `verifyChain` prefix-equality check |
| `hops root exts` (append-only chain builder) | `Delegate` (append one caveat) | `delegate()` / `attenuate()` |
| **`eff_antitone_append : EffSub (parent ++ ext) parent`** | **`Monotone`** (one hop) | prefix + append-only ⇒ narrowing |
| **`chainMono_hops : ChainMono (hops root exts)`** | **`Monotone`** (`∀ k, Eff(chain[k]) ⊆ Eff(chain[k-1])`) | consecutive hops narrow |
| **`within_root : ∀ hop ∈ hops root exts, EffSub hop root`** | **`WithinRoot`** | "the capability chain is the budget tree" |
| `mem_hops_prefix`, `hops_eq_cons` | `PrefixPreserved` | prefix preserved along the chain |
| trailing `example` (strict narrowing) | the `AllowWiden` negative control | the widening `verifyChain` rejects |

Key statements (all proved, `sorry`-free):

```lean
theorem eff_antitone_append (parent ext : List Caveat) :
    EffSub (parent ++ ext) parent

theorem chainMono_hops (root : List Caveat) (exts : List (List Caveat)) :
    ChainMono (hops root exts)          -- every consecutive child ⊆ parent

theorem within_root (root : List Caveat) (exts : List (List Caveat)) :
    ∀ hop ∈ hops root exts, EffSub hop root     -- transitive: every hop ⊆ root
```

The `max_blast` caveat (`cap` can only tighten across hops) is the formal image of
the multi-agent budget algebra `B_sub ≤ B_parent_remaining` (`risk.ts subBudget`);
monotonicity covers it uniformly with the scope/verb caveats.

### Negative control

The TLA model uses `AllowWiden` to let TLC exhibit a counterexample, proving the
invariant is non-vacuous. Here the trailing `example` proves the ordering is
**strict** — appending `verb_in {1}` genuinely drops a verb-2 action, so
`EffSub [] [verb_in {1}]` is *false*. That is exactly the widening the append-only
/ prefix rule forbids, so it cannot occur on the shipped path.

## Theorem 4 — verifier pipeline + the `grant_ref_bound` check (`Verifier.lean`)

`Verifier.lean` models `verifyPCActnCore` (`packages/pca/src/pcactn.ts`) as an ordered list of
named checks with a small-step semantics, and proves allow ⇒ every required check passed and
fail-closed monotonicity. The normative order is `wire, version, audience, validity, cap_chain,
grant_ref_bound, plan_inclusion, leaf_signature, counter, …`.

The `grant_ref_bound` clause (`grantRefBoundStatus`): `pass` iff `grant_ref` is non-empty and
equals `cap_chain[0].id`; `fail` on an empty chain or any mismatch; it reads only `grant_ref`
and the chain ids, never the `cap_chain` verdict. Proved (axioms: `propext` only for the
structural ones; `sorry`-free, machine-checked with `lake build` on Lean v4.34.1):

```lean
theorem grantRefBound_pass_iff (g : String) (ids : List String) :
    grantRefBoundStatus g ids = CheckStatus.pass ↔ ∃ root rest, ids = root :: rest ∧ g ≠ "" ∧ g = root
theorem grantRefBound_empty_chain_fails (g : String) : grantRefBoundStatus g [] = CheckStatus.fail
theorem grantRefBound_fail_denies_despite_chain …   -- a cap_chain pass cannot launder a forged grant_ref
theorem accepted_grantRef_is_root {a : PCActnView} (h : a.Accepted) : ∃ root rest, a.chainIds = root :: rest ∧ a.grantRef ≠ "" ∧ a.grantRef = root
theorem same_root_same_grant_ref {a b : PCActnView} (ha : a.Accepted) (hb : b.Accepted)
    (hca : a.chainIds = root :: ra) (hcb : b.chainIds = root :: rb) : a.grantRef = b.grantRef
```

`same_root_same_grant_ref` is the replay-namespace consequence: two accepted PCActns under one
root capability cannot have different `grant_ref` values, so a holder cannot reach a fresh
nonce/counter/budget namespace by re-signing. The replay stores themselves are NOT modelled;
this is the binding they rely on.

## Theorem 5 -- replay-store invariants (`Replay.lean`)

Models the store CONTRACT of `packages/pca/src/replay.ts` (`consumeOnce`, `advance`, `prune`) as a state
machine with a clock, over abstract keys. Proved (`sorry`-free; axioms `propext`, `Quot.sound`):

```lean
theorem no_double_accept (h : NReach s) (hx : (k, r, t) ∈ s.log) (hfresh : ¬ live s.store k s.clock) : r < s.clock
theorem prune_preserves_live  -- pruning expired entries never changes liveness at/after the clock
theorem creach_strict         -- accepted counters of one stream are strictly increasing (hence pairwise distinct)
```

Not modelled: distributed/crashing stores (a contract violation), the Postgres implementation.

## File list

```
formal/pca-lean/
├── lean-toolchain            # leanprover/lean4:v4.34.1
├── lakefile.toml             # pca-proof library, no dependencies
├── PcaProof.lean             # root: imports both modules
├── PcaProof/
│   ├── TrustBudget.lean      # Theorem 1
│   ├── Attenuation.lean      # Theorem 2
│   ├── PolicyVM.lean         # Theorem 3
│   ├── Verifier.lean         # Theorem 4 (pipeline + grant_ref_bound)
│   └── Replay.lean           # Theorem 5 (replay-store invariants)
├── .gitignore                # ignores /.lake build artifacts
└── README.md
```
