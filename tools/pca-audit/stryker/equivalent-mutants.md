# Surviving mutants judged equivalent or unreachable

Measured with `tools/pca-audit/stryker/run.sh` (Stryker 10.0.0, vitest runner, perTest coverage). Line numbers refer to
the sources at the time of the run; "L183:12" is line 183, column 12 as Stryker prints it. A mutant is listed only
when no input reachable through the public API changes the observable verdict (or only changes an unreachable
fallback message). Everything not listed here was either killed or is simply not yet killed.

## `src/capability.ts` (95.86 % measured: 440 killed, 19 survived; three of those 19 killed afterwards, see the end)

| Mutant | Why it is equivalent |
|---|---|
| L116:5 `typeof limit === 'number'` -> `true` (`isBudgetAllocCaveat`) | The next operand `Number.isFinite(limit)` is false for every non-number, so the typeof test is redundant. |
| L135:9 and L187:9 `typeof lim !== 'number'` -> `false` (`allocationsMonotone`, `budgetAllocNodes`) | The following `!Number.isFinite(lim)` is true for every non-number, so the verdict is the same. |
| L131:19 `i <= caveats.length` and L182:20 `ci <= leaf.caveats.length` | The one extra iteration reads `undefined`, which the `typeof cv !== 'object'` guard skips. |
| L183:12 (`hop < chain.length - 1` -> `true` / `<=`) and L183:18 (`chain.length + 1`) | The second operand `chain[hop].caveats.length <= ci` is false at the last hop because `ci < leaf.caveats.length` and the leaf is the last hop, so `hop` can never advance past it. |
| L242:11, L246:11, L250:11, L254:11, L258:11 `suite?.x` -> `suite.x`; L270:92 `suite?.alg` -> `suite.alg` | These run only when `resolveSigAlg(suite?.alg)` resolved a non-default suite, which requires `suite` to be defined. `suite` is never undefined there. |
| L289:9 `pqPk !== undefined` -> `true` | For every suite `seal` can reach, a non-ed25519 suite has a defined `pq_pk`. The only suites without one (fn-dsa) throw earlier (`canonicalize: unsupported type undefined`; fn-dsa hops are not supported in capability chains). |
| L449:7 `!alloc.ok` -> `true` | `alloc` is `{ ok: true }` on the other path, so returning it is identical to `return { ok: true }`. |

Killed after the measurement (new tests, not yet re-measured): L254:9 and L254:11 (a real SLH-DSA-SHA2-256s hop must
seal and verify) and L397:44 (a function-valued caveat carrying a string `type` is malformed).

## `src/server/verify.ts` (85.97 % measured: 239 killed, 31 survived, 8 with no coverage)

| Mutant | Why it is equivalent or unreachable |
|---|---|
| L173:41, L179:54, L192:22, L204:18, L234:22, L244:23, L244:49, L254:15 `p.x?.y` -> `p.x.y` | `verifyPCActnCore` has already rejected a PCActn whose `action`, `plan` or `freshness` is missing or not an object (terminal wire failure), so these are always objects here. |
| L202:16 `bc.lastAcceptedSeq !== undefined` -> `true` | `seq < undefined` is false, so the replay branch is not taken either way. |
| L242:52 `ctx.budget === undefined` -> `false` | The caller already builds `budgetIn` with `B: 0` when no budget is supplied; `decideBudget` repeats the zeroing. |
| L100:44 `typeof c === 'string'` -> `true` | The class reaches `classRank` as a string (wire validation); a non-string would only map to the default rank 2 anyway. |
| L161:9 `!core.allow && core.reason` -> `\|\|` | `core.reason` is always set when `core.allow` is false, and absent when it is true, so both forms push the same reasons. |
| L248:11 and L260:15 (`typeof p.tool_binding === 'string'`, `typeof p.caution === 'number'` -> `true`) | Wire validation already restricts both fields to their types, so the guard never sees another type. |
| L240:23 `>` -> `>=` on the reversibility rank | Only differs when the declared and authoritative classes have equal rank but different spelling (an unknown class string versus `irreversible`); both are then treated as the most restrictive class. |
| L285:37 / L285:44 / L289:44, L279:92 (message template strings) | The `policy:` / `delegated_caveats` prefixes are asserted by `allow`, `checks.*` and reason-substring tests; the exact empty-string replacement of an informational suffix is not a decision. |
| L287:9 and L287:33 (`releaseGuardianShare` informational reasons) | Only the informational reasons attached to an allowed verdict change; the decision itself is `checks` + `d.releaseGuardianShare`. |
| L309:9, L309:23, L309:66 (`'denied'` fallback reason) | A denied verdict always has at least one reason on every reachable path; the fallback is defence in depth. |
| L311:15 / L312:23 / L312:89 (outer `catch`, fail-closed message) | Reached only by an exception the earlier code does not throw; the fail-closed path itself is covered by `failClosed` tests, the NOCOV mutants are its message strings. |
| L158:71, L195:42, L201:45, L215:62 (fallback strings / default chain) | Fallbacks used only if a sub-verifier returns a failure with no reason, or `cap_chain` is not an array (already refused as a wire failure). |

Killed after the measurement (new tests in `src/server/verify.test.ts`): L158:56 and L201:33 (reasons from the core
verifier and the beacon verifier are passed through verbatim).

## First run pending (0.5 audit-readiness modules)

`src/frost-dkg-channel.ts`, `src/frost-dkg-tls.ts`, the 0.5 additions to `src/zk.ts` (risk-bound circuit layout, `policyVmRiskHash`, the bound backend, `circuitVersion`) and `src/zk-ceremony.ts` (`circuitProvenance`, `checkCircuitProvenance`) are in the Stryker plan automatically (every `src/**/*.ts` of a package with ledger entries; none is excluded by `tsconfig.build.json` or `stryker.base.json`). They have not been measured yet: survivors are to be killed or ledgered after the first CI run.
