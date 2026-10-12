# Changelog

## 0.4.1 - 2026-10-12

`PolicyVm.dfy` (the policy-decision model, used by the differential tests) follows the 0.4.1 security fix: the agent-native evaluator gains `max_spend` (`MaxSpendEv`, `MaxSpendSound`), the release rule gains the root caveats outside the envelope (`RootCaveats`, `RootCaveatsCover`, `RootCaveatsEnforced`, `RootMaxSpendEnforced`, `RootCaveatAttenuates`). Re-proved: 288 verified, 0 errors. `createPolicyVm().rootCaveats` exposes the proved selection; the PolicyVm differential generator now places random caveats on the root before and after the envelope.

## 0.4.0 - 2026-10-11

First release. Dafny-proved decision core (171 verified lemmas, no assume / axiom / extern) compiled to JavaScript: capability-chain walk and attenuation, threshold distinct-role count, replay guard and store model, check / verdict combinator, PQ key-authority and suite rules. See docs/pca/security/verified-core.md.

Chain walk, threshold count and replay-guard decision are now called from production (`@atlasauth/pca` capability.ts / threshold.ts / replay.ts). The differential tests compare production against frozen pre-wiring copies (`test/support/legacy/`); `test/support/reference-adapters.ts` is removed (the production code is the adapter). Added `diff-chain-helpers.test.ts`.
