# Changelog

## 0.4.0 - 2026-10-11

First release. Dafny-proved decision core (170 verified lemmas, no assume / axiom / extern) compiled to JavaScript: capability-chain walk and attenuation, threshold distinct-role count, replay guard and store model, check / verdict combinator, PQ key-authority and suite rules. See docs/pca/security/verified-core.md.

Chain walk, threshold count and replay-guard decision are now called from production (`@atlasauth/pca` capability.ts / threshold.ts / replay.ts). The differential tests compare production against frozen pre-wiring copies (`test/support/legacy/`); `test/support/reference-adapters.ts` is removed (the production code is the adapter). Added `diff-chain-helpers.test.ts`.
