# Changelog

## 0.4.2 (unreleased)

`Wire.dfy` gains compiled fast paths, each proved equal to the specification functions: `Fast.AcceptsU` (== `Json.ParseTop(t).Some?`, `Api.ParseAcceptsUSpec`) and `FastP.CanonU` (== `Json.CanonText`, `Api.CanonicalOfValueU`). They work on native 16-bit units and indices and are linear (one scan; one salted duplicate-key table per document; a merge sort of each object's keys), so `wireAcceptsText` and `wireCanonicalizeStrict` no longer allocate a BigNumber per code unit, no longer copy their accumulator per character or per member, and no longer exhaust the stack on wide arrays / objects. Measured (12-core Windows box): strictParse gate on a 1 MiB string 1.9 s -> about 35 ms, 100,000 escapes 126 s -> 9 ms; canonicalizeStrict of a 5,000-key object 809 s -> 14 ms, of a 20,000-character string 25 s -> under 5 ms. Re-proved: Wire.dfy 2,108 verified, 0 errors.

`Attest.dfy`: `IndexOf` and `DropAged` (the proved nonce store, opt-in `noncestore`) get `by method` bodies (an index loop; one slice), proved equal to the recursive definitions. The compiled recursive form copied the tail and recursed once per stored nonce: quadratic per consume, and a stack overflow once the store held a few thousand nonces (default capacity 100,000). A consume is now linear in the store size; 2,000 consumes took 118 s, now about 1 s. Re-proved: 139 verified, 0 errors.

`Regex.dfy`: `Size` evaluates `Size(inner)` once per repeat (a `var`; same function). Written with three calls, the compiled function was exponential in the nesting depth of repeats: `'(?:'.repeat(30) + 'a?' + ')?'.repeat(30)` never finished; it now takes about 50 ms. Re-proved: 245 verified, 0 errors.

## 0.4.1 - 2026-10-12

`PolicyVm.dfy` (the policy-decision model, used by the differential tests) follows the 0.4.1 security fix: the agent-native evaluator gains `max_spend` (`MaxSpendEv`, `MaxSpendSound`), the release rule gains the root caveats outside the envelope (`RootCaveats`, `RootCaveatsCover`, `RootCaveatsEnforced`, `RootMaxSpendEnforced`, `RootCaveatAttenuates`). Re-proved: 288 verified, 0 errors. `createPolicyVm().rootCaveats` exposes the proved selection; the PolicyVm differential generator now places random caveats on the root before and after the envelope.

## 0.4.0 - 2026-10-11

First release. Dafny-proved decision core (171 verified lemmas, no assume / axiom / extern) compiled to JavaScript: capability-chain walk and attenuation, threshold distinct-role count, replay guard and store model, check / verdict combinator, PQ key-authority and suite rules. See docs/pca/security/verified-core.md.

Chain walk, threshold count and replay-guard decision are now called from production (`@atlasauth/pca` capability.ts / threshold.ts / replay.ts). The differential tests compare production against frozen pre-wiring copies (`test/support/legacy/`); `test/support/reference-adapters.ts` is removed (the production code is the adapter). Added `diff-chain-helpers.test.ts`.
