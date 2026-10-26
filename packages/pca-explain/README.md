# @atlasauth/pca-explain

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Plain-language proof traces for Proof-Carrying Authority decisions. Given a PCActn and the result of the verifier, it explains why the action was allowed or denied: which checks passed, the first failing check with a concrete fix, which capability granted the action, which caveat narrowed or failed, and the risk, threshold and budget path. It also renders an attenuation trace for a delegation chain.

Everything is pure and read-only: it never re-authorizes anything and never throws, so malformed input degrades to a best-effort explanation.

## Install

```sh
npm i @atlasauth/pca-explain
```

Depends on `@atlasauth/pca`.

## Usage

The explainer reads the structural core verdict (`verifyPCActnCore`'s per-check map) to say which check failed and how to
fix it. It explains; it does not authorize: the allow / deny decision belongs to the full server verifier (`verifyPCActn` /
`requirePCA`, with the grant from your own store).

<!-- pca-core-verify: allow the structural verdict feeds the explainer; the authorization decision is verifyPCActn / requirePCA -->
```ts
import { explainVerification, explainChain } from '@atlasauth/pca-explain';
import { verifyPCActnCore } from '@atlasauth/pca';

// `pcactn` and `grant` come from your PCA flow.
const result = await verifyPCActnCore(pcactn, { grant, audience: 'ins_acme' });
const ex = explainVerification(pcactn, result);

console.log(ex.toText());
// PCA verification - DENY
// Denied at the "audience binding" check: aud does not match this resource server / instance
//   ...
//   x audience   aud does not match this resource server / instance  <- DECISIVE
//       fix: build the action with aud = this verifier's instance id ...

ex.verdict;           // 'allow' | 'deny'
ex.decisive?.name;    // the first failing check, e.g. 'audience'
ex.decisive?.remedy;  // what to change
ex.passed;            // names of the checks that held

console.log(explainChain([grant]).toText()); // per-hop attenuation trace
```

For the policy decision (admit, step-up or deny), pass the PCActn and the `PolicyDecision` to `explainDecision(pcactn, decision, { envelope, context })`. Supplying the envelope and the action and caveat context lets it name the granting predicate and each caveat's individual outcome; without them it falls back to the decision's own reasons. The result exposes `disposition`, `grant`, `caveats`, `risk`, `admission`, `decisive` and `summary`.

## API

- `explainVerification(pcactn, verifyResult, { now? })` returns a `VerificationExplanation` with `checks`, `passed`, `failed`, `notEnforced`, `decisive`, `summary` and `toText()`.
- `explainDecision(pcactn, decision, { envelope?, context? })` returns a `DecisionExplanation`.
- `explainChain(chain)` returns a `ChainExplanation` with per-hop `hops` and `toText()`.
- `VERIFY_CHECK_ORDER`: the normative check order used for the trace.

## What an explanation will and will not say

- It never says allow unless the verifier did. `explainVerification` reports an allow only for an explicit `allow: true` with per-check statuses and no failing check; `explainDecision` only for an explicit `admit: true`. A truthy value, an allow that a failing check contradicts, an allow with no per-check evidence, and a missing or malformed input are all explained as denials, and nothing throws.
- `explainChain(chain)` shows what a chain claims and labels itself `UNVERIFIED`; `explainChain(chain, { verify: true })` also records whether signatures, links and caveat rules hold.
- Text built from untrusted fields (audience, verb, resource, caveat values, verifier reasons) goes through `cleanText`: JWTs, bearer credentials, URL userinfo, `token=` / `password=` pairs and long token runs become `[redacted]`, and text is cut to 400 characters. A net, not a proof.

## Status

Experimental. The explanation is derived from the verifier's own result and describes it; it is not an authorization decision, and a check shown as "not enforced" means the verifier you ran did not enforce it.

## License

MIT - see LICENSE
