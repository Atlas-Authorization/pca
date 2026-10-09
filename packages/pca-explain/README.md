# @atlasauth/pca-explain

Plain-language proof traces for Proof-Carrying Authority decisions. Given a PCActn and the result of the verifier, it explains why the action was allowed or denied: which checks passed, the first failing check with a concrete fix, which capability granted the action, which caveat narrowed or failed, and the risk, threshold and budget path. It also renders an attenuation trace for a delegation chain.

Everything is pure and read-only: it never re-authorizes anything and never throws, so malformed input degrades to a best-effort explanation.

## Install

```sh
npm i @atlasauth/pca-explain
```

Depends on `@atlasauth/pca`.

## Usage

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

## Status

Experimental. The explanation is derived from the verifier's own result and describes it; it is not an authorization decision, and a check shown as "not enforced" means the verifier you ran did not enforce it.

## License

MIT - see LICENSE
