# @atlasauth/pca-explain

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| Verifier result missing, malformed, or not an object | Explained as a denial; nothing throws |
| `allow` is truthy but not exactly `true` | Denial |
| `allow: true` but a check failed | Denial, naming the failing check as decisive |
| `allow: true` with no per-check statuses | Denial: no evidence for an allow |
| A check the verifier did not enforce | Shown as "not enforced" or unsupported, never as passed |
| Policy decision missing or malformed | Default-deny explanation |
| Policy `admit` truthy but not exactly `true` | Not an admit |
| Envelope or context that makes the explainer itself throw | Degrades to a denial |
| Chain is not an array | Explained as an empty chain |
| Chain trace without `verify: true` | Labelled `UNVERIFIED` |
| Untrusted text containing credentials | Replaced with `[redacted]` and cut to 400 characters |

## Limits

- It describes a verdict that something else produced. It never verifies a signature, re-evaluates a caveat or authorizes anything itself, and `verify: true` on a chain checks only that chain's structure.
- An explanation is only as complete as the result you pass: with no per-check map or no envelope it can say less, and it will say so rather than guess.
- Redaction is pattern based and is a net, not a proof.
- Remedies are suggestions for a developer. They are not instructions to relax a check.

## Status

Production. The explanation is derived from the verifier's own result and describes it; it is not an authorization decision, and a check shown as "not enforced" means the verifier you ran did not enforce it.

## License

MIT - see LICENSE
