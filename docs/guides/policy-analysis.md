---
title: Analyze, author and test a policy
order: 22
---

# Analyze, author and test a policy

> **Status: production (pending CI).** The analysis tools are in `@atlasauth/pca-analyzer` and `@atlasauth/pca-policy-ci`; the forbid certificate and the linked templates are in `@atlasauth/pca`. Nothing here runs inside the verifier, and nothing here can widen a grant. See [maturity tiers](../maturity.md).

A grant is a promise about everything an agent may ever do, but the verifier only ever sees one action at a time. These tools answer the questions you have **before** you sign: how much can leave, what needs a human, what changed, what the agent may do right now, what it never used, and whether your tests would notice a mistake.

Three rules hold for all of them.

- **Every witness is re-checked.** A counterexample, a repair or a proposed grant is run through the real evaluator before you see it. A search that is wrong can lose an answer, never invent one.
- **Unsure means unsure.** When a policy uses something the analysis cannot decide exactly (a regular-expression resource, a comparison between two fields, a grid that is too large) the result says `approximate` and never claims the safe answer.
- **Nothing is applied for you.** A narrower grant, an access request or a repair is a proposal for a person to read.

## How much can leave

```ts
import { maxExposure, vetoesFromConstitution } from '@atlasauth/pca-analyzer';

const policy = {
  predicates: [{ verb: 'stripe.refund', resource: '/acct/*', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }] }],
  caveats: [{ type: 'rate', max: 3, per_secs: 86400 }],
  vetoes: vetoesFromConstitution(constitution).vetoes, // optional: your prohibitions
};
const e = maxExposure(policy, { verb: 'stripe.refund', integer: true, windowSecs: 86400, constitution });
e.perAction;            // { admitted: true, max: 500, attained: true, witness: { ... amount: 500 } }
e.autonomousPerAction;  // the largest single action that needs no human
e.window.bound;         // 1500: three refunds of 500 in a day
e.window.basis;         // ['per-action ceiling', 'rate caveat 3/86400s']
```

The number is an **upper bound**. It composes the per-action ceiling with rate limits and the `cap` and `rate` invariants of a constitution, and, with `budgetModel: 'dollars'`, the grant's budget allocation (in risk units an allocation says nothing about the amount, so it is left out and listed). An invariant counts only when it provably applies to every action of the verb (a universal trigger); the ones left out are listed in `window.notApplied`, because leaving one out can only raise the bound. An exclusive bound (`amount < 100`) is a supremum for a real number and the largest integer below it for an integer parameter. With no ceiling the answer is `Infinity` unless the action schema bounds the parameter.

`escalationSurface(policy)` lists verified actions that **need a human**, `delegationEnvelope([root, ...child])` gives everything any holder of the leaf could do, with the remaining delegation depth and any hop that is wider than its parent.

## What changed

```ts
import { diffPolicies, diffGate } from '@atlasauth/pca-analyzer';

const d = diffPolicies(oldPolicy, newPolicy, { exposure: { verb: 'stripe.refund', integer: true } });
d.summary;   // ['deny->allow: 4+ action(s), e.g. stripe.refund /acct/0 {"amount":750}', 'max exposure of stripe.refund rises by 300']
diffGate(d); // { ok: false, reasons: ['widens authority: ...', 'max exposure rises by 300'] }
```

The diff is ternary. `deny->allow` and `deny->escalate` widen; `allow->escalate` and `allow->deny` narrow; each kind comes with concrete actions. A diff that could not be decided exactly is never reported as "no change". In CI:

```sh
pca-policy-ci diff old.json new.json --verb stripe.refund --integer          # fails on any widening
pca-policy-ci diff old.json new.json --allow-widen --max-exposure-increase 100
```

An optional solver (`WitnessBackend`) can look for counterexamples when the grid is too large. Its witnesses are re-checked and discarded if wrong; its "no such action" is reported as `solver-claimed, not machine-checked` and never as a proof.

## What may I do right now

```ts
import { whatMayIDo } from '@atlasauth/pca-analyzer';

whatMayIDo(policy, verbShapes(actionSchema), { subject: { tier: 'gold' } }, { remaining: { usd: 40 } });
// [{ verb: 'stripe.refund', status: 'autonomous',
//    params: { amount: { kind: 'numeric', autonomous: [{ lo: 0, hi: 200, ... }], withApproval: [{ lo: 200, hi: 500, ... }] } },
//    policyDigest: '...', advisory: true }]
```

This is a **partial evaluation**: the policy is specialised to what is known (verb, resource, principal facts, time) and the parameters stay symbolic. The result is what an agent host needs to build its tool list and parameter constraints **before** the model plans, so the model never proposes an action that will be denied. It is advisory. The verifier stays authoritative, and the envelope carries the digest of the policy it was planned against.

`residual(policy, known)` returns the specialised policy itself, and it is exact: for every way of filling in the unknown parameters it decides what the original decides. An unknown that reaches a prohibition keeps the prohibition; partial evaluation never prunes a veto.

For a list endpoint, push authorization into the query instead of filtering rows afterwards:

```ts
import { residual, toFilter } from '@atlasauth/pca-analyzer';

const f = toFilter(residual(policy, { verb: 'stripe.refund' }, { resourceUnknown: true }), { columns: { 'action.resource': 'id', 'action.params.amount': 'amount' } });
// { ok: true, sql: "(id LIKE $1 ESCAPE '!' AND amount <= $2)", params: ['/acct/%', 500] }
```

The filter may only select a **subset** of what the evaluator allows. Anything it cannot express exactly (a regex resource, a field without a column, string ordering) makes `toFilter` return `{ ok: false, reason }`, and the caller falls back to checking rows one by one. It assumes the columns have the types the policy compares against and a byte-wise collation.

`toFilter` also returns the same filter as a UCAST tree (`ucast`, the expanded syntax of OPA's data-filtering API, with explicit not-null guards so a NULL column never satisfies a permit), for ORMs that take UCAST instead of SQL.

### Over HTTP

`POST /v1/pca/can` answers the same question for a registered grant. The body is signed by the grant's holder key (`holder_sig` over `atlas-pca/can/v1\0` and the canonical `{grant_ref, ts, verbs, params, known}`); an unknown grant and a bad signature are the same 404, only the named grant is ever read, and the route is rate-limited per source and per grant. A revoked, frozen, expired or not-yet-valid grant answers `denied` with the reason. The answer is advisory and carries the policy digest.

## What the agent never used

```ts
import { suggestNarrowing } from '@atlasauth/pca-analyzer';

const r = suggestNarrowing(policy, observedFromLedger, { decay: { nowSec, expiresInSecs: 30 * 86400 } });
r.proposal;       // a narrower grant, proven subsumed by the original
r.findings;       // unused predicates, unused verbs and caps that were never reached, ranked by blast radius and reversibility
r.accessRequests; // refused attempts, grouped, for a human to read
```

- **It only narrows.** The proposal is built as "the original clause AND more conditions" and then proven narrower with the analyzer. If that proof is not exact, there is no proposal.
- **Only the ledger counts.** Records marked `source: 'agent'` are counted in `rejected` and ignored.
- **Denials never loosen a grant.** A refused attempt becomes a signed access request (`signAccessRequest`). Nothing in the package turns one into authority.
- `decay` adds an `expires` caveat so permissions that are not used lapse when the grant is next minted. `taskBinding` ties a proposal to one goal.

## Would my tests notice a mistake

```ts
import { generateBoundaryTests, runPolicyTests, coverage, signPolicyTests } from '@atlasauth/pca-analyzer';

const examples = generateBoundaryTests(policy);       // one minimal allow per clause, a trigger per prohibition, the points around every threshold
// a person reads them and confirms; then:
const signed = signPolicyTests(examples, principalSecret, principalPublic);
runPolicyTests(policy, examples, { requireDigest: true }); // fails if the policy drifted, even if every example still passes
coverage(policy, traffic);                             // which clauses never decided, which thresholds were never probed, which mutations survive
```

`coverage` mutates the policy (widen a cap by one unit, flip `<=` to `<`, drop a prohibition) and reports the mutations your traffic cannot tell from the original, each with the action that would kill it. A mutation the analyzer proves equivalent to the policy is not a gap and is excluded from the score.

```sh
pca-policy-ci test policy.json tests.json --require-digest
pca-policy-ci coverage policy.json tests.json --min-clauses 1 --min-boundaries 1 --max-survivors 0
```

## Why was this denied, and what would fix it

```ts
import { minimalFlip } from '@atlasauth/pca-analyzer';

minimalFlip(policy, action, { holderAuthenticated: true, schema: verbShapes(actionSchema) });
// { current: 'deny', repairs: [{ repair: { kind: 'set_param', param: 'amount', from: 900, to: 500 }, cost: 2.44, decision: 'allow', action: { ... } }], repairExists: true }
```

The search proposes (wait for a time caveat, lower a parameter, pick another allowed value or resource, obtain a named fact, and with `allowSplit` split the action) and the real decision verifies. For an escalation it also names the cheapest repair that needs no human. Because a counterfactual teaches the asker about the policy, it is shown only to the authenticated holder, is rate-limited by a probe budget, and hides the values of `critical` parameters behind "a repair exists". Splitting is off by default and is offered only when no rate, budget or cap would be skirted by it.

## Does the policy match the schema

```ts
import { validatePolicyAgainstSchema } from '@atlasauth/pca-analyzer';

validatePolicyAgainstSchema(policy, actionSchema, { units: grantUnits });
// undeclared-verb, undeclared-param, type-mismatch, value-not-in-enum, out-of-range, redundant-bound,
// unreachable-predicate, unbounded-money, unit-missing, unit-mismatch
```

It accepts a signed action schema, a list of verb shapes or a list of action definitions. In CI, `pca-policy-ci policy.json --schema schema.json` adds the same findings under the rule `schema-mismatch`.

## A decision with a proof: forbid wins

A policy is a list of clauses: `permit`, `forbid` and `escalate`. Any matching forbid denies, whoever signed it and whatever order the clauses are in. A clause that cannot be decided counts as matched for a forbid and as not matched for a permit. `certify` returns the decision with a **certificate**: the value of every clause, the winning clause and the ones it shadowed.

```ts
import { certify, checkForbidCertificate, certificateConsistent } from '@atlasauth/pca';

const cert = certify(clauses, actionContext, { precedence: ['org', 'user'] });
checkForbidCertificate(cert, clauses, actionContext, { precedence: ['org', 'user'] }); // recomputes everything; a forged certificate fails
certificateConsistent(cert);                                                          // the table alone entails the decision: no evaluator needed
```

`precedence` ranks signers (an organisation's constitution before a user's grant). It only decides which forbid is **named**; it can never switch a forbid off. `certificateConsistent` is ported to the Python, Go and Ruby verifiers.

## Requiring these in the verifier

`authorize()` accepts `forbid: { clauses, precedence, requireCertificate }` and `requireLinkedTemplate: { registry }`. A matching forbid, a missing or non-recomputing certificate, or a grant that is not the instantiation of its linked template is refused before the PCActn's counter is spent, and a success carries the certificate.

## Templates that stay linked

A grant can say "template T at version D, filled with slots S" instead of carrying an unexplained copy of the policy.

```ts
import { createLink, signTemplate, resolveLink, verifyLinkedPolicy } from '@atlasauth/pca';

const ref = createLink(templateDef, { acct: 'a42', cap: 200, region: 'eu', verbs: ['mail.draft', 'mail.send'] });
// mintGrant({ ..., envelope: { predicates, caveats, template_ref: ref, ... } }): the grant signature covers the link
verifyLinkedPolicy(envelope, { templates: { [ref.version_digest]: signedTemplate }, trusted: [orgPublicKey] });
```

- A template is signed by your organisation and named by its digest. The verifier rebuilds the policy from (template, slots) and requires the grant to hold exactly that.
- A new template version applies to **new** grants. An existing link never changes underneath you.
- To tighten existing links, sign a **tighten overlay**: it can add `where` conditions and caveats and nothing else. A grant minted before the overlay no longer matches its link and must be re-minted.
- Slots are typed with closed domains. A slot value that would put a wildcard or a regex into a verb or a resource is refused.

## Limits

- The analysis enumerates a finite set of representative actions. It is exact for threshold, set-membership and prefix conditions; it reports `approximate` for regex resources, comparisons between two fields and the `like`, `matches`, `is_a` and `member_of` operators.
- Budgets that depend on history (the trust budget, a rate window already partly used) are not part of the static answer; `maxExposure` reports the structural bound.
- Stateful prohibitions that need history (`never_after`, `require_prior`) are listed as unmodelled; leaving them out can only raise a bound.
- None of this audits the verifier. It is a set of review tools for the policy you are about to sign.
