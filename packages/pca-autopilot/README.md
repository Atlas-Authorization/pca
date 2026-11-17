# @atlasauth/pca-autopilot

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Nobody wants to hand-write policy. Autopilot watches what an agent actually did and drafts the **tightest grant that covers it**, for a human to review and sign once.

**A proposal is never authority.** It becomes a grant only when a pinned reviewer signs an approval that commits to the exact proposal, the exact verification report and the exact list of sensitive actions they confirmed. Nothing learned from a log reaches enforcement any other way.

## Quickstart

```sh
# 1. read what the agent did (a receipt log, OpenTelemetry spans, or JSONL)
pca autopilot observe audit.jsonl

# 2. draft the least-privilege grant
pca autopilot propose autopilot.traces.json --margin 0.2

# 3. prove it: replay every observed action through the real verifier, list what else it permits
pca autopilot verify autopilot.proposal.json autopilot.traces.json [--existing current-policy.json]

# 4. a human reads the plain-language summary and signs once
pca autopilot review autopilot.proposal.json autopilot.report.json --reviewer-key @reviewer.key --yes \
    --holder <agent public key> --goal "triage the support inbox"

# later: widen by the minimum for denied-but-legitimate actions, or tighten what went unused
pca autopilot amend autopilot.proposal.json new.traces.json
pca autopilot amend autopilot.proposal.json new.traces.json --unused-days 30
```

JSONL input is one object per line: `{"at": 1800000000000, "verb": "gmail.draft", "resource": "/drafts/7", "params": {"recipients": 2}, "outcome": "allow", "tenant": "acme", "actor": "agent-1"}`.
Receipt logs (the proxy's audit log) carry no parameters, so amounts cannot be learned from them; the summary says so. Spans from `@atlasauth/pca-otel` carry the verb, resource and decision; add `pca.param.<name>`, `pca.tenant` and `pca.actor` attributes to carry the rest.

## End to end with the PCA proxy

```sh
# 1. watch the agent through the proxy (observe mode forwards everything and records what enforce mode would have refused);
#    audit.observedParams also records the numeric and enumerable parameters, so amounts can be learned
pca-proxy http --config pca-proxy.yaml --observe --audit ./pca.audit.jsonl      # audit.observedParams: { enabled: true, include: [amount] }

# 2. learn the tightest grant
pca autopilot observe ./pca.audit.jsonl --params ./pca.audit.jsonl.params.jsonl
pca autopilot propose autopilot.traces.json
pca autopilot verify  autopilot.proposal.json autopilot.traces.json

# 3. a human signs once; the grant file is minted for the agent's key
pca autopilot review autopilot.proposal.json autopilot.report.json --reviewer-key=@reviewer.key --yes \
    --holder <agent public key> --goal "triage the support inbox" --grant-out grant.json

# 4. enforce with it: in pca-proxy.yaml set  http: { mode: verify, grants: [grant.json] }  and run without --observe
```

`grant.json` is the encoded grant the proxy's `verify` mode loads; the agent signs its actions with the key you named as `--holder`. In the proxy's `sidecar` mode the proxy builds its grant from your rules (`limit`, `amountField`), so use the proposal there as the review of what to put in them. Without the parameters log, a receipt gives the verbs and resources but no amounts, and the proposal says so.

## What it produces

- **Verbs and resources.** One rule per verb and resource. The generalization ladder has two rungs: the exact resource, or, when at least `--min-distinct` (default 3) sibling resources were used, `parent/*` for that one parent. It never generalizes above the parent, never across tenants, and each generalization is explained. Because the matcher is a prefix, `parent/*` also admits anything deeper under the parent, and the excess report says so.
- **Numeric caps** from the largest value observed plus `--margin` (default 20%); a floor of 0 when every value was non-negative. Strings with few distinct values are pinned to them.
- **Time window and rate.** The grant expires after `--ttl-days` (default 30). The rate is the observed peak per window plus the margin.
- **Budget** from the forecast: enough that the budget never forces a human beyond the ones the risk tiers already force. Thresholds are never loosened.

## What stops a poisoned log

If an attacker acts while the agent is observed, the action is in the log. Autopilot:

- flags dangerous verbs, irreversible actions, secret-like resources, amount outliers and (when you pass `--trusted-actors`) unknown actors, and **leaves them out**. Each is listed under HELD BACK with an id; including one takes an explicit `--confirm <id>`, which the signed approval repeats;
- never includes an action the enforcer denied while observing; only `amend` can admit it, after repeated, unflagged attempts, and only through a new signed review;
- rejects records whose resource contains a wildcard or `re:` marker (it would be read as a pattern), `..` segments, control characters, non-finite numbers or prototype-pollution keys, and caps the number of records and rules (a flood fails closed);
- refuses a receipt log whose hash chain is broken;
- refuses to build across tenants; an action whose resource names another tenant is held back.

Flags only ever raise the bar. A heuristic that does not fire proves nothing, so the excess-authority report and the human signature are the control, not the heuristics.

## Library

```ts
import { ingestText, propose, verifyProposal, signApproval, issueGrant, summarize } from '@atlasauth/pca-autopilot';

const traces = ingestText(await readFile('audit.jsonl', 'utf8'));
const proposal = propose(traces, { margin: 0.2, now });
const report = await verifyProposal(proposal, traces, { existing: currentPolicy });
console.log(summarize(proposal, report));              // plain language + excess authority
const approval = signApproval(reviewerSecret, proposal, report, { at: now }); // refuses a failed report
const { grant } = issueGrant(proposal, report, approval, { principalSecret, holder, goal, principals: [reviewerPublic], now });
```

A reviewer can also approve with a user-verified passkey: sign `approvalChallenge(proposal, report, confirmed, expiresAt)` and pass the assertion as a `passkey` approval with the credential registered for that reviewer.

Everything is deterministic: pass `now` and the same traces give a byte-identical proposal and report.
