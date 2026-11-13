---
title: Design partner kit
order: 41
---

# PCA design partner kit

This page is for teams considering a design partnership on Proof-Carrying Authority (PCA): what you get, what we ask of you, how the first 90 days run, how we will both judge whether it worked, and the ways PCA can be integrated into your stack.

## Who this is for

PCA is a good fit if you run, or are about to run, AI agents that take **consequential actions through tools or APIs**: moving money, changing records, sending messages, deploying code, touching customer data. The question PCA answers for each such call is not only "who is calling" (authentication) or "what may they call" (authorization) but "is this specific action a faithful execution of what the principal actually authorized?" We call that execution authentication, or authF.

Concretely, every tool call carries a signed proof that the action is part of a plan the agent committed to in advance, is within a grant the principal signed (narrowed, never widened, through any sub-agents), is addressed to this server, is fresh, and has not been used before. Riskier actions can require a guardian co-signature or a human step-up. The resource server checks the proof offline.

The ideal partner has:

- at least one agent workflow in production or close to it, with a handful of tools whose misuse would matter;
- an engineer who owns that workflow and can spend a few hours a week on the partnership;
- a security or platform stakeholder who can say what "safe enough" means for the workflow.

## What you get

- **Direct engineering support.** A named engineer on our side and a shared channel. We pair with you on the integration, review your grant and caveat design, and review your integration code before it enforces anything.
- **Early access** to the hosted PCA verification service for your instance (it is off by default and enabled per instance), and to new capabilities before general release.
- **All the building blocks**, already published: the TypeScript libraries, native verifiers in nine more languages (Go, Python, Rust, Java, Kotlin, .NET, PHP, Ruby, Swift), framework and gateway adapters, and the shared conformance suite.
- **A threat-model session** for your workflow: which actions need plan binding, which need step-up, what your trust budget should be, and what PCA does not cover for you.
- **Priority on your issues.** Defects and integration blockers you report are triaged ahead of the general queue.
- **Influence on the standard.** PCA is specified in an individual Internet-Draft. Partner feedback shapes the next revisions, and partners who contribute substantively are acknowledged in the draft.
- **A written results report** at day 90 with your measurements, suitable for sharing internally.

Commercial terms, if any, are agreed separately and are not part of this kit.

## What we ask of you

- **A real workflow.** One agent and one to three tools to start, chosen together at kickoff.
- **A technical owner** who can spend roughly four hours a week, more during weeks you integrate.
- **A 30-minute sync every two weeks**, and a 60-minute review at days 30, 60 and 90.
- **Measurements.** The metrics in [Success metrics](#success-metrics), collected from your environment. We provide the queries or log fields.
- **Candid feedback**, including on what was confusing, slow or missing. A short written retrospective at day 90.
- **Private disclosure of security issues.** If you find a vulnerability, report it to us privately before publishing.
- **Optional:** permission to describe the partnership publicly, or a short case study, once you are satisfied with the results.

## Ground rules for the pilot

PCA 0.5 is hardened, awaiting independent audit, and **has not had an independent security audit**. During the partnership:

- Start in **shadow mode**: verify and log every decision, but do not block on it, until the false-deny rate is understood.
- Do not make PCA the **only** control over high-value or irreversible actions. Keep your existing authorization in place; PCA is added in front of it.
- Use a **shared, durable replay store** (PostgreSQL or Redis) as soon as any verifier runs in more than one process. An in-memory store is for development only.
- Keep your existing OAuth or API-key authentication for clients and users. PCA is added on top; it does not replace it.

## Integration options

You can mix these. Most partners start with one and add a second for defence in depth.

| Option | Where PCA runs | Code changes | Best when |
|---|---|---|---|
| MCP | Inside your MCP client (proof per tool call) and your MCP server | Small: wrap tool handlers | Your agents reach tools over the Model Context Protocol |
| Gateway | At your API gateway or service mesh | None in the services behind it | You want one choke point in front of many services |
| Framework adapters | In your agent framework and your API server | Small: wrap tools, add middleware | You own both the agent and the API |
| Hosted verifier | In the Atlas PCA service; your server calls it or trusts its receipts | Small: register grants and plans, submit actions | You want counters, budgets, step-ups and the ledger operated for you |

### MCP

- **Client side:** a wrapper around each MCP tool handler builds a signed proof for the call (failing fast if the agent's own grant does not allow it) and forwards it with the request.
- **Server side:** an MCP resource-server component serves OAuth Protected Resource Metadata (RFC 9728), checks resource binding (RFC 8707) and issuer validation (RFC 9207), and issues step-up challenges (RFC 9470). The proof's signed audience is the resource binding, so a proof minted for one MCP server is useless at another.
- Python agents using FastMCP have a dedicated adapter.

### Gateway

- Adapters for **Envoy `ext_authz`** (HTTP and gRPC, including Istio `AuthorizationPolicy` with `action: CUSTOM`), **Cloudflare Workers** and **AWS API Gateway** Lambda authorizers.
- A route map turns method and path into the capability a request needs. By default the proof is bound to the exact method, path, query string and body hash, so it cannot be replayed against a different request.
- The gateway runs the stateless core check. For single use, configure its replay guard with a shared store. Budgets, revocation and plan-root approval are enforced by the resource-server guard behind it, which also remains the backstop if the gateway is bypassed.

### Framework adapters

- **API servers:** middleware for Express, Fastify, Hono and Next.js (TypeScript), and resource-server guards in the Python, Go, Rust, Java, .NET, Ruby and PHP verifiers.
- **Agent frameworks (TypeScript):** LangChain, LlamaIndex, Mastra, the OpenAI Agents SDK, the Vercel AI SDK, and Anthropic and OpenAI tool calling.
- **Agent frameworks (Python):** CrewAI, LangGraph, Pydantic AI, Google ADK, Haystack, FastMCP and Microsoft Agent Framework.
- Every guard is default-deny: a check you require that is not enforced denies the call.

### Hosted verifier

The Atlas PCA service registers grants and plans, verifies each action, and in the same database transaction consumes its counter, debits the trust budget and appends it to the principal's transparency ledger, then returns a receipt you can check against the ledger offline. It also runs step-up approvals, revocation, an instance-wide kill switch, and ledger proofs. It is gated off by default and enabled per instance for partners.

### Try it first

The end-to-end demo needs no account and no Docker. It runs a full story (an allowed action, an off-plan denial, a threshold step-up, a replay, three tampering attempts, budget exhaustion, a sub-agent that cannot exceed its parent, and an offline-verified receipt) and exits non-zero if any outcome differs from what the protocol specifies:

```sh
npm create pca-app@latest my-demo && cd my-demo && npm install && npm start
```

## The first 90 days

### Days 1 to 30: understand and shadow

| Week | Activity | Output |
|---|---|---|
| 1 | Kickoff. Pick the workflow, the agent and one to three tools. Threat-model session. | Written scope and the list of actions in play |
| 1 to 2 | Map each tool call to a verb and resource. Design the grant: caveats (spend limits, expiry, rate, reversibility), plan shape, which actions need step-up. Run the demo. | Grant and plan design, reviewed by us |
| 2 to 3 | Integrate with the option you chose, in **shadow mode**: every call is verified and the verdict is logged, nothing is blocked. | Proofs flowing on real traffic |
| 4 | Review the first two weeks of shadow verdicts together. Fix every false deny. | Day-30 review |

Exit criteria: every in-scope tool call carries a proof; shadow verdicts are logged with their per-check results; the false-deny rate is known.

### Days 31 to 60: enforce on a narrow path

| Week | Activity | Output |
|---|---|---|
| 5 | Turn on enforcement for low-risk, reversible actions. Move the replay store to its production configuration. | First enforced path |
| 6 | Add a human step-up for one high-risk action. Test the approval experience with the people who will approve. | Step-up in use |
| 7 | Revocation and kill-switch drill: revoke a capability and freeze the instance in a test environment; measure time to effect. | Drill report |
| 8 | Prompt-injection exercise: feed the agent hostile content designed to make it call tools outside its plan. Record what PCA stopped and what it did not. | Day-60 review with exercise results |

Exit criteria: enforcement is on for the narrow path without unexplained denials; step-up, revocation and freeze have each been exercised; the injection exercise is written up.

### Days 61 to 90: expand and decide

| Week | Activity | Output |
|---|---|---|
| 9 to 10 | Extend to more tools or a second agent. Add delegation to sub-agents if your workflow uses them. | Wider coverage |
| 10 to 11 | Optionally add an extension your risk profile calls for: guardian co-signature, the transparency ledger with receipts, attestation of the agent runtime, or post-quantum hybrid signatures. | Extension in use, or a reasoned decision not to |
| 12 | Final measurements, retrospective, and a decision: expand, hold, or stop. | Day-90 results report |

## Success metrics

Targets are agreed at kickoff for your workflow. The measurements below are what we will collect; the suggested targets are starting points.

| Metric | How it is measured | Suggested target |
|---|---|---|
| Time to first verified call | Kickoff to the first real tool call carrying a proof that verifies | Under 2 weeks |
| Coverage | Share of in-scope tool calls that carry a proof | 100 % of in-scope calls by day 30 |
| False-deny rate | Legitimate calls denied, from shadow and enforced logs, after triage | Under 0.1 % before enforcement is widened |
| Out-of-plan calls stopped | In the injection exercise, share of attempted out-of-plan calls that were denied | 100 % |
| In-plan misuse | In the same exercise, harmful calls that stayed inside the plan and policy and were allowed | Recorded and reviewed; these show where grants or plans need tightening |
| Replays rejected | Deliberate replays in testing that were denied | 100 % |
| Added latency | Verification time per call at p50 and p95, in your environment | Agreed at kickoff from your latency budget |
| Step-up experience | Share of calls needing step-up, and median time to approval | Agreed at kickoff |
| Revocation time | Time from revoking a capability to the first denied call | Agreed at kickoff |
| Integration effort | Engineer-days spent, by phase | Tracked, no target |
| Developer experience | Short survey of the engineers involved at day 90 | Tracked, no target |

For orientation on latency: in our own benchmark, verifying a one-hop Ed25519 proof in-process with the TypeScript library took about 8 ms at the median on one server core, and a full hosted admission (verification plus the database transaction and ledger append) took about 260 ms at the median. Your numbers will depend on your language, chain length, signature suite and network, which is why the latency target is set from your own measurements.

## After day 90

If the partnership continues, we agree the next workflows, the extensions to adopt, and whether your deployment should be in scope for an independent security audit. Results you allowed us to share feed into the next revision of the specification.
