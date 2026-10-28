---
title: Start here
order: 1
---

# Start here

Pick the line that sounds like you. Each one is a path from nothing to a working, tested result.

| I want to... | Do this | Time |
|---|---|---|
| See it work before reading anything | `npm create pca-app@latest my-demo`, then `npm install && npm start` | 1 min |
| Protect an MCP server | [Golden path 1](./guides/golden-paths.md#1-protect-an-mcp-server) | 10 min |
| Guard an API route in my framework | [Add PCA to your framework](./guides/framework-recipes.md) (Express, FastAPI, Spring, Rails, Laravel, ASP.NET, Gin, axum, Vapor, Ktor) | 15 min |
| Let an agent spend money safely | [Golden path 2](./guides/golden-paths.md#2-let-an-agent-pay-under-200-a-day-with-approval) | 10 min |
| Describe my own actions | [Golden path 3](./guides/golden-paths.md#3-define-my-own-actions) | 15 min |
| Turn a plain-English goal into enforced policy | [Golden path 4](./guides/golden-paths.md#4-goal-to-policy-to-review-to-enforcement) | 15 min |
| Give a sub-agent less authority than its parent | [Golden path 5](./guides/golden-paths.md#5-delegate-to-a-sub-agent) | 5 min |
| Call another agent over A2A | [Golden path 6](./guides/golden-paths.md#6-an-a2a-hop) | 15 min |
| Understand why it is not "API keys with scopes" | [The comparison](./concepts/comparison.md) and the table on the [overview](./README.md) | 10 min |
| Know what to rely on, and what not to | [Maturity tiers](./maturity.md) and the [trust model](./security/trust-model.md) | 10 min |
| Understand a refusal | [Refusal reasons](./reference/refusals.md) | 2 min |
| Use a language other than TypeScript | [Language parity](./reference/language-parity.md), then the framework recipe | 15 min |

## By role

**Application developer, building an agent.** You need the agent side: `agent({ principal, goal, permissions, limits })`
and `act()`. Start with the [five-minute quickstart](./guides/five-minute-quickstart.md), then delegation
(golden path 5).

**Service owner, protecting an API or tool server.** You need the server side: one guard, four inputs. Start with
[Add PCA to your framework](./guides/framework-recipes.md). Run `pca-doctor` against your deployment before you rely on it.

**Payments and risk.** [Golden path 2](./guides/golden-paths.md#2-let-an-agent-pay-under-200-a-day-with-approval), then
[Agent payments, risk-priced approvals and wallet permissions](./guides/agent-payments-and-approvals.md).

**Platform and security.** [Threat model](./security/threat-model.md), [security contract](./security/security-contract.md),
[trust model](./security/trust-model.md), the [policy analysis guide](./guides/policy-analysis.md) and the
[operational plane](./guides/operational-plane.md).

**Standards and protocol people.** [PCA Core](./core.md), [wire formats](./reference/wire-formats.md), the
[conformance suite](./guides/verify-in-your-language.md) and the [MCP gateway profile](./guides/mcp-gateway-profile.md).

## The three ideas you need

1. **The agent proves each action.** It does not hold a bearer token it can spend freely. Every call carries a proof
   that this exact action, with these parameters, is inside what the person signed.
2. **The server decides.** It checks the proof against a grant from its own store, for the operation its route will
   execute. A valid proof for another action, another amount or another server is refused.
3. **Authority only narrows.** A sub-agent, a policy overlay or a model's output can add restrictions and never remove
   them. Anything that cannot be decided safely is refused or sent to a person.

Everything else is detail you add when you need it.
