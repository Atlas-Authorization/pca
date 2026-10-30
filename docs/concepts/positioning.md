---
title: How PCA relates to other agent-authorization offerings
order: 10
---

# How PCA relates to other agent-authorization offerings

This page answers, one claim at a time, the statements you will hear when you compare PCA with identity products, authorization servers, guardrail vendors and agent protocols. It describes what each offering documents about itself and what PCA does at the same point. It does not rank them, and it says where PCA does not do something. Everything about another product comes from that product's own documentation or a public specification, linked below; vendor pages are marketing as much as documentation, so check them against your version before relying on a detail.

The short version: most of these offerings decide **at issue time or at the session level**, and PCA decides **at each action, with its arguments, with a signature the resource server checks itself**. They compose. PCA can ride inside the credential most of them already issue.

## "Conditional Access applies to agents like users"

Microsoft Entra Agent ID models an agent as a special service principal; a blueprint holds the credentials and creates agent identities, Conditional Access can be attached at blueprint level so current and future instances inherit it, and disabling the blueprint blocks all of its identities ([Agent identities](https://learn.microsoft.com/entra/agent-id/agent-identities), [best practices](https://learn.microsoft.com/entra/agent-id/best-practices-agent-id)). AWS AgentCore Identity gives each agent a directory identity and restricts its token vault to the agent and user that obtained a credential ([terminology](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-terminology.html)). Keycard describes tokens bound to agent, user, runtime and task with per-task and per-tool-call policy ([Keycard docs](https://docs.keycard.ai/guides/why-keycard/)).

These evaluate when a token is issued or a session starts. PCA evaluates when the action happens: the proof names the verb, the resource and a digest of the arguments, so a resource server can check one action offline. PCA has the same two ideas you will recognize from blueprints, expressed as signed records: an operator-signed **agent blueprint** carries a tighten-only ceiling for every instance and a monotone epoch, and one signed record disables every instance, including ones the verifier has never seen. The two compose: use your identity provider for who the agent is, and PCA for what this call may do.

What PCA does not do: it does not run your directory, issue your sessions or replace your conditional-access signals.

## "We do per-call authorization" (hosted decision services)

Arcade documents an OAuth challenge when a tool is first needed and a per-call check of agent, user and action ([Arcade guide](https://blog.arcade.dev/agent-authorization-langgraph-guide)); Composio documents checks against OAuth scopes, permission rules and allowlists ([Composio authentication](https://docs.composio.dev/docs/authentication), [protection](https://composio.dev/protection)); Aembit describes a gateway that swaps the agent token for server credentials without exposing them and applies conditions such as device posture before issuing a credential ([Aembit](https://docs.aembit.io/get-started/how-aembit-works/)). Auth0 Token Vault stores third-party tokens and exchanges an Auth0 token for the provider token ([Auth0 Token Vault](https://auth0.com/ai/docs/intro/token-vault)).

In those designs the decision is made by a hosted service and the resource server trusts the answer. In PCA the decision is a signed proof the resource server verifies itself. PCA's connection vault (`@atlasauth/pca-connect`) is the comparable component: it releases a provider token only against a verified proof, once per action. Today the released token is an ordinary bearer token for its scopes until it expires, so the strongest use is a short lifetime and narrow scopes.

## "MCP authorization is OAuth, so it is enough for agents" and "A2A has built-in auth"

MCP authorization is OAuth 2.1 with protected resource metadata, resource indicators, issuer validation and a runtime `insufficient_scope` step-up ([MCP authorization, draft](https://modelcontextprotocol.io/specification/draft/basic/authorization)). The specification leaves room for the required scopes to be "determined dynamically based on the specific request arguments and context", and the scope is the unit it standardizes.

A2A authenticates the caller, gates an extended Agent Card behind that authentication and lets an agent park a task in `TASK_STATE_AUTH_REQUIRED`; it states that this state by itself authorizes nothing and leaves the credential's meaning to the agent, the issuer or an extension ([A2A specification](https://a2a-protocol.org/latest/specification/), section 7.6).

PCA fills those two gaps without changing either protocol. For MCP, a resource server can add an optional `pca_need` parameter to the `insufficient_scope` challenge: a stock client ignores it and steps up by scope as before, and a PCA-aware client turns it into an approve-or-amend flow for the exact action. The MCP authorization conformance matrix in the PCA packages records, per specification revision, which requirement a resource server and a client step-up meet and runs a check for each. For A2A, PCA is declared as an extension on the Agent Card; AUTH_REQUIRED carries a typed need, the task resumes only on a proof for exactly that need, and every hop of a delegation verifies its own proof.

## "Our authorization server already issues agent tokens"

Several providers present themselves as OAuth authorization servers for MCP and agents: Stytch Connected Apps and WorkOS AuthKit say so on their product pages ([Stytch](https://stytch.com/docs/get-started/guides/ai-agents-and-apps), [WorkOS](https://workos.com/mcp)), and Descope documents inbound apps with user consent and revocation ([Descope](https://docs.descope.com/agentic-identity-hub)). Keep them. PCA defines one authorization-details type, `pca_grant` (RFC 9396), so an authorization server that supports custom detail types can carry a PCA grant by digest. The resource server still requires a per-action proof, so the token alone is never sufficient. Support for custom RFC 9396 types differs by provider: Auth0 and Atlas document it; for Entra ID, WorkOS, Stytch and Descope the pages read on 2026-10-26 do not show it (details and sources in the guide), so confirm with the provider before depending on it. See [Carry a PCA grant in your OAuth server](../guides/pca-grant-oauth.md).

## "Transaction approval with CIBA and RAR"

Auth0 asynchronous authorization supports CIBA with an optional RAR `authorization_details` shown in the push notification ([Auth0 docs](https://auth0.com/ai/docs/intro/asynchronous-authorization)); the CIBA binding message is advisory text. PSD2 dynamic linking requires an authentication code specific to the amount and payee, and the Secure Payment Confirmation specification has the user agent display the payment data and sign it ([PSD2 RTS Article 5](https://www.legislation.gov.uk/eur/2018/389/article/5), [Secure Payment Confirmation](https://www.w3.org/TR/secure-payment-confirmation/)).

PCA's approval signs the digest of the exact action, and the CIBA integration carries a sanitized binding message. PCA does not yet commit the text the person saw: the signature binds the action, not the screen. A display commitment is on the roadmap and is not part of this release.

## "Network-level spend limits"

Card-network and issuer controls bound amount and merchant. PCA's payment mandate adds purpose, the committed plan, delegation limits and cumulative caps across calls, and it composes with those controls; it does not replace the issuer's own limits.

## "98% prompt-injection detection"

Detection products report how often they recognize hostile text. PCA makes no detection claim. A grant and a per-action proof bound what an agent can do whether or not the model was fooled, so an injected instruction still has to fit inside the grant. The two answer different questions and work together: detection reduces how often the agent is steered, bounds limit the damage when it is.

## "A zero-code gateway with trust ceilings"

Some vendors offer a zero-code gateway with trust ceilings in front of an MCP server (Permit.io is one; see its own documentation for what it enforces). PCA's gateway package (`@atlasauth/pca-gateway`) does the same: it sits in front of an existing server and checks a proof for the audience and the capability the route needs, with no application change, and the check works offline.

## What to take from this

If you already have an identity provider and an authorization server, you keep them. PCA adds the argument-level proof and the signed fleet controls, and gives them a standard place to travel: an authorization-details type for OAuth, an optional challenge parameter for MCP and an extension for A2A.
