/**
 * THE AGENT SIDE.
 *
 * Proof-Carrying Authority (PCA) lets an AI agent prove, on every tool call, that the human
 * behind it actually authorized that exact action — within exact limits. You never hand the agent
 * a bearer token it can spend however it likes; instead each action carries its own proof.
 *
 * This file builds such an agent with the one-line `agent({...})` facade from `@atlasauth/pca`.
 * That one call compiles plain-English intent ("may refund, up to $500 each") into the real
 * cryptographic primitives (a signed grant + policy + a trust budget) so you never touch them.
 *
 * Nothing here authorizes anything. `.act()` only PRODUCES a proof-carrying action; the resource
 * server's verifier (see `server.ts`) is what allows or denies it.
 */

import { agent, generateKeyPair, type Capability, type KeyPair, type ProvenanceBundle } from '@atlasauth/pca';

/** The resource server / Atlas instance id these actions are for. The proof is bound to it. */
export const AUDIENCE = 'ins_quickstart';

/** Everything the agent needs to send the server for one action. */
export interface RefundRequest {
  /** The wire-encoded proof-carrying action. POST this to the server. */
  pcactn: string;
  /** The charge being refunded: with the verb, it names the resource the proof is for. */
  charge: string;
  /** The plaintext params (the proof commits only their hash, so the server needs these to judge). */
  params: Record<string, unknown>;
  /** The plan's Merkle root — the principal (human) authorizes this with the server up front. */
  planRoot: string;
  /** Where the action's choice and arguments came from (provenance by default): send it as `pca_provenance`. */
  provenance?: ProvenanceBundle;
}

export interface QuickstartAgent {
  /** The signed Root Intent Grant. The server looks actions up against this. */
  grant: Capability;
  /** Build a proof-carrying `stripe.refund` action. `counter` must strictly increase per agent. */
  refund(amount: number, charge: string, counter: number): RefundRequest;
}

/** Create the quickstart agent. Pass your own principal key, or let one be generated for the demo. */
export function createQuickstartAgent(principal: KeyPair = generateKeyPair()): QuickstartAgent {
  // ONE call: compiles intent -> predicates + caveats + a trust budget + a signed grant.
  const a = agent({
    principal, // the human's key; it roots + signs the grant (the longest-lived key)
    goal: 'reconcile October refunds',
    permissions: { stripe: ['refund'] }, // the agent may issue refunds...
    limits: { refund: '$500/day' }, // ...but never more than $500 per refund.
    aud: AUDIENCE,
  });
  // The harness (never the model) records what the human asked. The server re-derives every argument's origin from this
  // signed record: an amount or charge that came from a web page or a tool result instead would be held for the human.
  a.provenance?.principal('Reconcile October refunds: refund ch_happy $42, ch_second $100 and ch_whale $5000.');

  return {
    grant: a.grant,
    refund(amount, charge, counter) {
      // `.act()` hands back a proof-carrying action for ONE tool call. It does not authorize.
      const params = { amount, currency: 'usd' };
      const { pcactn, encoded, provenance } = a.act('stripe.refund', `charge:${charge}`, params, { counter });
      return { pcactn: encoded, charge, params, planRoot: pcactn.plan.root, ...(provenance ? { provenance } : {}) };
    },
  };
}
