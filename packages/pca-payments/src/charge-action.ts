import {
  type BondedClaim,
  type Capability,
  type CapabilityChain,
  type OpenOptimisticOpts,
  type PCActn,
  type PlanNode,
  buildPCActn,
  openOptimistic,
  paramsDigest,
} from '@atlasauth/pca';
import { CHARGE_REVERSIBILITY_CLASS, CHARGE_VERB, type Charge } from './authorize';
import type { PaymentMandate } from './mandate';

/**
 * Turn a charge into a proof-carrying action anchorable in the transparency ledger (spec §2.6).
 *
 * A charge is a single-node committed plan; the PCActn opens that plan node. It carries the recomputable
 * risk claim r = amount/X so the ledger entry records the exact autonomous-spend risk. The reversibility
 * class is `reversible` so the optimistic bond (dispute/refund, §2.5) may be opened against it.
 */

const clamp01 = (x: number): number => (x < 0 ? 0 : x > 1 ? 1 : x);

/** The charge params committed in both the plan node and the PCActn action (they must reconcile). */
export function chargeParams(mandate: PaymentMandate, charge: Charge): Record<string, unknown> {
  return {
    amount: charge.amount,
    currency: charge.currency ?? mandate.terms.currency,
    ...(charge.category !== undefined ? { category: charge.category } : {}),
  };
}

/**
 * The committed plan node for a charge. `params_digest` is pinned to the charge params so the committed
 * leaf reconciles with the PCActn action's `params_digest` (otherwise plan-inclusion fails).
 */
export function chargePlanNode(mandate: PaymentMandate, charge: Charge, id: string): PlanNode {
  return {
    id,
    verb: CHARGE_VERB,
    resource: `merchant:${charge.merchant}`,
    reversibility_class: CHARGE_REVERSIBILITY_CLASS,
    params_digest: paramsDigest(chargeParams(mandate, charge)),
  };
}

export interface ChargePCActnOpts {
  /** The capability chain rooted at the mandate grant (default `[mandate.grant]`). */
  chain?: CapabilityChain;
  /** Ed25519 secret of the leaf holder (the agent) — signs the PCActn. */
  signerSecret: Uint8Array;
  /** Audience: the resource-server / Atlas instance id this action is for. */
  aud: string;
  /** Monotonic per-action counter. */
  counter: number;
  /** Plan-node id (default `charge:<merchant>:<counter>`). */
  nodeId?: string;
  /** `iat` (epoch ms); default `Date.now()`. */
  now?: number;
}

/** Build a signed PCActn for a charge. Returns `{ pcactn, node }`; append `pcactn` to a `TransparencyLedger`. */
export function chargeToPCActn(
  mandate: PaymentMandate,
  charge: Charge,
  opts: ChargePCActnOpts,
): { pcactn: PCActn; node: PlanNode } {
  const nodeId = opts.nodeId ?? `charge:${charge.merchant}:${opts.counter}`;
  const node = chargePlanNode(mandate, charge, nodeId);
  const X = mandate.terms.perTransactionCap;
  const amount = typeof charge.amount === 'number' && Number.isFinite(charge.amount) ? charge.amount : X;
  const r = clamp01(X > 0 ? amount / X : 1);
  const params = chargeParams(mandate, charge);
  const chain: CapabilityChain = opts.chain ?? [mandate.grant];
  const pcactn = buildPCActn({
    grant: chain[0] as Capability,
    chain,
    plan: [node],
    nodeId,
    params,
    counter: opts.counter,
    signerSecret: opts.signerSecret,
    aud: opts.aud,
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    riskClaim: { r, inputs: { ...params, blastRadius: r } },
  });
  return { pcactn, node };
}

/**
 * Open the optimistic bonded claim for a charge (spec §2.5): the agent acts immediately on a signed,
 * bonded claim of compliance; a watchtower/human can file a fraud proof within the challenge window to
 * slash the bond and roll the charge back. This is the dispute/refund window, cryptographically
 * adjudicated. Thin wrapper over the PCA `openOptimistic`; REFUSES an irreversible charge.
 */
export function openChargeBond(pcactn: PCActn, opts: OpenOptimisticOpts, signerSecret: Uint8Array): BondedClaim {
  return openOptimistic(pcactn, opts, signerSecret);
}
