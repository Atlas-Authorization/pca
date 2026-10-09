import { delegate } from '../capability';
import { mintGrant } from '../envelope';
import { hashCanonical } from '../hash';
import { encodeKey, generateKeyPair } from '../keys';
import { commitPlan, conditionsDigest, type PlanNode } from '../merkle';
import { PCACTN_VERSION, signPCActn, type PCActn } from '../pcactn';
import { DEFAULT_RISK_POLICY } from '../risk';

export const NOW = Date.UTC(2026, 9, 6, 12, 0, 0);
/** The audience every test PCActn is issued for (wire v2 freshness binding). */
export const AUD = 'rs-test';

export function setup(opts: { extraPlan?: boolean; agentBinding?: Record<string, unknown>; taskCaveats?: Record<string, unknown>[] } = {}) {
  const principal = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: pPub,
    goal: 'tidy sessions',
    envelope: {
      predicates: [{ verb: 'list_sessions', resource: 'session:*' }, { verb: 'rotate_recovery_keys', resource: 'account:me' }],
      caveats: [{ type: 'expires', at: NOW + 3_600_000 }, { type: 'delegation_depth', max: 2 }],
      agent_binding: (opts.agentBinding ?? {}) as never,
      risk_policy: DEFAULT_RISK_POLICY,
    },
  });
  const agent = generateKeyPair();
  const aPub = encodeKey(agent.publicKey);
  const task = delegate(grant, aPub, [{ type: 'expires', at: NOW + 600_000 }, ...((opts.taskCaveats ?? []) as never[])], principal.secretKey);
  const chain = [grant, task];
  const params = { scope: 'all' };
  const plan: PlanNode[] = [
    { id: 'n1', verb: 'list_sessions', resource: 'session:*', params_digest: hashCanonical({}), reversibility_class: 'reversible' },
    { id: 'n2', verb: 'rotate_recovery_keys', resource: 'account:me', params_digest: hashCanonical(params), reversibility_class: 'irreversible' },
  ];
  const committed = commitPlan(plan);
  const mk = (n: PlanNode, o: { counter?: number; tweak?: (a: PCActn['action']) => void; nonce?: string; attEpoch?: number; beaconRef?: string; extra?: Record<string, unknown> } = {}): PCActn => {
    const action = { verb: n.verb, resource: n.resource, params_digest: n.params_digest!, reversibility_class: n.reversibility_class! };
    o.tweak?.(action);
    return signPCActn(
      {
        ver: PCACTN_VERSION,
        action,
        grant_ref: grant.id,
        cap_chain: chain,
        plan: { root: committed.root, inclusion_proof: committed.proofFor(n.id), node_id: n.id, conditions_digest: conditionsDigest(n.pre, n.post) },
        attestation: { quote_digest: o.nonce ?? '', epoch: o.attEpoch ?? 0, model_id: 'm', measurement: '', operator: 'o' },
        provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
        freshness: { beacon_ref: o.beaconRef ?? '', epoch: 0, accumulator_witness: '' },
        counter: o.counter ?? 1,
        risk_claim: { r: 0, inputs: {} },
        aud: AUD,
        iat: NOW,
        exp: NOW + 600_000,
        ...(o.extra as object),
      } as never,
      agent.secretKey,
    );
  };
  // taint is RS-supplied: a missing value fails closed to the worst case (the agent's claim is never used).
  const lowRisk = { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 };
  return { grant, plan, mk, lowRisk, params, aPub };
}
