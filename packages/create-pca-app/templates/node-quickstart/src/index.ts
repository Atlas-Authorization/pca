/**
 * Proof-Carrying Authority — the whole authF loop in one file.
 *
 * "authF" = verify a proof-carrying ACTION, not a bearer token. An agent carries a signed capability
 * chain and, per action, a signed `PCActn` that commits to exactly what it is about to do. The verifier
 * checks it OFFLINE — no network, no shared secret, no call back to an auth server — against the grant
 * the verifier itself holds, and decides whether the action is inside that grant. This file:
 *
 *   1. generates a principal (human) key + an agent (holder) key
 *   2. mints a root capability with a simple policy (a verb/resource predicate + caveats)
 *   3. has the agent build + sign a PCActn for an allowed action
 *   4. verifies it with the full server verifier            -> verdict ALLOW
 *   5. tampers with the signed action and verifies again    -> verdict DENY
 *   6. has a compromised agent sign an action OUTSIDE its grant (github.delete_repo) -> verdict DENY
 *   7. presents a forged root                               -> verdict DENY
 *
 * Run it:  npm install && npm start
 */

import {
  DEFAULT_REQUIRED_CHECKS,
  agent,
  buildPCActn,
  decodePCActn,
  encodeKey,
  generateKeyPair,
  merkleRoot,
  mintRoot,
  mlDsa65Keygen,
  planNodeLeaf,
  readEnvelope,
  verifyPCActn,
  type Capability,
  type PCActn,
  type PcaVerdict,
  type PlanNode,
} from '@atlasauth/pca';

// The resource server / Atlas instance this agent is acting against. The PCActn is bound to it, so a
// proof minted for one audience cannot be replayed at another.
const AUDIENCE = 'ins_quickstart';

/**
 * What a resource server does with an inbound action: the AUTHORIZATION decision, made by the full server
 * verifier (`verifyPCActn`), never by the structural core alone. It is given:
 *   - the grant the server itself holds (never the one the artifact presents as its own root),
 *   - this server's audience id, accepted signature suites and clock,
 *   - the plaintext params (checked against the signed commitment and the grant's limits),
 *   - the plan roots the principal authorized, a revocation check and the holder's trust budget,
 * and `require`s the default-deny profile, so a check that is merely "not enforced" denies.
 */
async function serverVerdict(grant: Capability, p: PCActn, params: Record<string, unknown>, authorizedPlans: ReadonlySet<string>): Promise<PcaVerdict> {
  const now = Date.now();
  // The one-node plan, rebuilt from the SIGNED action (its Merkle root is bound inside the PCActn).
  const node: PlanNode = {
    id: p.plan.node_id,
    verb: p.action.verb,
    resource: p.action.resource,
    params_digest: p.action.params_digest,
    reversibility_class: p.action.reversibility_class,
  };
  const plan = [node];
  const policy = readEnvelope(grant)?.risk_policy;
  const bMax = policy?.bMax ?? 0;
  // The server prices a money-moving action itself, from the amount it verified: $42 under a $500 cap is 42/500 of the
  // blast radius. Risk inputs the server does not supply are priced at the worst case, which (the refund being
  // irreversible) would turn even this in-scope refund into a human step-up.
  const amount = params['amount'];
  const risk = typeof amount === 'number' && policy !== undefined && policy.kappa > 0 ? { blastRadius: Math.min(1, Math.max(0, amount / policy.kappa)) } : undefined;
  return verifyPCActn(p, {
    grant,
    audience: AUDIENCE,
    allowedSuites: ['ed25519'],
    now,
    hooks: { revocation: () => ({ enforced: true, ok: true }) }, // plug your revocation list in here
    context: {
      params,
      ...(risk !== undefined ? { risk } : {}),
      plan,
      planAuthorized: merkleRoot(plan.map(planNodeLeaf)) === p.plan.root && authorizedPlans.has(p.plan.root),
      budget: { B: bMax, tau: now, asOf: now },
    },
    require: [...DEFAULT_REQUIRED_CHECKS],
  });
}

async function main(): Promise<void> {
  // 1. Keys. The PRINCIPAL (the human) roots + signs the grant and is the longest-lived key in the
  //    system. The HOLDER (the agent) signs each individual action; its secret never needs to leave
  //    the client. `agent()` will generate a holder for you, but we pass one to make the two roles
  //    explicit.
  const principal = generateKeyPair();
  const holder = generateKeyPair();

  // 2. Mint a root capability with a simple policy. The facade compiles these human-level inputs into
  //    the real primitives: a verb/resource PREDICATE (stripe.refund on any resource, amount <= $500)
  //    plus CAVEATS (a reversibility ceiling and a one-day expiry window), then mints a signed Root
  //    Intent Grant. Nothing here authorises anything — it only produces well-formed, signed proofs.
  const a = agent({
    principal,
    holder,
    goal: 'reconcile October refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUDIENCE,
  });

  console.log('Minted grant:', a.grant.id);
  console.log('  predicate(s):', JSON.stringify(a.policy.predicates));
  console.log('  caveat(s):   ', JSON.stringify(a.policy.caveats));

  // The plan roots the principal authorized with the resource server (out-of-band).
  const authorizedPlans = new Set<string>();

  // 3. The agent builds + signs a proof-carrying action for an ALLOWED action ($42 <= the $500 cap).
  //    `encoded` is the wire string you would POST to the resource server (e.g. as a PCA-Action header).
  const params = { amount: 42, currency: 'usd' };
  const { pcactn, encoded } = a.act('stripe.refund', 'charge:ch_123', params, { counter: 1 });
  authorizedPlans.add(pcactn.plan.root);

  // 4. Verify OFFLINE with the full server verifier, against the grant WE hold.
  const valid = await serverVerdict(a.grant, decodePCActn(encoded), params, authorizedPlans);
  report('Valid action', valid);

  // 5. Tamper with the SIGNED action: redirect the refund to a different charge. The holder signature
  //    and the plan-inclusion proof both cover `action`, so this is detected offline — verdict DENY.
  const tampered = decodePCActn(encoded);
  tampered.action.resource = 'charge:ch_ATTACKER';
  const bad = await serverVerdict(a.grant, tampered, params, authorizedPlans);
  report('Tampered action', bad);

  // 6. OUT OF SCOPE. A compromised (or prompt-injected) agent signs an action its grant never allowed.
  //    The proof is well-formed and signed by the agent's real key, and here the plan root was even
  //    authorized; the verifier still denies, because the grant only permits `stripe.refund`.
  const rogue = a.act('github.delete_repo', 'repo:prod', {}, { counter: 2 });
  authorizedPlans.add(rogue.pcactn.plan.root);
  const rogueRes = await serverVerdict(a.grant, rogue.pcactn, {}, authorizedPlans);
  report('Out-of-scope action (github.delete_repo)', rogueRes);

  // 7. A FORGED ROOT. An attacker mints a root that names your principal as `issuer` but is signed with
  //    their OWN post-quantum key, then proves an action under it. The verifier is safe because the
  //    trusted grant is the one WE hold (`a.grant`), never the root the artifact presents as its own;
  //    trusting the presented root would make the attacker's key the trusted key. `allowedSuites` also
  //    refuses the pure-PQ suite outright.
  const attacker = generateKeyPair();
  const forgedRoot = mintRoot({
    principalSecret: attacker.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(attacker.publicKey),
    caveats: [{ type: 'ttl', secs: 3600 }],
    suite: { alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(9)) },
  });
  const forgedPlan = [{ id: 'n', verb: 'refund', resource: 'order/1', reversibility_class: 'reversible' as const }];
  const forged = buildPCActn({
    grant: forgedRoot,
    chain: [forgedRoot],
    plan: forgedPlan,
    nodeId: 'n',
    counter: 1,
    signerSecret: attacker.secretKey,
    aud: AUDIENCE,
    now: Date.now(),
  });
  const forgedRes = await serverVerdict(a.grant, forged, {}, authorizedPlans);
  report('Forged pure-PQ root', forgedRes);

  // The point of the whole exercise, asserted:
  if (!valid.allow) throw new Error('expected the valid action to be ALLOWed');
  if (bad.allow) throw new Error('expected the tampered action to be DENIED');
  if (rogueRes.allow) throw new Error('expected the out-of-scope action to be DENIED');
  if (forgedRes.allow) throw new Error('expected the forged root to be DENIED');
  console.log('\nauthF loop complete: the in-scope action is authorized; tampered, out-of-scope and forged ones are not.');
}

/** Pretty-print a verdict and its per-check breakdown. */
function report(label: string, res: PcaVerdict): void {
  const passes = Object.values(res.checks).filter((s) => s === 'pass').length;
  console.log(`\n${label}:  ${res.allow ? 'ALLOW' : 'DENY'}  (${passes} checks passed)`);
  if (!res.allow) for (const r of res.reasons) console.log(`  reason: ${r}`);
  for (const [name, status] of Object.entries(res.checks)) {
    const mark = status === 'pass' ? '[pass]' : status === 'fail' ? '[FAIL]' : '[ -- ]';
    console.log(`  ${mark} ${name}`);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
