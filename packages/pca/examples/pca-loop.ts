/**
 * THE PCA LOOP  --  a runnable, narrated walk through Proof-Carrying Authority.
 *
 * Think of this as "the OAuth dance", but for agents. In OAuth a user consents once, the client
 * receives a bearer token, and every later call just waves that token around. In PCA the principal
 * signs a *Root Intent Grant*, the agent commits to a *plan*, and then EVERY ACTION carries a
 * proof ("PCActn") that a verifier checks offline: is this action a node of the committed plan, is
 * it inside the signed policy, is the signing chain intact, and is there still trust budget left?
 *
 * Run:   pnpm --filter @atlasauth/pca example
 *
 * Only the real exported API of `../src` is used. Pieces that belong to later milestones (threshold
 * signatures, attestation, the revocation ledger) are stubbed or reported as 'not-enforced'.
 */
import {
  // keys + hashing
  generateKeyPair,
  encodeKey,
  hashCanonical,
  // grant + capabilities
  mintGrant,
  delegate,
  verifyChain,
  readEnvelope,
  // plan commitment
  commitPlan,
  conditionsDigest,
  merkleRoot,
  // the per-action proof
  signPCActn,
  verifyPCActnCore,
  pcactnDigest,
  PCACTN_VERSION,
  // policy VM + risk
  decide,
  recharge,
  DEFAULT_RISK_POLICY,
  safetyBound,
  type Capability,
  type PCActn,
  type PlanNode,
  type RiskInputs,
  type TrustBudget,
  type PolicyDecision,
  type RiskPolicy,
} from '../src';

// ---- tiny printing helpers ---------------------------------------------------------------
const step = (n: number, title: string) => console.log(`\n── Step ${n}: ${title} ──`);
const say = (s: string) => console.log(`   ${s}`);
const short = (s: string) => s.slice(0, 10) + '…';
const bar = (B: number, max: number) => {
  const n = Math.round((B / max) * 20);
  return `[${'█'.repeat(n)}${'░'.repeat(20 - n)}] ${B.toFixed(2)}/${max.toFixed(2)}`;
};
const showChecks = (checks: Record<string, string>) => {
  for (const [k, v] of Object.entries(checks)) {
    const mark = v === 'pass' ? 'PASS' : v === 'fail' ? 'FAIL' : 'n/e ';
    say(`  [${mark}] ${k}${v === 'not-enforced' ? '   (not enforced yet: a later milestone owns it)' : ''}`);
  }
};

async function main() {
  // A simulated clock so the output is deterministic about WHEN things happen (epoch ms).
  let now = Date.UTC(2026, 9, 6, 12, 0, 0);
  const tick = (secs = 1) => (now += secs * 1000);

  // ═════════════════════════════════════════════════════════════════════════════════════════
  step(1, 'the principal mints a Root Intent Grant G');
  // The principal (you, on your phone) owns a root Ed25519 key. Everything below is signed by it.
  const principal = generateKeyPair();
  const principalPub = encodeKey(principal.publicKey);

  // The risk policy is part of the signed grant. Here kappa=2 makes each action "expensive" so we
  // can watch the trust budget drain in only a few steps (default is kappa=1).
  const riskPolicy: RiskPolicy = { ...DEFAULT_RISK_POLICY, kappa: 2, rho: 0.5, bMax: 1 };

  const { grant: G, goalCommit } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: principalPub,
    holder: principalPub, // G is held by the principal; the agent gets a *delegated* child below
    goal: 'secure my account', // only a salted hash of this goes into the grant
    envelope: {
      // Semantic action-predicates: pure data (no code!). Default deny; any matching one allows.
      predicates: [
        { verb: 'list_sessions', resource: 'session:*' },
        {
          verb: 'revoke_session',
          resource: 'session:*',
          // "revoke_session WHERE session.device != current_device"
          where: [{ field: 'action.params.device', op: 'ne', ref: 'env.current_device' }],
        },
        { verb: 'rotate_recovery_keys', resource: 'account:me' },
      ],
      // Envelope caveats: also signed, also conjunctive.
      caveats: [
        { type: 'expires', at: now + 60 * 60 * 1000 },
        { type: 'delegation_depth', max: 2 },
      ],
      agent_binding: {}, // model/measurement allow-list: enforced by the L0 attestation milestone
      risk_policy: riskPolicy,
    },
  });
  say(`principal key      : ${short(principalPub)}`);
  say(`grant id           : ${short(G.id)}   goal_commit: ${short(goalCommit)} (the goal text is hidden)`);
  say(`envelope           : ${readEnvelope(G)!.predicates.length} predicates, ${readEnvelope(G)!.caveats.length} caveats, θ1=${riskPolicy.theta1} θ2=${riskPolicy.theta2} κ=${riskPolicy.kappa}`);
  say(`safety bound       : between human recharges, total auto-admitted risk <= ${safetyBound(riskPolicy)}`);
  say(`root chain verifies: ${JSON.stringify(verifyChain([G], principalPub))}`);

  // ═════════════════════════════════════════════════════════════════════════════════════════
  step(2, 'the agent gets its own key; the principal delegates G -> a task capability');
  // (In M5 the agent key will be TEE-attested. Today it's just a keypair.)
  const agent = generateKeyPair();
  const agentPub = encodeKey(agent.publicKey);
  // delegate() appends caveats (it can only NARROW) and rebinds the holder to the agent key.
  // Signer must be the parent's holder, which for G is the principal.
  const task: Capability = delegate(
    G,
    agentPub,
    [{ type: 'expires', at: now + 10 * 60 * 1000 }], // this task capability lives only 10 minutes
    principal.secretKey,
  );
  const chain: Capability[] = [G, task];
  say(`agent key          : ${short(agentPub)}`);
  say(`task capability    : ${short(task.id)} bound to the agent, ${task.caveats.length} caveats (G's + 1 added)`);
  say(`chain G -> task    : ${JSON.stringify(verifyChain(chain, principalPub))}`);

  // ═════════════════════════════════════════════════════════════════════════════════════════
  step(3, 'the agent commits a plan Π');
  // The plan is a list of nodes. Each node commits verb, resource, params digest and
  // reversibility class. commitPlan() returns a Merkle root and a proof generator.
  const node = (id: string, verb: string, resource: string, params: Record<string, unknown>, rev: string): PlanNode => ({
    id, verb, resource, params_digest: hashCanonical(params), reversibility_class: rev,
  });
  const P = {
    list: { sessions: {} },
    r2: { session_id: 's2', device: 'old-laptop' },
    r3: { session_id: 's3', device: 'cafe-kiosk' },
    r4: { session_id: 's4', device: 'unknown-tablet' },
    rot: { scope: 'all' },
  };
  const plan: PlanNode[] = [
    node('n1', 'list_sessions', 'session:*', P.list, 'reversible'),
    node('n2', 'revoke_session', 'session:s2', P.r2, 'reversible'),
    node('n3', 'revoke_session', 'session:s3', P.r3, 'reversible'),
    node('n4', 'revoke_session', 'session:s4', P.r4, 'reversible'),
    node('n5', 'rotate_recovery_keys', 'account:me', P.rot, 'irreversible'),
  ];
  const committed = commitPlan(plan);
  say(`plan nodes         : ${plan.map((n) => `${n.id}:${n.verb}`).join('  ')}`);
  say(`plan root          : ${short(committed.root)}  <- the only thing the verifier needs to remember`);
  say('(authorizing the root with the guardian is M1/M2: reported "not-enforced" below)');

  // Helper: the agent turns (plan node + params) into a signed PCActn. Everything here is plain
  // data; the verifier recomputes the Merkle leaf from the action itself, so lying is detectable.
  let counter = 0;
  const emit = (n: PlanNode, params: Record<string, unknown>, r: number, opts: { proofNode?: string } = {}): PCActn => {
    const proofNode = opts.proofNode ?? n.id;
    return signPCActn(
      {
        ver: PCACTN_VERSION,
        action: {
          verb: n.verb,
          resource: n.resource,
          params_digest: hashCanonical(params),
          reversibility_class: n.reversibility_class ?? 'reversible',
        },
        grant_ref: G.id,
        cap_chain: chain,
        plan: {
          root: committed.root,
          inclusion_proof: committed.proofFor(proofNode),
          node_id: n.id,
          conditions_digest: conditionsDigest(n.pre, n.post),
        },
        // Stubs for later milestones (attestation M5, freshness/revocation M3, provenance M1+):
        attestation: { quote_digest: '', epoch: 0, model_id: 'demo-model', measurement: '', operator: 'demo' },
        provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
        freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
        counter: ++counter,
        risk_claim: { r, inputs: {} },
        // v2 freshness binding: who this action is FOR, and for how long it is valid.
        aud: 'demo-resource-server',
        iat: Date.now(),
        exp: Date.now() + 10 * 60_000,
      },
      agent.secretKey, // signed by the LEAF holder: the agent
    );
  };

  // ── stub ledger (M3 replaces this) ──────────────────────────────────────────────────────
  // M3 will be a real append-only transparency log with revocation accumulators. Here: an array.
  const ledger: string[] = [];
  const anchor = (p: PCActn) => {
    ledger.push(pcactnDigest(p));
    return merkleRoot(ledger);
  };

  // Shared decision helper: build the ActionContext the Policy VM evaluates.
  let budget: TrustBudget = { B: riskPolicy.bMax, tau: now, asOf: now };
  const ask = (n: PlanNode, params: Record<string, unknown>, risk: Partial<RiskInputs>): PolicyDecision => {
    const d = decide({
      grant: G,
      action: {
        action: { verb: n.verb, resource: n.resource, params, reversibility_class: n.reversibility_class },
        env: { current_device: 'my-phone' },
      },
      plan,
      nodeId: n.id,
      risk,
      budget,
      now,
      caveatContext: { delegationDepth: 1 },
    });
    return d;
  };
  const verdict = (d: PolicyDecision) =>
    `guardian share ${d.releaseGuardianShare ? 'RELEASED' : 'WITHHELD'}, r=${d.r.toFixed(3)}, ` +
    `required t=${d.requiredThreshold.t} (${d.requiredThreshold.proof}), ` +
    `${d.admit ? 'auto-admit' : d.needStepUp ? 'STEP-UP' : 'pass'}` +
    (d.reasons.length ? `\n   reasons: ${d.reasons.join('; ')}` : '');

  // ═════════════════════════════════════════════════════════════════════════════════════════
  step(4, 'the agent emits a PCActn for the in-plan action list_sessions');
  tick();
  const n1 = plan[0]!;
  const pc1 = emit(n1, P.list, 0);
  say(`PCActn             : ${n1.verb} ${n1.resource} node=${pc1.plan.node_id} counter=${pc1.counter}`);
  say(`inclusion proof    : leaf #${pc1.plan.inclusion_proof.index} of ${pc1.plan.inclusion_proof.size}, ${pc1.plan.inclusion_proof.path.length} sibling hashes`);
  say(`signed (Ed25519)   : ${short(pc1.sig)} by the agent key`);

  // ═════════════════════════════════════════════════════════════════════════════════════════
  step(5, 'the Policy VM decides: does the guardian release its share?');
  // Listing sessions is nearly free: on-plan, reversible, no blast radius, trusted input.
  const lowRisk: Partial<RiskInputs> = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 };
  const d1 = ask(n1, P.list, lowRisk);
  say(verdict(d1));
  say(`threshold map      : r=${d1.r.toFixed(3)} <= θ1=${riskPolicy.theta1}  =>  t=1 (a claim suffices, no human)`);
  say(`budget             : ${bar(budget.B, riskPolicy.bMax)}  ->  ${bar(d1.budget.B, riskPolicy.bMax)}  (cost κ·r = ${(riskPolicy.kappa * d1.r).toFixed(3)})`);
  budget = d1.budget;

  // ═════════════════════════════════════════════════════════════════════════════════════════
  step(6, 'the verifier checks the PCActn offline -> ALLOW, then anchors it');
  const v1 = await verifyPCActnCore(pc1, { grant: G });
  say(`verifyPCActnCore   : ${v1.allow ? 'ALLOW' : 'REJECT'}`);
  showChecks(v1.checks);
  const root1 = anchor(pc1);
  say(`ledger (STUB — M3 will replace this): entry #${ledger.length} ${short(ledger[ledger.length - 1]!)} , ledger root ${short(root1)}`);

  // ═════════════════════════════════════════════════════════════════════════════════════════
  step(7, 'REJECTION: the agent tries an out-of-plan action, delete_account');
  tick();
  // The agent (compromised? prompt-injected?) wants delete_account. There is NO such node in Π, so
  // it cannot get an honest inclusion proof. The best it can do is replay list_sessions' proof.
  const rogueNode: PlanNode = {
    id: 'n1', // pretend to be node n1 ...
    verb: 'delete_account',
    resource: 'account:me',
    params_digest: hashCanonical({}),
    reversibility_class: 'irreversible',
  };
  const rogue = emit(rogueNode, {}, 0.1, { proofNode: 'n1' }); // ... using n1's real proof
  const vRogue = await verifyPCActnCore(rogue, { grant: G });
  say(`verifyPCActnCore   : ${vRogue.allow ? 'ALLOW' : 'REJECTED'}   reason: ${vRogue.reason}`);
  showChecks(vRogue.checks);
  const dRogue = ask(rogueNode, {}, { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 0, confidence: 0.5 });
  say(`and the Policy VM independently: ${verdict(dRogue)}`);
  say('Two independent layers said no: the plan (L1) and the signed predicates (L2).');

  // ═════════════════════════════════════════════════════════════════════════════════════════
  step(8, 'STEP-UP + BUDGET: the battery drains');
  // Routine, in-plan, reversible revokes: r ~ 0.22 (<= θ1), so each is auto-admitted but costs
  // κ·r ≈ 0.44 of budget. Watch B fall until it can no longer cover the next action.
  const routine: Partial<RiskInputs> = { semanticDistance: 0.2, reversibility: 0.7, blastRadius: 0.5, taint: 0, confidence: 0.9 };
  const revokes: [PlanNode, Record<string, unknown>][] = [
    [plan[1]!, P.r2],
    [plan[2]!, P.r3],
    [plan[3]!, P.r4],
  ];
  const run = async (n: PlanNode, params: Record<string, unknown>, risk: Partial<RiskInputs>, label: string) => {
    tick();
    const before = budget;
    const d = ask(n, params, risk);
    const pc = emit(n, params, d.r);
    const v = await verifyPCActnCore(pc, { grant: G });
    say(`${label}`);
    say(`  budget before : ${bar(before.B, riskPolicy.bMax)}`);
    say(`  decide        : ${verdict(d)}`);
    say(`  budget after  : ${bar(d.budget.B, riskPolicy.bMax)}`);
    say(
      `  verifier      : ${v.allow ? 'proof VALID' : 'REJECT'}` +
        (d.admit ? '' : ' -- but required threshold NOT met: the threshold check is "not-enforced" in the M0 core, so a real RS must not act until step-up completes (M2/M4)'),
    );
    if (d.admit) {
      anchor(pc);
      budget = d.budget;
    }
    return d;
  };

  await run(revokes[0]![0], revokes[0]![1], routine, '8a. revoke_session s2 (routine)');
  await run(revokes[1]![0], revokes[1]![1], routine, '8b. revoke_session s3 (routine)');
  const depleted = await run(revokes[2]![0], revokes[2]![1], routine, '8c. revoke_session s4 (routine, but the battery is flat)');
  say(`  -> same low risk as before, but B < cost: t=${depleted.requiredThreshold.t}. Depletion forces a human.`);

  // The human co-signs from their device: the ONLY way budget goes up.
  tick(30);
  budget = recharge(budget, riskPolicy.rho, riskPolicy.bMax, now);
  say(`8d. human co-sign  : recharge +ρ=${riskPolicy.rho}   budget now ${bar(budget.B, riskPolicy.bMax)}`);
  await run(revokes[2]![0], revokes[2]![1], routine, '8e. revoke_session s4 again, after recharge');

  // Now a genuinely high-risk action: in the plan AND permitted by the envelope, but irreversible,
  // max blast radius, far from the goal. Risk is high regardless of budget.
  const nRot = plan[4]!;
  const high: Partial<RiskInputs> = { semanticDistance: 0.8, reversibility: 0, blastRadius: 1, taint: 0.2, confidence: 0.7 };
  const dHigh = await run(nRot, P.rot, high, '8f. rotate_recovery_keys (irreversible, blast radius 1.0)');
  say(`  -> r=${dHigh.r.toFixed(3)} > θ2=${riskPolicy.theta2}  =>  t=${dHigh.requiredThreshold.t} (${dHigh.requiredThreshold.proof}): needs the principal-device share`);
  say(`  -> auto-admit? ${dHigh.admit}.  The budget was NOT debited; the agent must ask the human.`);

  console.log(`\nledger holds ${ledger.length} anchored actions (stub). Final budget ${bar(budget.B, riskPolicy.bMax)}`);
  console.log(
    '\nSummary: where OAuth returns a bearer token after one consent, PCA verifies a proof per action bound to committed intent.\n',
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
