/**
 * The PCA demo story: nine scripted outcomes against a REAL local resource server.
 *
 *   resource server  node:http + `withPCA` (@atlasauth/pca-fetch) = the real default-deny verifier
 *   guardian         FROST 3-of-5 (RFC 9591) with all five key shares held in this process
 *   agent            built with the `agent()` facade; signs one PCActn per tool call
 *
 * Nothing here talks to the network beyond 127.0.0.1, and nothing needs an account or an API key.
 * `runStory` returns the outcome rows; the caller decides how to print them.
 */
import { createServer } from 'node:http';

const AUD = 'ins_pca_demo';
const FROST_T = 3;
const FROST_N = 5;
const GOAL = 'reconcile October refunds';

/** Risk the resource server computes for itself (never trusts the agent's claim): amount / $500 cap. */
const CAP = 500;
const riskOf = (verb, params) =>
  verb === 'stripe.refund' ? Math.max(0, Math.min(1, Number(params?.amount ?? CAP) / CAP)) : 0.8;

export async function runStory({ pca, fetchGuard, ui, breakIt = false }) {
  const {
    agent, agentNative, generateKeyPair, b64u, buildPCActn, encodePCActn, decodePCActn, pcaHeaders, decodePcaHeader,
    commitPlan, paramsDigest, thresholdMessage, shareMessage, signShare, assembleThreshold, createThresholdVerifier,
    frostTrustedDealerKeygen, frostCosign, admit, decide, DEFAULT_CATALOG, TransparencyLedger, verifyWitnessedHead,
    verifyLedgerInclusion, verifyOpening, entryCommit, appendReceipt, verifyReceiptChain, receiptHead, pcactnDigest, pcaStateKey,
  } = pca;
  const { withPCA, memoryPcaStore } = fetchGuard;

  const rows = [];
  /** Record one outcome row; `expected`/`actual` are ALLOWED | DENIED | VERIFIED | REFUSED. */
  const record = (step, label, expected, actual, reason, extra = {}) => {
    // `match`: the outcome must ALSO be for the right reason (a denial for the wrong reason is a deviation).
    const { match, ...rest } = extra;
    const reasonOk = !match || match.test(reason ?? '');
    const row = { step, label, expected, actual, ok: expected === actual && reasonOk, reason: reason ?? '', ...rest };
    rows.push(row);
    ui.outcome(row);
    return row;
  };

  // ---- parties ---------------------------------------------------------------------------------
  const principal = generateKeyPair(); // the human; roots the grant and holds the "principal device" share
  const witnessKey = generateKeyPair(); // the resource server operator's transparency-log signing key
  const kg = frostTrustedDealerKeygen(FROST_T, FROST_N); // guardian: 3-of-5, shares all in-process
  const guardianPub = b64u(kg.groupPublicKey);

  // ---- 1. principal mints a grant with a plan + budget -----------------------------------------
  await ui.step(1, 'Principal mints a grant (plan + budget)', 'A human signs exactly what the agent may do, how much, and the plan it committed to.');
  const a = agent({
    principal,
    goal: GOAL,
    permissions: { stripe: ['refund'] },
    limits: { refund: `$${CAP}/day` },
    aud: AUD,
    // $-denominated budget of $300; <=30% of the $500 cap is machine-approved (t=1), above it needs t=3.
    riskPolicy: { theta1: 0.3, theta2: 0.3, bMax: 300 },
  });
  const policy = a.policy.riskPolicy;
  const spec = (verb) => DEFAULT_CATALOG.get(verb) ?? { reversibility: 'irreversible', blastRadius: 0.8 };
  const node = (id, verb, resource, params) => ({
    id, verb, resource, params_digest: paramsDigest(params), reversibility_class: spec(verb).reversibility,
  });
  const PARAMS = {
    n1: { amount: 42, currency: 'usd' },
    n2: { amount: 450, currency: 'usd' },
    n3: { amount: 140, currency: 'usd' },
    n4: { amount: 140, currency: 'usd' },
    n5: { amount: 10, currency: 'usd' },
    n6: { amount: 200, currency: 'usd' },
    n7: { to: 'cust@example.com', body: 'hi' },
    n8: { amount: 60, currency: 'usd' },
  };
  const plan = [
    node('n1', 'stripe.refund', 'charge:ch_001', PARAMS.n1),
    node('n2', 'stripe.refund', 'charge:ch_002', PARAMS.n2),
    node('n3', 'stripe.refund', 'charge:ch_003', PARAMS.n3),
    node('n4', 'stripe.refund', 'charge:ch_004', PARAMS.n4),
    node('n5', 'stripe.refund', 'charge:ch_005', PARAMS.n5),
    node('n6', 'stripe.refund', 'charge:ch_006', PARAMS.n6),
    node('n7', 'gmail.send', 'msg:thread-1', PARAMS.n7),
    node('n8', 'stripe.refund', 'charge:ch_008', PARAMS.n8),
  ];
  const committed = commitPlan(plan);
  ui.info(`grant ${a.grant.id.slice(0, 16)}...  may: stripe.refund up to $${CAP} each, $${policy.bMax} trust budget`);
  ui.info(`plan root ${committed.root.slice(0, 16)}...  (${plan.length} committed actions)`);
  ui.info(`<=${(policy.theta1 * 100).toFixed(0)}% of cap: agent alone (t=1).  Above: needs t=3 = agent + guardian(FROST ${FROST_T}-of-${FROST_N}) + principal`);
  ui.info(`autonomy bound: even a fully compromised agent can auto-spend at most $${a.autonomyBound} before a human co-sign`);

  // ---- the resource server -----------------------------------------------------------------------
  const store = memoryPcaStore();
  const seen = new WeakMap(); // pcactn -> {r, budget} computed by the server for THAT request
  const ledger = new TransparencyLedger(a.principalPublic);
  let receipts = [];
  const openings = []; // ledger index -> {commit, salt}
  let authorizedPlan; // the plan the principal registered with this server

  const signerSetFor = (leafHolder) => [
    { role: 'agent', publicKey: leafHolder },
    { role: 'guardian', publicKey: guardianPub },
    { role: 'principal', publicKey: b64u(principal.publicKey) },
  ];
  const leafOf = (p) => p.cap_chain?.[p.cap_chain.length - 1]?.holder;

  // Misconfigured on purpose with --break: proves the harness exits nonzero on deviation.
  const rsAudience = breakIt ? 'ins_some_other_server' : AUD;
  const guard = {
    audience: rsAudience,
    // The operation the request asks this server to run: its verb, resource and params, taken from the request body
    // (this endpoint is an RPC relay), never from the proof. The proof must be for exactly that operation.
    operation: (req) => req.body?.operation,
    resolveGrant: async (ref) => (ref === a.grant.id ? a.grant : null),
    budgetStore: store,
    hooks: {
      revocation: () => ({ enforced: true, ok: true }),
      threshold: (ctx) => {
        const info = seen.get(ctx.pcactn);
        const t = info ? admit(info.r, info.budget, policy).t : 3; // mirror the Policy VM; fail closed
        return createThresholdVerifier({ signerSet: signerSetFor(leafOf(ctx.pcactn) ?? ''), t })(ctx);
      },
    },
    context: async (req, p) => {
      const params = req.body?.params;
      const key = pcaStateKey(a.grant.id, leafOf(p), undefined, rsAudience);
      const st = await store.get(key);
      const now = Date.now();
      const budget = st?.budget ?? { B: policy.bMax, tau: now, asOf: now };
      const r = riskOf(p.action?.verb, params);
      seen.set(p, { r, budget });
      return {
        params,
        plan: authorizedPlan,
        planAuthorized: authorizedPlan ? true : undefined,
        budget,
        risk: { blastRadius: r, semanticDistance: 0, reversibility: 0.5, taint: 0, confidence: 1 },
      };
    },
  };

  const guarded = withPCA(guard, async (_req, { pca: ctx }) => {
    const { index, commit } = ledger.append(ctx.pcactn);
    openings[index] = { commit, salt: ledger.entry(index).opening.salt };
    return Response.json({ ok: true, verdict: ctx.verdict, ledgerIndex: index });
  });

  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const request = new Request(`http://127.0.0.1${req.url}`, {
      method: req.method,
      headers: req.headers,
      body: req.method === 'GET' ? undefined : Buffer.concat(chunks),
    });
    const response = await guarded(request);
    const text = await response.text();
    // Access log: one hash-chained receipt per request (allow AND deny), decodable requests only.
    try {
      const p = decodePCActn(decodePcaHeader(req.headers['pca-action'] ?? ''));
      const verdict = JSON.parse(text).verdict ?? {};
      receipts = appendReceipt(receipts, p, { allow: response.status === 200, checks: verdict.checks });
    } catch { /* undecodable proof: nothing to log */ }
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(text);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  ui.info(`resource server listening on ${base}  (audience ${AUD}, default-deny verifier)`);

  const authorize = () => { authorizedPlan = plan; };
  authorize();
  ui.info('principal registered the plan root with the resource server (plan_root_authorized)');
  record(1, 'grant + plan minted and registered', 'VERIFIED', 'VERIFIED', `grant ${a.grant.id.slice(0, 12)}, ${plan.length}-node plan`);

  // ---- helpers ------------------------------------------------------------------------------------
  const sign = (who, nodeId, counter, opts = {}) => {
    const n = (opts.plan ?? plan).find((x) => x.id === nodeId);
    const params = opts.params ?? PARAMS[nodeId];
    const r = riskOf(n.verb, params);
    return {
      params,
      operation: { verb: n.verb, resource: n.resource, params },
      pcactn: buildPCActn({
        grant: a.grant, chain: who.chain, plan: opts.plan ?? plan, nodeId, params, counter,
        signerSecret: who.holder.secretKey, aud: AUD, riskClaim: { r, inputs: { blastRadius: r } },
      }),
    };
  };

  const send = async (pcactn, params, operation) => {
    const enc = typeof pcactn === 'string' ? pcactn : JSON.stringify(pcactn);
    const res = await fetch(`${base}/act`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...pcaHeaders(enc) },
      body: JSON.stringify({ params, operation }),
    });
    const body = await res.json().catch(() => ({}));
    const verdict = body.verdict ?? {};
    const failed = Object.entries(verdict.checks ?? {}).filter(([, v]) => v === 'fail').map(([k]) => k);
    const reasons = (verdict.reasons ?? []).filter((x) => !x.startsWith('policy: risk') || res.status !== 200);
    return {
      status: res.status, allowed: res.status === 200, verdict, failed,
      t: verdict.requiredThreshold?.t, reason: reasons[0] ?? body.error ?? (res.status === 200 ? 'all checks passed' : 'denied'),
      reasons, ledgerIndex: body.ledgerIndex,
    };
  };
  const word = (r) => (r.allowed ? 'ALLOWED' : 'DENIED');
  const short = (s) => (s.length > 110 ? s.slice(0, 107) + '...' : s);

  // ---- 2. in-plan action -> ALLOWED ----------------------------------------------------------------
  await ui.step(2, 'Agent acts inside the plan', 'A proof-carrying action: signed, bound to one plan node, one audience, one counter.');
  const act2 = sign(a, 'n1', 1);
  const enc2 = encodePCActn(act2.pcactn);
  const r2 = await send(enc2, act2.params, act2.operation);
  ui.wire('refund $42 on ch_001', r2);
  record(2, 'in-plan refund $42', 'ALLOWED', word(r2), r2.reason, { status: r2.status });

  // ---- 3. out-of-plan -> DENIED ----------------------------------------------------------------------
  await ui.step(3, 'Agent goes off-plan', 'Same verb, same cap - but this action is not a node of the plan the principal authorized.');
  const rogueNode = node('x1', 'stripe.refund', 'charge:ch_EVIL', PARAMS.n1);
  const act3 = sign(a, 'x1', 2, { plan: [rogueNode], params: PARAMS.n1 });
  const r3 = await send(encodePCActn(act3.pcactn), act3.params, act3.operation);
  ui.wire('refund $42 on ch_EVIL (not in plan)', r3);
  record(3, 'off-plan refund (charge not in plan)', 'DENIED', word(r3), r3.reasons.find((x) => x.startsWith('plan_root')) ?? r3.reason, { status: r3.status , match: /plan/ });

  // ---- 4. risky action -> step-up t=3 via FROST ----------------------------------------------------------
  await ui.step(4, 'Risky action escalates to step-up', `$450 is 90% of the cap: the agent alone is not enough. Needs t=3 cosigners.`);
  const act4 = sign(a, 'n2', 3);
  const r4a = await send(encodePCActn(act4.pcactn), act4.params, act4.operation);
  ui.wire('refund $450 with only the agent signature', r4a);
  record('4a', 'refund $450, agent signature only', 'DENIED', word(r4a), r4a.reasons.find((x) => x.startsWith('threshold')) ?? r4a.reason, { status: r4a.status, requiredT: r4a.t , match: /threshold/ });

  // Guardian: runs its OWN Policy VM before releasing its share, then FROST-signs with 3 of 5 nodes.
  const quorum = (ids) => kg.participantShares.filter((s) => ids.includes(s.identifier));
  const message = thresholdMessage(act4.pcactn);
  const signerSet = signerSetFor(leafOf(act4.pcactn));
  const gmsg = shareMessage('guardian', message, signerSet, 3);
  let lone;
  try { frostCosign(kg.groupPublicKey, quorum([1, 2]), gmsg, { threshold: FROST_T }); lone = 'signed (BUG)'; }
  catch (e) { lone = e.message; }
  ui.info(`guardian nodes 1+2 alone try to sign -> ${lone}`);
  record('4b', `2 of ${FROST_N} guardian nodes try to cosign`, 'REFUSED', lone.startsWith('signed') ? 'ALLOWED' : 'REFUSED', lone, { match: /below the threshold/ });

  const release = decide({
    grant: a.grant, chain: a.chain, now: Date.now(), budget: { B: policy.bMax, tau: Date.now(), asOf: Date.now() },
    action: { action: { verb: 'stripe.refund', resource: 'charge:ch_002', params: act4.params, reversibility_class: act4.pcactn.action.reversibility_class } },
    plan, nodeId: 'n2', risk: { blastRadius: riskOf('stripe.refund', act4.params), semanticDistance: 0, reversibility: 0.5, taint: 0, confidence: 1 },
  });
  ui.info(`guardian Policy VM: release=${release.releaseGuardianShare}, r=${release.r.toFixed(2)}, requires t=${release.requiredThreshold.t}`);
  const sigG = frostCosign(kg.groupPublicKey, quorum([1, 3, 5]), gmsg, { threshold: FROST_T });
  ui.info(`guardian FROST ${FROST_T}-of-${FROST_N}: nodes 1,3,5 produced ONE 64-byte Ed25519 signature under the group key`);
  const shareG = { role: 'guardian', publicKey: guardianPub, sig: b64u(sigG) };
  const shareP = signShare('principal', principal.secretKey, message, { signerSet, t: 3 });
  ui.info('principal approved on their device (Ed25519 share)');
  const stepped = { ...act4.pcactn, threshold: assembleThreshold([shareG, shareP]) };
  const r4c = await send(JSON.stringify(stepped), act4.params, act4.operation);
  ui.wire('refund $450 with agent + guardian(FROST) + principal', r4c);
  record('4c', 'refund $450 with t=3 cosigners', 'ALLOWED', word(r4c), r4c.reason, { status: r4c.status, requiredT: r4c.t });
  const headline = { pcactn: stepped, ledgerIndex: r4c.ledgerIndex };

  // ---- 5. replay ------------------------------------------------------------------------------------------
  await ui.step(5, 'Replay an accepted action', 'The attacker captured step 2 off the wire and resends it byte for byte.');
  const r5 = await send(enc2, act2.params, act2.operation);
  ui.wire('replay of the step-2 refund', r5);
  record(5, 'replay of accepted action', 'DENIED', word(r5), r5.reasons.find((x) => x.startsWith('replay')) ?? r5.reason, { status: r5.status , match: /replay.*replay/ });

  // ---- 6. tampering -----------------------------------------------------------------------------------------
  await ui.step(6, 'Tamper with a signed action', 'Three edits to a fresh, otherwise-valid action. The signature or the chain must break.');
  const base6 = sign(a, 'n5', 4);
  const clone = () => JSON.parse(JSON.stringify(base6.pcactn));
  const t6a = clone();
  const raw = Buffer.from(t6a.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  raw[0] ^= 0x01;
  t6a.sig = raw.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const r6a = await send(t6a, base6.params, base6.operation);
  ui.wire('one bit of the signature flipped', r6a);
  record('6a', 'bit-flipped signature', 'DENIED', word(r6a), r6a.reasons.find((x) => /signature|leaf/.test(x)) ?? r6a.reason, { status: r6a.status , match: /signature/ });

  // widened delegation: take a sub-agent action and strip the narrowing caveat from its capability
  const narrow = agentNative.predicatesCaveat([
    { verb: 'stripe.refund', resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] },
  ]);
  const sub = a.subAgent({ addedCaveats: [narrow] });
  const baseSub = sign(sub, 'n6', 1);
  const t6b = JSON.parse(JSON.stringify(baseSub.pcactn));
  const leafCap = t6b.cap_chain[t6b.cap_chain.length - 1];
  leafCap.caveats = leafCap.caveats.filter((c) => c.type !== 'predicates');
  const r6b = await send(t6b, baseSub.params, baseSub.operation);
  ui.wire('sub-agent strips its own "<= $100" caveat from the delegation', r6b);
  record('6b', 'widened delegation (caveat removed)', 'DENIED', word(r6b), r6b.reasons.find((x) => /cap_chain|chain|signature/.test(x)) ?? r6b.reason, { status: r6b.status , match: /cap_chain/ });

  const t6c = clone();
  t6c.aud = 'ins_some_other_server';
  const r6c = await send(t6c, base6.params, base6.operation);
  ui.wire('audience swapped to another server', r6c);
  record('6c', 'swapped audience', 'DENIED', word(r6c), r6c.reasons.find((x) => /aud/.test(x)) ?? r6c.reason, { status: r6c.status , match: /aud/ });

  // ---- 7. budget exhaustion -----------------------------------------------------------------------------------
  await ui.step(7, 'Spend the trust budget', `Budget is $${policy.bMax}. Each auto-approved refund is debited; $42 is already spent.`);
  const act7a = sign(a, 'n3', 5);
  const r7a = await send(encodePCActn(act7a.pcactn), act7a.params, act7a.operation);
  ui.wire('refund $140 (budget left $258 -> $118)', r7a);
  record('7a', 'refund $140 while budget remains', 'ALLOWED', word(r7a), r7a.reason, { status: r7a.status });
  const act7b = sign(a, 'n4', 6);
  const r7b = await send(encodePCActn(act7b.pcactn), act7b.params, act7b.operation);
  ui.wire('refund $140 again (budget $118 < $140)', r7b);
  record('7b', 'refund $140 after budget is spent', 'DENIED', word(r7b), r7b.reasons.find((x) => /budget/.test(x)) ?? r7b.reasons.find((x) => /threshold/.test(x)) ?? r7b.reason, { status: r7b.status, requiredT: r7b.t , match: /budget/ });

  // ---- 8. attenuated sub-agent ------------------------------------------------------------------------------------
  await ui.step(8, 'Sub-agent cannot exceed its parent', 'The agent delegated a narrower capability: refunds up to $100 only. Authority can shrink, never grow.');
  const act8a = sign(sub, 'n8', 2);
  const r8a = await send(encodePCActn(act8a.pcactn), act8a.params, act8a.operation);
  ui.wire('sub-agent refunds $60 (within its $100 caveat)', r8a);
  record('8a', 'sub-agent refund $60 (inside delegation)', 'ALLOWED', word(r8a), r8a.reason, { status: r8a.status });
  const act8b = sign(sub, 'n6', 3);
  const r8b = await send(encodePCActn(act8b.pcactn), act8b.params, act8b.operation);
  ui.wire('sub-agent refunds $200 (parent allows $500, delegation allows $100)', r8b);
  record('8b', 'sub-agent refund $200 (exceeds delegation)', 'DENIED', word(r8b), r8b.reasons.find((x) => /delegat|caveat/.test(x)) ?? r8b.reason, { status: r8b.status , match: /delegat/ });
  const act8c = sign(sub, 'n7', 4);
  const r8c = await send(encodePCActn(act8c.pcactn), act8c.params, act8c.operation);
  ui.wire('sub-agent sends email (parent never had gmail.send)', r8c);
  record('8c', 'sub-agent action the parent never held', 'DENIED', word(r8c), r8c.reasons.find((x) => /no predicate permits/.test(x)) ?? r8c.reasons.find((x) => /caveat/.test(x)) ?? r8c.reason, { status: r8c.status , match: /no predicate permits/ });

  // ---- 9. receipts + transparency log, verified OFFLINE ---------------------------------------------------------------
  await ui.step(9, 'Verify the receipt offline', 'An auditor with only public keys and this bundle - no server, no database - checks the history.');
  const idx = headline.ledgerIndex;
  if (idx === undefined) {
    record(9, 'receipt + inclusion proof verify offline', 'VERIFIED', 'REFUSED', 'no allowed action reached the transparency log');
    server.close();
    return { rows, ok: false, bundle: null, audience: AUD };
  }
  const head = ledger.witnessHead(witnessKey.secretKey);
  const bundle = JSON.parse(JSON.stringify({
    pcactn: headline.pcactn,
    opening: openings[idx],
    inclusion: ledger.inclusionProof(idx),
    head,
    receipts,
    witnessPublic: b64u(witnessKey.publicKey),
  }));
  const offline = verifyBundle(pca, bundle);
  ui.info(`bundle: ${receipts.length} receipts, ledger size ${head.size}, signed head root ${head.root.slice(0, 16)}...`);
  for (const c of offline.checks) ui.info(`  [${c.ok ? 'PASS' : 'FAIL'}] ${c.name}`);
  record(9, 'receipt + inclusion proof verify offline', 'VERIFIED', offline.ok ? 'VERIFIED' : 'REFUSED', offline.ok ? 'opening, inclusion, signed head, receipt chain all check out' : offline.checks.find((c) => !c.ok)?.name);
  // negative control: rewrite history in the bundle -> the same verifier must refuse it.
  const forged = JSON.parse(JSON.stringify(bundle));
  const victim = forged.receipts.find((x) => x.outcome === 'deny');
  if (victim) victim.outcome = 'allow';
  const forgedRes = verifyBundle(pca, forged);
  record('9b', 'tampered receipt log (a deny rewritten as allow)', 'REFUSED', forgedRes.ok ? 'VERIFIED' : 'REFUSED', 'failed: ' + (forgedRes.checks.find((c) => !c.ok)?.name ?? ''), { match: /receipt hash-chain/ });

  server.close();
  return { rows, ok: rows.every((r) => r.ok), bundle, audience: AUD };
}

/** Offline verification of a receipt bundle: uses ONLY public data. Exported so auditors can reuse it. */
export function verifyBundle(pca, b) {
  const { verifyOpening, entryCommit, verifyLedgerInclusion, verifyWitnessedHead, verifyReceiptChain, pcactnDigest } = pca;
  const checks = [];
  const add = (name, ok) => checks.push({ name, ok: Boolean(ok) });
  const commit = b.opening ? entryCommit(b.opening.salt, b.pcactn) : '';
  add('opening reproduces the ledger commitment', b.opening && verifyOpening(b.opening.commit ?? commit, { salt: b.opening.salt, pcactn: b.pcactn }));
  add('Merkle inclusion proof reaches the signed root', verifyLedgerInclusion(b.head.root, b.inclusion, commit));
  add('tree head signed by the log operator', verifyWitnessedHead(b.head, b.witnessPublic));
  const chain = verifyReceiptChain(b.receipts);
  add('receipt hash-chain is intact', chain.ok);
  add('receipt for this action is in the chain', b.receipts.some((r) => r.actionDigest === pcactnDigest(b.pcactn) && r.outcome === 'allow'));
  return { ok: checks.every((c) => c.ok), checks };
}
