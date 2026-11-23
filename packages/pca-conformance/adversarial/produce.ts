// The `produce` kind of the driver protocol: run one producer-vector case (packages/pca/conformance/producer-vectors.json or
// producer-pq-vectors.json) through the TypeScript reference producers. Input raw = JSON text `{op, args, keys, pq_keys?}`
// (`keys`: name -> {seed, public} Ed25519; `pq_keys`: name -> {family, seed, public, sign_seed?}). Output `{out}` (the
// artifact) or `{error}` (the producer refused). A native driver answers the same shape.
import { createRequire } from 'node:module';
import { safeParse } from '../../../tools/pca-diff-fuzz/gen/safejson';

const nodeRequire = createRequire(__filename);
// Same source choice as ref.ts: the TypeScript source, or the built dist when PCA_REF=dist.
const mod = (m: string) => nodeRequire(process.env.PCA_REF === 'dist' ? `../../pca/dist/${m}.js` : `../../pca/src/${m}`);
const pca = mod('index');
const meshM = mod('mesh');
const sessionM = mod('intent-session');
const requiredM = mod('intent-required');
const schemaM = mod('action-schema');
const labelsM = mod('label-receipts');
const factsM = mod('oracle-facts');
const offerM = mod('offer-set');
const progressM = mod('progress');
const contractsM = mod('contracts');
const enforcerM = mod('contract-enforcer');
const passportM = mod('passport');

type Any = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const bytes = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));

const KEYGEN: Record<string, string> = {
  'ml-dsa-65': 'mlDsa65Keygen', 'ml-dsa-87': 'mlDsa87Keygen', 'slh-dsa-sha2-128f': 'slhDsa128fKeygen', 'slh-dsa-sha2-256s': 'slhDsa256sKeygen', 'fn-dsa-512': 'fnDsa512Keygen', 'fn-dsa-1024': 'fnDsa1024Keygen',
};
const SLOT: Record<string, string> = {
  'ml-dsa-65': 'mlDsa', 'ml-dsa-87': 'mlDsa87', 'slh-dsa-sha2-128f': 'slhDsa', 'slh-dsa-sha2-256s': 'slhDsa256s', 'fn-dsa-512': 'fnDsa512', 'fn-dsa-1024': 'fnDsa1024',
};

function producer(keys: Record<string, { seed: string; public: string }>, pqKeys: Record<string, Any>): Record<string, (a: Any) => unknown> {
  const sk = (n: string) => bytes(keys[n]!.seed);
  const pk = (n: string) => keys[n]!.public;
  const kp = (n: string) => ({ secretKey: sk(n), publicKey: bytes(pk(n)) });
  const pq = (n: string | null): Record<string, Any> => {
    if (n === null || n === undefined) return {};
    const k = pqKeys[n];
    const pair = pca[KEYGEN[k.family]!](bytes(k.seed));
    return { [SLOT[k.family]!]: k.family.startsWith('fn-dsa') ? { ...pair, signSeed: bytes(k.sign_seed) } : pair };
  };
  const pqPub = (n: string | null) => (n ? pqKeys[n].public : undefined);
  return {
    // ---- Ed25519 producers (producer-vectors.json)
    ed25519_sign: (a) => ({ public: pca.b64u(pca.publicKeyOf(bytes(a.seed))), sig: pca.b64u(pca.sign(bytes(a.seed), pca.utf8(a.message_utf8))) }),
    goal_commit: (a) => ({ commit: pca.goalCommitOf(a.goal, a.salt) }),
    params_digest: (a) => ({ digest: pca.paramsDigest(a.params ?? undefined) }),
    plan_commit: (a) => {
      const c = pca.commitPlan(a.nodes);
      return { root: c.root, proofs: Object.fromEntries(a.nodes.map((n: { id: string }) => [n.id, c.proofFor(n.id)])) };
    },
    mint_grant: (a) => {
      const r = pca.mintGrant({ principalSecret: sk(a.principal), principalPublic: pk(a.principal), holder: pk(a.holder), envelope: a.envelope, goal: a.goal, salt: a.salt });
      return { grant: r.grant, goal_commit: r.goalCommit, goal_salt: r.goalSalt };
    },
    delegate: (a) => pca.delegate(a.parent, a.to_holder ? pk(a.to_holder) : a.parent.holder, a.added_caveats, sk(a.signer)),
    act: (a) => {
      const p = pca.buildPCActn({ grant: a.grant, chain: a.chain, plan: a.plan, nodeId: a.node_id, params: a.params, counter: a.counter, signerSecret: sk(a.signer), aud: a.aud, iat: a.iat, exp: a.exp, nonce: a.nonce, caution: a.caution, rationaleCommitment: a.rationale_commitment, toolBinding: a.tool_binding, freshAt: a.fresh_at });
      return { pcactn: p, threshold_message: pca.b64u(pca.thresholdMessage(p)), header: pca.pcaHeaders(pca.encodePCActn(p))['PCA-Action'] };
    },
    fresh_at: (a) => pca.signFreshAt(sk(a.signer), a.scope, a.state, a.issued_at),
    escalation_digests: (a) => ({ policy_digest: pca.escalationPolicyDigest(a.grant), action_digest: pca.escalationActionDigest(a.pcactn), history_head: pca.escalationHistoryHead(a.last_counter ?? undefined) }),
    sign_escalation_answer: (a) => pca.signEscalationAnswer(a.body, sk(a.signer)),
    sign_discharge: (a) => pca.signDischarge(a.body, sk(a.signer)),
    discharge_digest: (a) => ({ digest: pca.dischargeDigest(a.discharge) }),
    sign_narrow: (a) => pca.signNarrow(a.body, sk(a.signer)),
    sign_passport: (a) => {
      const passport = passportM.issuePassport(a.identity);
      return { passport, signed: passportM.signPassport(passport, { issuerSecret: sk(a.issuer), subject: pk(a.subject), exp: a.exp }) };
    },
    sign_workflow: (a) => pca.signWorkflow(sk(a.signer), a.body),
    sign_step_receipt: (a) => pca.signStepReceipt(sk(a.signer), { workflow: a.workflow, step: a.step, outcome: a.outcome, paramsDigest: a.params_digest, outputs: a.outputs, issuedAt: a.issued_at, ...(a.prev ? { prev: a.prev } : {}) }),
    sign_read_grant: (a) => pca.signReadGrant(sk(a.signer), a.body),
    sign_aggregate_grant: (a) => pca.signAggregateGrant(sk(a.signer), a.body),
    sign_revocation_epoch: (a) => pca.signRevocationEpoch(sk(a.signer), a.body),
    sign_undo_token: (a) => pca.signUndoToken(a.record, sk(a.signer)),
    sign_undo_receipt: (a) => pca.signUndoReceipt(a.body, sk(a.signer)),
    sign_contract: (a) => contractsM.signContract(a.contract, sk(a.signer)),
    sign_contract_reset: (a) => ({ sig: enforcerM.signContractReset(sk(a.signer), a.contract_id, a.seq) }),
    sign_constitution: (a) => pca.prohibitions.signConstitution(a.constitution, sk(a.signer)),
    sign_safety_evidence: (a) => pca.prohibitions.signSafetyEvidence(a.evidence, sk(a.signer), pk(a.signer)),
    sign_threshold_share: (a) => pca.signShare(a.role, sk(a.signer), bytes(a.message), { signerSet: a.signer_set, t: a.t }),
    sign_prepared_share: (a) => pca.signPreparedShare(a.role, sk(a.signer), bytes(a.prepared)),
    sign_pq_binding: (a) => pca.signPqBinding(sk(a.signer), pk(a.signer), a.pq_pk, a.epoch, a.aud),
    sign_caution: (a) => pca.agentNative.signCaution(a.body, sk(a.signer)),
    sign_heartbeat: (a) => pca.agentNative.signHeartbeat(a.body, sk(a.signer)),
    prov_recorder: (a) => {
      let tick = 0;
      const r = pca.createProvenanceRecorder({ mediator: a.mediator, kid: a.kid, secretKey: sk(a.key), session: a.session, now: () => a.clock[tick++] });
      const outs = a.steps.map((s: Any) =>
        s.kind === 'principal' ? r.principal(s.text) : s.kind === 'tool' ? r.tool(s.name, s.output) : s.kind === 'retrieval' ? r.retrieval(s.source, s.content) : s.kind === 'web' ? r.web(s.url, s.content) : r.forAction(s.op),
      );
      return { pin: r.pin, receipts: outs.slice(0, -1), bundle: outs[outs.length - 1] };
    },
    sign_mesh_action: (a) => ({ sig: meshM.signMeshAction(a.chain, a.action, sk(a.signer)) }),
    sign_session_root: (a) => sessionM.signSessionRoot(a.body, sk(a.signer)),
    mint_session_grant: (a) => {
      const r = sessionM.mintSessionGrant({ principalSecret: sk(a.principal), principalPublic: pk(a.principal), holder: pk(a.holder), session: a.session, seq: a.seq, ...(a.prev !== undefined ? { prev: a.prev } : {}), root: a.root, mapDigest: a.map_digest, ...(a.map_form ? { mapForm: a.map_form } : {}), predicates: a.predicates, ...(a.caveats ? { caveats: a.caveats } : {}), salt: a.salt });
      return { grant: r.grant, goal_salt: r.goalSalt };
    },
    sign_intent_required: (a) => requiredM.signIntentRequired(a.body, a.kid, sk(a.signer)),
    sign_action_schema: (a) => schemaM.signActionSchema(a.doc, a.kid, sk(a.signer)),
    sign_labels: (a) => labelsM.signLabels(a.body, sk(a.signer)),
    sign_fact: (a) => factsM.signFact(a.body, sk(a.signer)),
    sign_offer_set: (a) => offerM.signOfferSet(a.body, sk(a.signer)),
    sign_progress_step: (a) => progressM.signProgressStep(a.step, sk(a.signer), pk(a.signer)),
    sign_read_receipt: (a) => pca.signReadReceipt(sk(a.signer), { grant: a.grant, verb: a.verb, resource: a.resource, purpose: a.purpose, fields: a.fields, labels: a.labels, issuedAt: a.issued_at, ...(a.prev ? { prev: a.prev } : {}) }),
    sign_template: (a) => pca.signTemplate(a.def, sk(a.signer), pk(a.signer)),
    sign_tighten: (a) => pca.signTighten(a.overlay, sk(a.signer), pk(a.signer)),
    parse_limit: (a) => pca.parseLimit(a.limit),
    compile_policy: (a) => {
      const { actions: _a, inputLimits: _i, ...rest } = pca.compilePolicy({ permissions: a.permissions, limits: a.limits, budgetModel: a.budget_model, now: a.now });
      return rest;
    },
    facade_act: (a) => {
      const base = pca.agent({ principal: kp(a.principal), goal: a.goal, goalSalt: a.goal_salt, permissions: a.permissions, limits: a.limits, holder: kp(a.holder), aud: a.aud, now: a.now, provenance: { secretKey: sk(a.recorder_key), session: a.session, now: () => a.now } });
      for (const t of a.principal_messages ?? []) base.provenance.principal(t);
      const h = a.sub_agent ? base.subAgent({ holder: kp(a.sub_agent.holder), addedCaveats: a.sub_agent.added_caveats }) : base;
      const r = h.act(a.act.verb, a.act.resource, a.act.params, { counter: a.act.counter, now: a.act.now, ...(a.act.nonce !== undefined ? { nonce: a.act.nonce } : {}) });
      return { grant: base.grant, goal_commit: base.grant.caveats[0].goal_commit, chain: h.chain, pcactn: r.pcactn, encoded: r.encoded, provenance: r.provenance };
    },
    // ---- post-quantum producers (producer-pq-vectors.json)
    pq_keygen: (a) => {
      const pair = pca[KEYGEN[a.family]!](bytes(a.seed));
      return { public: pca.b64u(pair.publicKey ?? pair.verifyingKey) };
    },
    suite_sign: (a) => pca.signWithSuite(a.alg, { ...(a.ed ? { edSecret: sk(a.ed) } : {}), ...pq(a.pq) }, pca.utf8(a.message_utf8)),
    mint_root_suite: (a) => pca.mintRoot({ principalSecret: sk(a.principal), principalPublic: pk(a.principal), holder: pk(a.holder), ...(a.holder_pq ? { holderPq: pqPub(a.holder_pq) } : {}), caveats: a.caveats, suite: { alg: a.alg, ...pq(a.pq) } }),
    delegate_suite: (a) => pca.delegate(a.parent, pk(a.to_holder), a.added_caveats, sk(a.signer), { alg: a.alg, ...pq(a.pq) }, pqPub(a.holder_pq)),
    sign_pcactn_suite: (a) => ({ pcactn: pca.signPCActnSuite(a.body, { alg: a.alg, edLeafSecret: sk(a.signer), ...pq(a.pq) }) }),
    sign_artifact_suite: (a) => {
      const suite = { alg: a.alg, ...pq(a.pq) };
      if (a.kind === 'escalation_answer') return pca.signEscalationAnswer(a.body, sk(a.signer), suite);
      if (a.kind === 'revocation_epoch') return pca.signRevocationEpoch(sk(a.signer), a.body, suite);
      throw new Error(`unknown artifact kind ${a.kind}`);
    },
  };
}

/** One `produce` item: `{out}` on success, `{error}` when the producer refuses or the op is unknown. */
export function refProduce(rawStr: string): Record<string, unknown> {
  let o: Any;
  try {
    o = safeParse(rawStr);
  } catch (e) {
    return { error: 'exception:' + (e as Error).message.slice(0, 60) };
  }
  const f = producer(o.keys ?? {}, o.pq_keys ?? {})[o.op];
  if (!f) return { error: `unsupported_op: ${String(o.op)}` };
  try {
    return { out: JSON.parse(JSON.stringify(f(o.args))) };
  } catch (e) {
    return { error: (e as Error).message };
  }
}
