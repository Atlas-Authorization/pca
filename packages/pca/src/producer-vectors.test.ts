/**
 * Producer vectors (conformance/producer-vectors.json, generated independently by conformance/gen-producer.mjs from fixed keys):
 * the reference producers must reproduce every `expect` exactly. The native producers (Python, Go, Rust, Ruby, PHP, ...) are held to
 * the same file, so a drift in either direction is caught here or there.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { delegate } from './capability';
import { goalCommitOf, mintGrant } from './envelope';
import { signAggregateGrant } from './read-vault';
import { signReadGrant } from './readside';
import { signFreshAt } from './fresh-at';
import { dischargeDigest, signDischarge, signNarrow } from './caveat-lang';
import { escalationActionDigest, escalationHistoryHead, escalationPolicyDigest, signEscalationAnswer } from './escalation';
import { issuePassport, signPassport } from './passport';
import { signStepReceipt, signWorkflow } from './workflow';
import { buildPCActn, encodePCActn } from './pcactn';
import { commitPlan, paramsDigest } from './merkle';
import { b64u, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';
import { pcaHeaders } from './adapters';
import { signRevocationEpoch } from './revocation';
import { signUndoReceipt, signUndoToken } from './undo';
import { signContract } from './contracts';
import { signContractReset } from './contract-enforcer';
import { signConstitution, signSafetyEvidence } from './prohibitions';
import { signPreparedShare, signShare } from './threshold';
import { signPqBinding } from './pq';
import { signCaution, signHeartbeat } from './agent-native';
import { createProvenanceRecorder } from './arg-provenance';
import { signMeshAction } from './mesh';
import { mintSessionGrant, signSessionRoot } from './intent-session';
import { signIntentRequired } from './intent-required';
import { signActionSchema } from './action-schema';
import { signLabels } from './label-receipts';
import { signFact } from './oracle-facts';
import { signOfferSet } from './offer-set';
import { signProgressStep } from './progress';
import { signReadReceipt } from './readside';
import { signTemplate, signTighten } from './policy-link';
import { agent, compilePolicy, parseLimit } from './facade';

type Args = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const doc = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'producer-vectors.json'), 'utf8')) as {
  keys: Record<string, { seed: string; public: string }>;
  cases: Array<{ name: string; op: string; args: Args; expect: Args }>;
};
const sk = (name: string): Uint8Array => new Uint8Array(Buffer.from(doc.keys[name]!.seed, 'base64url'));
const pk = (name: string): string => doc.keys[name]!.public;
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const kp = (name: string) => ({ secretKey: sk(name), publicKey: new Uint8Array(Buffer.from(pk(name), 'base64url')) });
const raw = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));
/** A refusal case expects `{error}`: the producer must throw (and sign nothing). */
const orError = (f: () => unknown): unknown => {
  try {
    return f();
  } catch (e) {
    return { error: (e as Error).message };
  }
};

const run: Record<string, (a: Args) => unknown> = {
  ed25519_sign: (a) => ({ public: b64u(publicKeyOf(new Uint8Array(Buffer.from(a.seed, 'base64url')))), sig: b64u(sign(new Uint8Array(Buffer.from(a.seed, 'base64url')), utf8(a.message_utf8))) }),
  goal_commit: (a) => ({ commit: goalCommitOf(a.goal, a.salt) }),
  params_digest: (a) => ({ digest: paramsDigest(a.params ?? undefined) }),
  plan_commit: (a) => {
    const c = commitPlan(a.nodes);
    return { root: c.root, proofs: Object.fromEntries(a.nodes.map((n: { id: string }) => [n.id, c.proofFor(n.id)])) };
  },
  mint_grant: (a) => {
    const r = mintGrant({ principalSecret: sk(a.principal), principalPublic: pk(a.principal), holder: pk(a.holder), envelope: a.envelope, goal: a.goal, salt: a.salt });
    return { grant: r.grant, goal_commit: r.goalCommit, goal_salt: r.goalSalt };
  },
  delegate: (a) => delegate(a.parent, a.to_holder ? pk(a.to_holder) : a.parent.holder, a.added_caveats, sk(a.signer)),
  act: (a) => {
    const p = buildPCActn({ grant: a.grant, chain: a.chain, plan: a.plan, nodeId: a.node_id, params: a.params, counter: a.counter, signerSecret: sk(a.signer), aud: a.aud, iat: a.iat, exp: a.exp, nonce: a.nonce, caution: a.caution, rationaleCommitment: a.rationale_commitment, toolBinding: a.tool_binding, freshAt: a.fresh_at });
    const enc = encodePCActn(p);
    return { pcactn: p, header: pcaHeaders(enc)['PCA-Action'] };
  },
  fresh_at: (a) => signFreshAt(sk(a.signer), a.scope, a.state, a.issued_at),
  escalation_digests: (a) => ({ policy_digest: escalationPolicyDigest(a.grant), action_digest: escalationActionDigest(a.pcactn), history_head: escalationHistoryHead(a.last_counter ?? undefined) }),
  sign_escalation_answer: (a) => signEscalationAnswer(a.body, sk(a.signer)),
  sign_discharge: (a) => signDischarge(a.body, sk(a.signer)),
  discharge_digest: (a) => ({ digest: dischargeDigest(a.discharge) }),
  sign_narrow: (a) => signNarrow(a.body, sk(a.signer)),
  sign_passport: (a) => {
    const passport = issuePassport(a.identity);
    return { passport, signed: signPassport(passport, { issuerSecret: sk(a.issuer), subject: pk(a.subject), exp: a.exp }) };
  },
  sign_workflow: (a) => signWorkflow(sk(a.signer), a.body),
  sign_step_receipt: (a) => signStepReceipt(sk(a.signer), { workflow: a.workflow, step: a.step, outcome: a.outcome, paramsDigest: a.params_digest, outputs: a.outputs, issuedAt: a.issued_at, ...(a.prev ? { prev: a.prev } : {}) }),
  sign_read_grant: (a) => signReadGrant(sk(a.signer), a.body),
  sign_aggregate_grant: (a) => signAggregateGrant(sk(a.signer), a.body),
  sign_revocation_epoch: (a) => signRevocationEpoch(sk(a.signer), a.body),
  sign_undo_token: (a) => signUndoToken(a.record, sk(a.signer)),
  sign_undo_receipt: (a) => signUndoReceipt(a.body, sk(a.signer)),
  sign_contract: (a) => signContract(a.contract, sk(a.signer)),
  sign_contract_reset: (a) => ({ sig: signContractReset(sk(a.signer), a.contract_id, a.seq) }),
  sign_constitution: (a) => signConstitution(a.constitution, sk(a.signer)),
  sign_safety_evidence: (a) => signSafetyEvidence(a.evidence, sk(a.signer), pk(a.signer)),
  sign_threshold_share: (a) => signShare(a.role, sk(a.signer), raw(a.message), { signerSet: a.signer_set, t: a.t }),
  sign_prepared_share: (a) => signPreparedShare(a.role, sk(a.signer), raw(a.prepared)),
  sign_pq_binding: (a) => signPqBinding(sk(a.signer), pk(a.signer), a.pq_pk, a.epoch, a.aud),
  sign_caution: (a) => signCaution(a.body, sk(a.signer)),
  sign_heartbeat: (a) => signHeartbeat(a.body, sk(a.signer)),
  prov_recorder: (a) => {
    let tick = 0;
    const r = createProvenanceRecorder({ mediator: a.mediator, kid: a.kid, secretKey: sk(a.key), session: a.session, now: () => a.clock[tick++] });
    const outs = a.steps.map((s: Args) =>
      s.kind === 'principal' ? r.principal(s.text) : s.kind === 'tool' ? r.tool(s.name, s.output) : s.kind === 'retrieval' ? r.retrieval(s.source, s.content) : s.kind === 'web' ? r.web(s.url, s.content) : r.forAction(s.op),
    );
    return { pin: r.pin, receipts: outs.slice(0, -1), bundle: outs[outs.length - 1] };
  },
  sign_mesh_action: (a) => ({ sig: signMeshAction(a.chain, a.action, sk(a.signer)) }),
  sign_session_root: (a) => signSessionRoot(a.body, sk(a.signer)),
  mint_session_grant: (a) => {
    const r = mintSessionGrant({ principalSecret: sk(a.principal), principalPublic: pk(a.principal), holder: pk(a.holder), session: a.session, seq: a.seq, ...(a.prev !== undefined ? { prev: a.prev } : {}), root: a.root, mapDigest: a.map_digest, ...(a.map_form ? { mapForm: a.map_form } : {}), predicates: a.predicates, ...(a.caveats ? { caveats: a.caveats } : {}), salt: a.salt });
    return { grant: r.grant, goal_salt: r.goalSalt };
  },
  sign_intent_required: (a) => signIntentRequired(a.body, a.kid, sk(a.signer)),
  sign_action_schema: (a) => signActionSchema(a.doc, a.kid, sk(a.signer)),
  sign_labels: (a) => signLabels(a.body, sk(a.signer)),
  sign_fact: (a) => signFact(a.body, sk(a.signer)),
  sign_offer_set: (a) => signOfferSet(a.body, sk(a.signer)),
  sign_progress_step: (a) => signProgressStep(a.step, sk(a.signer), pk(a.signer)),
  sign_read_receipt: (a) => signReadReceipt(sk(a.signer), { grant: a.grant, verb: a.verb, resource: a.resource, purpose: a.purpose, fields: a.fields, labels: a.labels, issuedAt: a.issued_at, ...(a.prev ? { prev: a.prev } : {}) }),
  sign_template: (a) => signTemplate(a.def, sk(a.signer), pk(a.signer)),
  sign_tighten: (a) => signTighten(a.overlay, sk(a.signer), pk(a.signer)),
  parse_limit: (a) => parseLimit(a.limit),
  compile_policy: (a) => {
    const { actions: _a, inputLimits: _i, ...rest } = compilePolicy({ permissions: a.permissions, limits: a.limits, budgetModel: a.budget_model, now: a.now });
    return rest;
  },
  facade_act: (a) => {
    const base = agent({ principal: kp(a.principal), goal: a.goal, goalSalt: a.goal_salt, permissions: a.permissions, limits: a.limits, holder: kp(a.holder), aud: a.aud, now: a.now, provenance: { secretKey: sk(a.recorder_key), session: a.session, now: () => a.now } });
    for (const t of a.principal_messages ?? []) base.provenance!.principal(t);
    const h = a.sub_agent ? base.subAgent({ holder: kp(a.sub_agent.holder), addedCaveats: a.sub_agent.added_caveats }) : base;
    const r = h.act(a.act.verb, a.act.resource, a.act.params, { counter: a.act.counter, now: a.act.now, ...(a.act.nonce !== undefined ? { nonce: a.act.nonce } : {}) });
    const env = base.grant.caveats[0] as Args;
    return { grant: base.grant, goal_commit: env.goal_commit, chain: h.chain, pcactn: r.pcactn, encoded: r.encoded, provenance: r.provenance };
  },
};

describe('producer vectors (fixed keys, exact outputs)', () => {
  for (const c of doc.cases) {
    it(c.name, () => {
      const got = json(orError(() => run[c.op]!(c.args)));
      const want = json(c.expect);
      if (c.op === 'act') delete (want as Args).threshold_message; // restated by the generator only; the native signers recompute it
      expect(got).toEqual(want);
    });
  }
  it('every op is covered', () => {
    for (const c of doc.cases) expect(run[c.op], c.op).toBeDefined();
  });
});
