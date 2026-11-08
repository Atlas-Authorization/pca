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

type Args = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const doc = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'producer-vectors.json'), 'utf8')) as {
  keys: Record<string, { seed: string; public: string }>;
  cases: Array<{ name: string; op: string; args: Args; expect: Args }>;
};
const sk = (name: string): Uint8Array => new Uint8Array(Buffer.from(doc.keys[name]!.seed, 'base64url'));
const pk = (name: string): string => doc.keys[name]!.public;
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

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
};

describe('producer vectors (fixed keys, exact outputs)', () => {
  for (const c of doc.cases) {
    it(c.name, () => {
      const got = json(run[c.op]!(c.args));
      const want = json(c.expect);
      if (c.op === 'act') delete (want as Args).threshold_message; // restated by the generator only; the native signers recompute it
      expect(got).toEqual(want);
    });
  }
  it('every op is covered', () => {
    for (const c of doc.cases) expect(run[c.op], c.op).toBeDefined();
  });
});
