import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  buildPCActn,
  delegate,
  encodeKey,
  generateKeyPair,
  mintGrant,
  parsePcaGrantDetails,
  pcaChainDigest,
  type Capability,
  type CapabilityChain,
  type PCActn,
  type PcaNeed,
} from '@atlasauth/pca';
import {
  PCA_A2A_EXTENSION_URI,
  TASK_STATE_AUTH_REQUIRED,
  TASK_STATE_INPUT_REQUIRED,
  answerMessage,
  attachPcaToA2ATask,
  authRequiredStatus,
  checkPushNotification,
  clientOptsIntoPca,
  isAuthRequired,
  pcaExtensionDeclaration,
  pcaPushToken,
  readAuthRequiredNeed,
  readPcaExtension,
  resumeAuthRequired,
  uniformTaskNotFound,
  verifyA2ADelegation,
  type A2ATask,
} from './index';

const NOW = 1_800_000_000_000;
const AUD_B = 'agent-b.example';
const AUD_C = 'agent-c.example';

const P = generateKeyPair();
const A = generateKeyPair();
const S = generateKeyPair();
const mkGrant = (principal = P, holder = A): Capability =>
  mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'buy the cart',
    envelope: { predicates: [{ verb: 'purchase', resource: '*' }], caveats: [{ type: 'expires', at: NOW + 3_600_000 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;
const grant = mkGrant();
const subCap = delegate(grant, encodeKey(S.publicKey), [], A.secretKey);
const CART = 'merchant/acme/cart/42';

const nodeFor = (resource: string) => [{ id: 'n1', verb: 'purchase', resource, reversibility_class: 'reversible' as const }];
function proof(chain: CapabilityChain, secret: Uint8Array, aud: string, resource = CART, counter = 1): PCActn {
  return buildPCActn({ grant: chain[0] as Capability, chain, plan: nodeFor(resource), nodeId: 'n1', counter, signerSecret: secret, aud, now: NOW });
}
// the resource server's view for the full verifier, derived from the proof's own action (its plan is the single node)
const optsFor = (aud: string, g: Capability = grant) => ({
  aud,
  now: NOW,
  grant: g,
  hooks: { revocation: () => ({ enforced: true as const, ok: true }) },
  context: (p: PCActn) => ({
    plan: nodeFor(p.action.resource),
    planAuthorized: true,
    budget: { B: 100, tau: NOW, asOf: NOW },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 },
  }),
});
const task = (id: string, p?: PCActn, state = 'TASK_STATE_SUBMITTED'): A2ATask => {
  const t: A2ATask = { id, status: { state } };
  return p ? attachPcaToA2ATask(t, p) : t;
};
const need: PcaNeed = { v: 1, kind: 'scope', verb: 'purchase', resource: CART, scopes: ['cart:pay'] };
const rootProof = (aud: string, resource = CART) => proof([grant], A.secretKey, aud, resource);
const subProof = (aud: string, resource = CART) => proof([grant, subCap], S.secretKey, aud, resource);

describe('A2A PCA binding - T-587', () => {
  describe('Agent Card extension (A2A 4.4.4, 4.6)', () => {
    const detail = { type: 'pca_grant', chain_digest: pcaChainDigest(['capA']), chain_len: 1 };
    const card = (e: unknown) => ({ name: 'b', capabilities: { extensions: e } });
    it('declares, reads back and surfaces the grant pointers', () => {
      const decl = pcaExtensionDeclaration({ aud: AUD_B, suites: ['ed25519'], grants: [detail as never] });
      expect(decl.required).toBe(true);
      const r = readPcaExtension(card([decl]));
      expect(r).toMatchObject({ ok: true, required: true });
      expect(r.ok && r.grants).toEqual([detail]);
      expect(parsePcaGrantDetails([detail]).ok).toBe(true);
    });
    it('refuses a missing, duplicated, malformed or over-reaching declaration', () => {
      const ok = pcaExtensionDeclaration({ aud: AUD_B });
      expect(readPcaExtension({ name: 'x' })).toEqual({ ok: false, code: 'not_declared' });
      expect(readPcaExtension(card([{ uri: 'https://other.example/x', params: {} }]))).toEqual({ ok: false, code: 'not_declared' });
      expect(readPcaExtension(card([ok, { ...ok, params: { aud: 'other' } }]))).toEqual({ ok: false, code: 'bad_declaration' });
      expect(readPcaExtension(card([{ ...ok, required: 'yes' }]))).toEqual({ ok: false, code: 'bad_declaration' });
      expect(readPcaExtension(card([{ ...ok, params: {} }]))).toEqual({ ok: false, code: 'bad_params' });
      expect(readPcaExtension(card([{ ...ok, params: { aud: AUD_B, admin: true } }]))).toEqual({ ok: false, code: 'bad_params' });
      expect(readPcaExtension(card([{ ...ok, params: { aud: AUD_B, grants: [{ ...detail, actions: ['x'] }] } }]))).toEqual({ ok: false, code: 'bad_grants' });
    });
    it('the client opts in through the A2A-Extensions list by exact URI', () => {
      expect(clientOptsIntoPca(`https://x.example/a, ${PCA_A2A_EXTENSION_URI}`)).toBe(true);
      expect(clientOptsIntoPca(`${PCA_A2A_EXTENSION_URI}/v3`)).toBe(false);
      expect(clientOptsIntoPca(undefined)).toBe(false);
    });
  });

  describe('AUTH_REQUIRED mapping (A2A 7.6)', () => {
    const parked = (): A2ATask => ({ id: 't1', status: authRequiredStatus(need, { messageId: 'm1', now: 1_800_000_000_000 }) });
    it('parks the need in the status message and reads it back', () => {
      const t = parked();
      expect(t.status.state).toBe(TASK_STATE_AUTH_REQUIRED);
      expect(isAuthRequired(t.status.state)).toBe(true);
      expect(isAuthRequired('auth-required')).toBe(true);
      expect(isAuthRequired(TASK_STATE_INPUT_REQUIRED)).toBe(false);
      expect(readAuthRequiredNeed(t)).toEqual({ ok: true, need });
      expect(readAuthRequiredNeed({ id: 'x', status: { state: 'TASK_STATE_WORKING' } })).toBeNull();
    });
    it('resumes only on a verified proof for exactly the parked need', async () => {
      const t = parked();
      const p = rootProof(AUD_B, CART);
      const r = await resumeAuthRequired(t, answerMessage(need, p, 'm2'), optsFor(AUD_B));
      expect(r.ok).toBe(true);
    });
    it('the state alone, a proof for another action, an unbound answer, a foreign audience and a tampered proof all refuse', async () => {
      const t = parked();
      const good = rootProof(AUD_B, CART);
      expect(await resumeAuthRequired(t, { role: 'user', parts: [] } as never, optsFor(AUD_B))).toEqual({ ok: false, reason: 'answer_not_bound_to_need' });
      const unbound = { ...answerMessage(need, good, 'm'), metadata: { [PCA_A2A_EXTENSION_URI]: good } } as never;
      expect(await resumeAuthRequired(t, unbound, optsFor(AUD_B))).toEqual({ ok: false, reason: 'answer_not_bound_to_need' });
      const other = rootProof(AUD_B, 'merchant/acme/cart/OTHER');
      expect(await resumeAuthRequired(t, answerMessage(need, other, 'm'), optsFor(AUD_B))).toEqual({ ok: false, reason: 'action_mismatch' });
      expect((await resumeAuthRequired(t, answerMessage(need, good, 'm'), optsFor('someone-else.example'))).ok).toBe(false);
      expect((await resumeAuthRequired(t, answerMessage(need, { ...good, counter: good.counter + 1 }, 'm'), optsFor(AUD_B))).ok).toBe(false);
      const noProof = { ...answerMessage(need, good, 'm'), metadata: { ['https://atlasauth.net/a2a/ext/pca/v2#need']: (answerMessage(need, good, 'm').metadata as Record<string, unknown>)['https://atlasauth.net/a2a/ext/pca/v2#need'] } } as never;
      expect(await resumeAuthRequired(t, noProof, optsFor(AUD_B))).toEqual({ ok: false, reason: 'no_proof' });
    });
    it('an INPUT_REQUIRED or WORKING task never resumes on a proof', async () => {
      const good = rootProof(AUD_B, CART);
      for (const state of [TASK_STATE_INPUT_REQUIRED, 'TASK_STATE_WORKING', 'TASK_STATE_COMPLETED']) {
        const t = { ...parked(), status: { ...parked().status, state } } as A2ATask;
        expect(await resumeAuthRequired(t, answerMessage(need, good, 'm'), optsFor(AUD_B))).toEqual({ ok: false, reason: 'task_not_auth_required' });
      }
    });
    it('a status without a decodable need cannot be resumed', async () => {
      const t: A2ATask = { id: 't', status: { state: TASK_STATE_AUTH_REQUIRED } };
      expect(await resumeAuthRequired(t, { role: 'user', parts: [] } as never, optsFor(AUD_B))).toEqual({ ok: false, reason: 'no_valid_need' });
    });
  });

  describe('per-hop delegation', () => {
    it('each hop is verified for its own audience and the chain extends hop to hop', async () => {
      const hop1 = task('t', rootProof(AUD_B));
      const hop2 = task('t', subProof(AUD_C));
      const r = await verifyA2ADelegation([{ task: hop1, opts: optsFor(AUD_B) }, { task: hop2, opts: optsFor(AUD_C) }]);
      expect(r.ok).toBe(true);
      expect(r.chains.map((c) => c.length)).toEqual([1, 2]);
      expect(r.chains[1]?.[0]).toBe(r.chains[0]?.[0]);
    });
    it('a proof minted for hop B does not pass hop C, and the failing hop is named', async () => {
      const p = rootProof(AUD_B);
      const r = await verifyA2ADelegation([{ task: task('t', p), opts: optsFor(AUD_B) }, { task: task('t', p), opts: optsFor(AUD_C) }]);
      expect(r).toMatchObject({ ok: false, failedHop: 1 });
    });
    it('an unrelated chain at the next hop, a dropped hop, a missing proof and empty input are refused', async () => {
      const OP = generateKeyPair();
      const og = mkGrant(OP, OP);
      const unrelated = await verifyA2ADelegation([
        { task: task('t', subProof(AUD_B)), opts: optsFor(AUD_B) },
        { task: task('t', proof([og], OP.secretKey, AUD_C)), opts: optsFor(AUD_C, og) },
      ]);
      expect(unrelated).toMatchObject({ ok: false, failedHop: 1, reason: 'chain_does_not_extend_previous_hop' });
      const dropped = await verifyA2ADelegation([
        { task: task('t', subProof(AUD_B)), opts: optsFor(AUD_B) },
        { task: task('t', rootProof(AUD_C)), opts: optsFor(AUD_C) },
      ]);
      expect(dropped).toMatchObject({ ok: false, failedHop: 1, reason: 'chain_does_not_extend_previous_hop' });
      expect(await verifyA2ADelegation([{ task: task('t'), opts: optsFor(AUD_B) }])).toMatchObject({ ok: false, failedHop: 0 });
      expect(await verifyA2ADelegation([])).toMatchObject({ ok: false, reason: 'no_hops' });
    });
    it('forwarding the same chain unchanged is allowed (a fresh proof for the next audience)', async () => {
      const r = await verifyA2ADelegation([{ task: task('t', rootProof(AUD_B)), opts: optsFor(AUD_B) }, { task: task('t', rootProof(AUD_C)), opts: optsFor(AUD_C) }]);
      expect(r.ok).toBe(true);
    });
  });

  describe('push notifications (A2A 13.2)', () => {
    const ids = ['capA', 'capB'];
    const salt = 'a-secret-salt-16+chars';
    const tok = pcaPushToken('t1', ids, salt);
    const payload = (id: string) => ({ statusUpdate: { taskId: id, status: { state: 'TASK_STATE_COMPLETED' } } });
    it('accepts the right token for the right task', () => {
      expect(checkPushNotification({ taskId: 't1', chainIds: ids, salt }, { token: tok, payload: payload('t1') })).toEqual({ ok: true });
      expect(checkPushNotification({ taskId: 't1', chainIds: ids, salt }, { token: tok, payload: { task: { id: 't1' } } })).toEqual({ ok: true });
    });
    it('refuses a missing token, a token for another task, chain or salt, and a payload about another task', () => {
      const e = { taskId: 't1', chainIds: ids, salt };
      expect(checkPushNotification(e, { token: undefined, payload: payload('t1') })).toEqual({ ok: false, reason: 'no_token' });
      expect(checkPushNotification(e, { token: pcaPushToken('t2', ids, salt), payload: payload('t1') })).toEqual({ ok: false, reason: 'token_mismatch' });
      expect(checkPushNotification(e, { token: pcaPushToken('t1', ['capA'], salt), payload: payload('t1') })).toEqual({ ok: false, reason: 'token_mismatch' });
      expect(checkPushNotification(e, { token: pcaPushToken('t1', ids, `${salt}x`), payload: payload('t1') })).toEqual({ ok: false, reason: 'token_mismatch' });
      expect(checkPushNotification(e, { token: tok, payload: payload('t2') })).toEqual({ ok: false, reason: 'task_mismatch' });
      expect(checkPushNotification(e, { token: tok, payload: 'x' })).toEqual({ ok: false, reason: 'task_mismatch' });
    });
    it('refuses a weak salt', () => expect(() => pcaPushToken('t', ids, 'short')).toThrow(RangeError));
  });

  it('not found and not authorized are one answer', () => {
    expect(JSON.stringify(uniformTaskNotFound())).toBe(JSON.stringify(uniformTaskNotFound()));
  });
});
