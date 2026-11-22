import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  buildPCActn,
  delegate,
  encodeKey,
  encodePcaNeed,
  generateKeyPair,
  mintGrant,
  type Capability,
  type CapabilityChain,
  type PCActn,
  type PcaNeed,
} from '@atlasauth/pca';
import {
  PCA_A2A_EXTENSION_URI,
  answerMessage,
  attachPcaToA2ATask,
  authRequiredStatus,
  chainExtends,
  checkChainExtension,
  checkPushNotification,
  pcaExtensionDeclaration,
  pcaPushToken,
  readAuthRequiredNeed,
  readPcaExtension,
  resumeAuthRequired,
  resumeGate,
  uniformTaskNotFound,
  verifyA2ADelegation,
  verifyA2ATask,
  type A2ATask,
} from './index';

const URI = PCA_A2A_EXTENSION_URI;
const card = (ext: unknown) => ({ capabilities: { extensions: [ext] } });
const ext = (params: unknown, extra: Record<string, unknown> = {}) => ({ uri: URI, params, ...extra });
const bad = (code: string) => ({ ok: false, code });

describe('pcaExtensionDeclaration', () => {
  it('carries the fixed description and defaults to required', () => {
    expect(pcaExtensionDeclaration({ aud: 'a' })).toEqual({ uri: URI, description: 'Per-action proofs of authority (PCActn) on tasks and messages', required: true, params: { aud: 'a' } });
    expect(pcaExtensionDeclaration({ aud: 'a' }, false).required).toBe(false);
  });
});

describe('readPcaExtension', () => {
  it('reads a minimal declaration with no grants and required defaulting to false', () => {
    const r = readPcaExtension(card(ext({ aud: 'a' })));
    expect(r).toStrictEqual({ ok: true, required: false, params: { aud: 'a' }, grants: [] });
    expect(readPcaExtension(card(ext({ aud: 'a' }, { required: false })))).toMatchObject({ ok: true, required: false });
    expect(readPcaExtension(card(ext({ aud: 'a' }, { required: true })))).toMatchObject({ ok: true, required: true });
  });
  it('is total over hostile cards', () => {
    for (const c of [null, undefined, 5, {}, { capabilities: null }, { capabilities: {} }, { capabilities: { extensions: 'x' } }, card(null), { capabilities: { extensions: [null] } }]) {
      expect(readPcaExtension(c)).toEqual(bad('not_declared'));
    }
    expect(readPcaExtension({ capabilities: { extensions: [null, ext({ aud: 'a' })] } })).toMatchObject({ ok: true });
    expect(readPcaExtension({ capabilities: { extensions: [{ uri: 'other', params: {} }] } })).toEqual(bad('not_declared'));
  });
  it('refuses two declarations and a non-boolean required', () => {
    expect(readPcaExtension({ capabilities: { extensions: [ext({ aud: 'a' }), ext({ aud: 'b' })] } })).toEqual(bad('bad_declaration'));
    for (const required of ['yes', 1, null]) expect(readPcaExtension(card(ext({ aud: 'a' }, { required })))).toEqual(bad('bad_declaration'));
  });
  it('audience and parameter names are bounded', () => {
    for (const p of [undefined, null, [], 'x', {}, { aud: 5 }, { aud: '' }, { aud: 'a'.repeat(513) }, { aud: 'a', extra: 1 }]) expect(readPcaExtension(card(ext(p)))).toEqual(bad('bad_params'));
    expect(readPcaExtension(card(ext({ aud: 'a'.repeat(512) })))).toMatchObject({ ok: true });
  });
  it('suites are at most 16 strings of 1..64 characters', () => {
    const s = (suites: unknown) => readPcaExtension(card(ext({ aud: 'a', suites })));
    for (const suites of ['x', null, {}, Array.from({ length: 17 }, () => 'a'), ['a', 5], [5], [''], ['a'.repeat(65)], ['ok', '']]) expect(s(suites)).toEqual(bad('bad_params'));
    expect(s(Array.from({ length: 16 }, () => 'a'))).toMatchObject({ ok: true });
    expect(s(['a'.repeat(64), 'a'])).toMatchObject({ ok: true });
    expect(s([])).toMatchObject({ ok: true });
  });
  it('policy_digest is a string of 1..128 characters', () => {
    const d = (policy_digest: unknown) => readPcaExtension(card(ext({ aud: 'a', policy_digest })));
    for (const v of [5, '', null, 'x'.repeat(129)]) expect(d(v)).toEqual(bad('bad_params'));
    expect(d('x'.repeat(128))).toMatchObject({ ok: true });
    expect(d('x')).toMatchObject({ ok: true });
  });
  it('malformed grants are bad_grants', () => {
    expect(readPcaExtension(card(ext({ aud: 'a', grants: 'nope' })))).toEqual(bad('bad_grants'));
  });
});

describe('AUTH_REQUIRED mapping', () => {
  const need: PcaNeed = { v: 1, kind: 'scope', verb: 'purchase', resource: 'cart/1', scopes: ['cart:pay'] };
  it('reports the need error before any other argument error', () => {
    const badNeed = { ...need, verb: '' } as PcaNeed;
    let want = '';
    try {
      encodePcaNeed(badNeed);
    } catch (e) {
      want = (e as Error).message;
    }
    expect(want).not.toBe('');
    expect(() => authRequiredStatus(badNeed, { messageId: 'm', now: Number.NaN })).toThrow(want);
  });
  it('resumeGate returns the first refusal in order', () => {
    const enc = encodePcaNeed(need);
    expect(resumeGate({ state: 'TASK_STATE_WORKING', needEncoded: enc, answerNeedDigest: 'x', proofAction: undefined })).toBe('task_not_auth_required');
    expect(resumeGate({ state: 'TASK_STATE_AUTH_REQUIRED', needEncoded: undefined, answerNeedDigest: 'x', proofAction: undefined })).toBe('no_valid_need');
    expect(resumeGate({ state: 'TASK_STATE_AUTH_REQUIRED', needEncoded: 'zz', answerNeedDigest: 'x', proofAction: undefined })).toBe('no_valid_need');
    expect(readAuthRequiredNeed({ status: { message: { metadata: {} } } })).toBeNull();
  });
  it('chain extension: prefix rules and the shape of the refusal', () => {
    expect(chainExtends(['a'], ['a'])).toBe(true);
    expect(chainExtends(['a', 'b'], ['a'])).toBe(false);
    expect(chainExtends(['a'], ['a', 'b'])).toBe(true);
    expect(chainExtends(['a'], ['b', 'a'])).toBe(false);
    expect(checkChainExtension([['a'], ['a', 'b']])).toEqual({ ok: true });
    expect(checkChainExtension([['a'], []])).toEqual({ ok: false, failedHop: 1, reason: 'no_chain' });
    expect(checkChainExtension([[], ['a']])).toEqual({ ok: false, failedHop: 0, reason: 'no_chain' });
    expect(checkChainExtension([['a'], null as never])).toEqual({ ok: false, failedHop: 1, reason: 'no_chain' });
    expect(checkChainExtension([['a', 'b'], ['a']])).toEqual({ ok: false, failedHop: 1, reason: 'chain_does_not_extend_previous_hop' });
  });
});

describe('push notification tokens', () => {
  const SALT = 's'.repeat(16);
  it('the salt must be a string of at least 16 characters', () => {
    const msg = 'pcaPushToken: the salt must be a secret of at least 16 characters';
    for (const salt of [undefined, 5, '', 's'.repeat(15)]) {
      let err: Error | undefined;
      try {
        pcaPushToken('t', ['c'], salt as never);
      } catch (e) {
        err = e as Error;
      }
      expect(err).toBeInstanceOf(RangeError);
      expect(err!.message).toBe(msg);
    }
    expect(() => pcaPushToken('t', ['c'], SALT)).not.toThrow();
  });
  it('a truncated or extended token is a mismatch, never a prefix match', () => {
    const exp = { taskId: 't', chainIds: ['c'], salt: SALT };
    const token = pcaPushToken('t', ['c'], SALT);
    const payload = { task: { id: 't' } };
    expect(checkPushNotification(exp, { token, payload })).toEqual({ ok: true });
    expect(checkPushNotification(exp, { token: token.slice(0, -1), payload })).toEqual({ ok: false, reason: 'token_mismatch' });
    expect(checkPushNotification(exp, { token: token.slice(0, 10), payload })).toEqual({ ok: false, reason: 'token_mismatch' });
    expect(checkPushNotification(exp, { token: `${token}x`, payload })).toEqual({ ok: false, reason: 'token_mismatch' });
    expect(checkPushNotification(exp, { token: undefined, payload })).toEqual({ ok: false, reason: 'no_token' });
    expect(checkPushNotification(exp, { token: '', payload })).toEqual({ ok: false, reason: 'no_token' });
    expect(checkPushNotification(exp, { token, payload: { statusUpdate: { taskId: 't' } } })).toEqual({ ok: true });
    expect(checkPushNotification(exp, { token, payload: { task: { id: 'other' } } })).toEqual({ ok: false, reason: 'task_mismatch' });
  });
  it('uniformTaskNotFound is one fixed error', () => {
    expect(uniformTaskNotFound()).toStrictEqual({ code: 'TaskNotFoundError', message: 'task not found' });
  });
});

// ---- full verifier paths -------------------------------------------------------------------------------------------

const NOW = 1_800_000_000_000;
const AUD_B = 'agent-b.example';
const AUD_C = 'agent-c.example';
const P = generateKeyPair();
const A = generateKeyPair();
const S = generateKeyPair();
const grant: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'buy the cart',
  envelope: { predicates: [{ verb: 'purchase', resource: '*' }], caveats: [{ type: 'expires', at: NOW + 3_600_000 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;
const subCap = delegate(grant, encodeKey(S.publicKey), [], A.secretKey);
const CART = 'merchant/acme/cart/42';
const nodeFor = (resource: string) => [{ id: 'n1', verb: 'purchase', resource, reversibility_class: 'reversible' as const }];
const proof = (chain: CapabilityChain, secret: Uint8Array, aud: string, resource = CART): PCActn =>
  buildPCActn({ grant: chain[0] as Capability, chain, plan: nodeFor(resource), nodeId: 'n1', counter: 1, signerSecret: secret, aud, now: NOW });
const optsFor = (aud: string) => ({
  aud,
  now: NOW,
  grant,
  hooks: { revocation: () => ({ enforced: true as const, ok: true }) },
  context: (p: PCActn) => ({
    plan: nodeFor(p.action.resource),
    planAuthorized: true,
    budget: { B: 100, tau: NOW, asOf: NOW },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 },
  }),
});
const taskOf = (id: string, p?: PCActn): A2ATask => (p ? attachPcaToA2ATask({ id, status: { state: 'TASK_STATE_SUBMITTED' } }, p) : { id, status: { state: 'TASK_STATE_SUBMITTED' } });

describe('resumeAuthRequired', () => {
  const need: PcaNeed = { v: 1, kind: 'scope', verb: 'purchase', resource: CART, scopes: ['cart:pay'] };
  const parked = (): A2ATask => ({ id: 't1', status: authRequiredStatus(need, { messageId: 'm1', now: NOW }) as never });

  it('a missing task or status is a refusal, not an exception', async () => {
    const p = proof([grant], A.secretKey, AUD_B);
    const answer = answerMessage(need, p, 'm2');
    for (const t of [undefined, null, {}, { id: 't1' }, { id: 't1', status: null }]) {
      expect(await resumeAuthRequired(t as never, answer, optsFor(AUD_B))).toEqual({ ok: false, reason: 'task_not_auth_required' });
    }
  });
  it('resumes on a proof for the parked need and reports the verifier reason when the proof fails', async () => {
    const p = proof([grant], A.secretKey, AUD_B);
    const answer = answerMessage(need, p, 'm2');
    const ok = await resumeAuthRequired(parked(), answer, optsFor(AUD_B));
    expect(ok.ok).toBe(true);
    const wrongAud = optsFor(AUD_C);
    const want = (await verifyA2ATask(attachPcaToA2ATask({ id: 't1', status: { state: 'TASK_STATE_WORKING' } }, p), wrongAud)).reason;
    expect(want).toBeTruthy();
    const bad = await resumeAuthRequired(parked(), answer, wrongAud);
    expect(bad).toEqual({ ok: false, reason: want });
  });
});

describe('verifyA2ADelegation', () => {
  it('returns the capability ids of each verified hop, and the verifier reason on a failing hop', async () => {
    const p1 = proof([grant], A.secretKey, AUD_B);
    const p2 = proof([grant, subCap], S.secretKey, AUD_C);
    const ok = await verifyA2ADelegation([
      { task: taskOf('t1', p1), opts: optsFor(AUD_B) },
      { task: taskOf('t2', p2), opts: optsFor(AUD_C) },
    ]);
    expect(ok).toEqual({ ok: true, chains: [[grant.id], [grant.id, subCap.id]] });
    const want = (await verifyA2ATask(taskOf('t2', p2), optsFor(AUD_B))).reason;
    expect(want).toBeTruthy();
    const bad = await verifyA2ADelegation([
      { task: taskOf('t1', p1), opts: optsFor(AUD_B) },
      { task: taskOf('t2', p2), opts: optsFor(AUD_B) },
    ]);
    expect(bad).toEqual({ ok: false, failedHop: 1, reason: want, chains: [[grant.id]] });
    expect(await verifyA2ADelegation([])).toEqual({ ok: false, reason: 'no_hops', chains: [] });
  });
});
