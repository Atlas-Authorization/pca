import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, readEnvelope } from '@atlasauth/pca';
import { ingestText } from './ingest';
import { buildPasskeyApproval, passkeyChallenge, requestPasskeyApproval } from './passkey';
import { issueGrant, verifyApproval } from './signoff';
import { propose } from './synth';
import { verifyProposal } from './verify';
import { NOW, benign, jsonl, row } from './test-support/fixtures';
import { ORIGIN, RP, authenticator } from './test-support/webauthn';

const world = async () => {
  const s = ingestText(jsonl([...benign(), row(30, { verb: 'gmail.delete', resource: '/drafts/1', params: {} })]));
  const p = propose(s, { now: NOW });
  const r = await verifyProposal(p, s);
  return { s, p, r };
};
const opts = (a: ReturnType<typeof authenticator>, over: Record<string, unknown> = {}) => ({ principals: ['alice'], now: NOW + 1000, credentials: { alice: a.publicKey }, rpId: RP, origins: [ORIGIN], storedSignCount: () => 0, ...over });

describe('passkey approval', () => {
  it('a user-verified passkey over the approval commitment is accepted, the grant carries exactly the proposal, and the new counter is returned', async () => {
    const { p, r } = await world();
    const a = authenticator();
    const approval = await requestPasskeyApproval(p, r, { principal: 'alice', at: NOW, rpId: RP, credentials: a.credentials as never });
    expect(approval.method).toBe('passkey');
    const ok = verifyApproval(approval, p, r, opts(a));
    expect(ok).toEqual({ ok: true, principal: 'alice', method: 'passkey', signCount: 1 });
    const issuer = generateKeyPair();
    const g = issueGrant(p, r, approval, { ...opts(a), principalSecret: issuer.secretKey, holder: b64u(generateKeyPair().publicKey), goal: 'g' });
    expect(readEnvelope(g.grant)!.predicates).toEqual(p.policy.predicates);
    expect(g.approvedBy).toBe('alice');
  });

  it('the challenge binds proposal, report, confirmations and expiry', async () => {
    const { p, r } = await world();
    const c = (o: Record<string, unknown>) => Buffer.from(passkeyChallenge(p, r, { principal: 'alice', at: NOW, ...o }).challenge).toString('hex');
    expect(c({})).toBe(c({}));
    expect(c({ ttlMs: 60_000 })).not.toBe(c({}));
    expect(c({ at: NOW + 1 })).not.toBe(c({}));
  });

  it('refuses an assertion made for a different proposal, a different report or different confirmations', async () => {
    const { s, p, r } = await world();
    const a = authenticator();
    const approval = await requestPasskeyApproval(p, r, { principal: 'alice', at: NOW, rpId: RP, credentials: a.credentials as never });
    const p2 = propose(s, { now: NOW, margin: 0.5 });
    expect(verifyApproval(approval, p2, await verifyProposal(p2, s), opts(a)).ok).toBe(false);
    expect(verifyApproval({ ...approval, expires_at: approval.expires_at + 1 }, p, r, opts(a)).ok).toBe(false); // challenge covers the expiry
    expect(verifyApproval({ ...approval, confirmed: ['x'] }, p, r, opts(a)).ok).toBe(false);
  });

  it('refuses a touch without user verification, a wrong origin or ceremony type, a counter that did not advance, an unknown credential and an expired approval', async () => {
    const { p, r } = await world();
    const mk = async (o: Parameters<typeof authenticator>[0]) => { const a = authenticator(o); return { a, approval: await requestPasskeyApproval(p, r, { principal: 'alice', at: NOW, rpId: RP, credentials: a.credentials as never }) }; };
    const noUv = await mk({ flags: 0x01 });
    expect(verifyApproval(noUv.approval, p, r, opts(noUv.a)).ok).toBe(false);
    const origin = await mk({ origin: 'https://evil.example.com' });
    expect(verifyApproval(origin.approval, p, r, opts(origin.a)).ok).toBe(false);
    const create = await mk({ type: 'webauthn.create' });
    expect(verifyApproval(create.approval, p, r, opts(create.a)).ok).toBe(false);
    const ctr = await mk({ signCount: 5 });
    expect(verifyApproval(ctr.approval, p, r, opts(ctr.a, { storedSignCount: () => 5 })).ok).toBe(false);
    const good = await mk({});
    expect(verifyApproval(good.approval, p, r, opts(good.a, { credentials: { alice: authenticator().publicKey } })).ok).toBe(false);
    expect(verifyApproval(good.approval, p, r, opts(good.a, { principals: ['mallory'] })).ok).toBe(false);
    expect(verifyApproval(good.approval, p, r, opts(good.a, { now: NOW + 16 * 60_000 })).ok).toBe(false);
  });

  it('refuses to build an approval for a report that did not pass, and without a credentials API', async () => {
    const { p, r } = await world();
    expect(() => buildPasskeyApproval(p, { ...r, ok: false }, { authenticatorData: new Uint8Array(1), clientDataJSON: new Uint8Array(1), signature: new Uint8Array(1) }, { principal: 'alice', at: NOW })).toThrow();
    await expect(requestPasskeyApproval(p, r, { principal: 'alice', at: NOW, rpId: RP })).rejects.toThrow(/credentials API/);
    await expect(requestPasskeyApproval(p, r, { principal: 'alice', at: NOW, rpId: RP, credentials: { get: async () => null } })).rejects.toThrow(/cancelled/);
  });
});
