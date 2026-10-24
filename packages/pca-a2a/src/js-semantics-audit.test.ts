/**
 * Regressions for the 2026-10-12 JavaScript-semantics audit: every A2A verification surface is total over hostile shapes
 * (a refusal, never an exception), and a non-array `history` is never walked through its own `length`. Each expectation
 * also kills the mutant that reverts the fix.
 */
import { describe, expect, it } from 'vitest';
import { type PCActn, pcactnDigest } from '@atlasauth/pca';
import {
  type A2AMessage,
  type A2APaymentMandate,
  type A2ATask,
  type AgentCard,
  PCA_A2A_EXTENSION_URI,
  extractPca,
  extractPcaFromMessage,
  pcaA2AMiddleware,
  verifyA2APaymentMandate,
  verifyA2ATask,
  verifyAgentCard,
} from './index';

const opts = { aud: 'rs', expectedRootIssuer: 'principal' };
const fakePca = { ver: 2 } as unknown as PCActn;

describe('extractPca / extractPcaFromMessage are total', () => {
  it('a task without status, a null task and a null message yield no proof instead of throwing', () => {
    expect(extractPca({ id: 't' } as unknown as A2ATask)).toBeUndefined();
    expect(extractPca({ id: 't', status: null } as unknown as A2ATask)).toBeUndefined();
    expect(extractPca(null as unknown as A2ATask)).toBeUndefined();
    expect(extractPca(undefined as unknown as A2ATask)).toBeUndefined();
    expect(extractPcaFromMessage(null as unknown as A2AMessage)).toBeUndefined();
    expect(extractPcaFromMessage(undefined as unknown as A2AMessage)).toBeUndefined();
  });
  it('a proof is still read from the status message and from a real history array', () => {
    const meta = { [PCA_A2A_EXTENSION_URI]: fakePca };
    expect(extractPca({ id: 't', status: { state: 's', message: { metadata: meta } } } as unknown as A2ATask)).toBe(fakePca);
    expect(extractPca({ id: 't', status: { state: 's' }, history: [{ metadata: meta }] } as unknown as A2ATask)).toBe(fakePca);
  });
  it('a non-array history with an own length is not walked (it used to be read index by index)', () => {
    const history = { length: 1, 0: { metadata: { [PCA_A2A_EXTENSION_URI]: fakePca } } };
    expect(extractPca({ id: 't', status: { state: 's' }, history } as unknown as A2ATask)).toBeUndefined();
    expect(extractPca({ id: 't', status: { state: 's' }, history: 'xyz' } as unknown as A2ATask)).toBeUndefined();
  });
  it('the task verifier and the guard deny a status-less task cleanly', async () => {
    expect(await verifyA2ATask({ id: 't' } as unknown as A2ATask, opts)).toEqual({ ok: false, reason: 'no proof-carrying action attached to this task' });
    expect(await pcaA2AMiddleware(opts)({ id: 't' } as unknown as A2ATask)).toEqual({ ok: false, reason: 'proof-carrying action required but none attached to task' });
  });
});

describe('verifyAgentCard is total', () => {
  const key = new Uint8Array(32).fill(7);
  it('a non-object card is refused', async () => {
    expect(await verifyAgentCard(null as unknown as AgentCard, { key })).toEqual({ ok: false, reason: 'agent card is not an object' });
    expect(await verifyAgentCard('card' as unknown as AgentCard, { key })).toEqual({ ok: false, reason: 'agent card is not an object' });
  });
  it('a card with no strict canonical form (a 1e21 number) is refused, not thrown', async () => {
    const card = { name: 'n', big: 1e21, signatures: [{ protected: 'e30', signature: 'AA' }] } as unknown as AgentCard;
    const r = await verifyAgentCard(card, { key });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^agent card has no canonical form: /);
  });
});

describe('verifyA2APaymentMandate is total', () => {
  it('a mandate without credentialSubject.x_pca is refused, not thrown', async () => {
    const r = await verifyA2APaymentMandate({} as unknown as A2APaymentMandate, fakePca, opts);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^malformed payment mandate or PCActn: /);
  });
  it('a PCActn with no strict canonical form is refused, not thrown', async () => {
    const m = { credentialSubject: { x_pca: { pcactn_digest: 'x' } } } as unknown as A2APaymentMandate;
    const r = await verifyA2APaymentMandate(m, { ver: 2, n: 1e21 } as unknown as PCActn, opts);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^malformed payment mandate or PCActn: /);
  });
  it('a mandate bound to the digest of a null PCActn is refused at the PCActn, not thrown', async () => {
    const m = { credentialSubject: { x_pca: { pcactn_digest: pcactnDigest(null as unknown as PCActn) } } } as unknown as A2APaymentMandate;
    expect(await verifyA2APaymentMandate(m, null as unknown as PCActn, opts)).toEqual({ ok: false, reason: 'PCActn is not an object' });
    const five = { credentialSubject: { x_pca: { pcactn_digest: pcactnDigest(5 as unknown as PCActn) } } } as unknown as A2APaymentMandate;
    expect(await verifyA2APaymentMandate(five, 5 as unknown as PCActn, opts)).toEqual({ ok: false, reason: 'PCActn is not an object' });
  });
});
