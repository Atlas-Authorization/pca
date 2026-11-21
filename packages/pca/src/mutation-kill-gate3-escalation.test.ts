/**
 * Mutation kills for the 0.5.0 flagship gate survivors in escalation.ts: a request built for a null PCActn or one with no
 * action, a request without a render digest carries no render_digest member, the zero-time bounds of an answer, a
 * malformed render_digest, pinned-principal lists holding null / undefined, the two render-binding refusals, and the
 * fail-closed catch (an Error and a non-Error throw).
 */
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { buildEscalationRequest, escalationAnswerShapeError, signEscalationAnswer, verifyEscalationAnswer, type EscalationAnswerBody } from './escalation';

const NOW = 1_800_000_000_000;
const k = generateKeyPair();
const pub = encodeKey(k.publicKey);
const dg = (c: string) => b64u(new Uint8Array(32).fill(c.charCodeAt(0)));
const body = (o: Partial<EscalationAnswerBody> = {}): EscalationAnswerBody => ({
  v: 1, kind: 'pca-escalation-answer', principal: pub, policy_digest: dg('a'), action_digest: dg('b'), history_head: dg('c'), decision: 'allow', iat: NOW, expires_at: NOW + 1000, nonce: b64u(new Uint8Array(16).fill(7)), ...o,
});
const bind = { policy_digest: dg('a'), action_digest: dg('b'), history_head: dg('c') };
const sign = (o: Partial<EscalationAnswerBody> = {}) => signEscalationAnswer(body(o), k.secretKey);

describe('escalation.ts: buildEscalationRequest', () => {
  const grant = { id: 'g' } as never;
  it('a null PCActn or one without an action yields the string "undefined" (never a throw)', () => {
    const r1 = buildEscalationRequest({ aud: 'a', grant, pcactn: null as never, lastCounter: undefined, reasons: [], now: NOW });
    expect([r1.verb, r1.resource]).toEqual(['undefined', 'undefined']);
    const r2 = buildEscalationRequest({ aud: 'a', grant, pcactn: {} as never, lastCounter: undefined, reasons: [], now: NOW });
    expect([r2.verb, r2.resource]).toEqual(['undefined', 'undefined']);
  });
  it('render_digest is present only when given', () => {
    const pcactn = { action: { verb: 'v', resource: 'r' } } as never;
    const r = buildEscalationRequest({ aud: 'a', grant, pcactn, lastCounter: 1, reasons: [], now: NOW });
    expect(Object.keys(r)).not.toContain('render_digest');
    expect(buildEscalationRequest({ aud: 'a', grant, pcactn, lastCounter: 1, reasons: [], now: NOW, renderDigest: dg('r') }).render_digest).toBe(dg('r'));
  });
});

describe('escalation.ts: answer shape bounds', () => {
  const e = (o: object) => escalationAnswerShapeError({ ...body(), sig: 'x', ...o });
  it('iat = 0 is a valid lower bound; expires_at = 0 fails the ordering check, a negative expires_at the sign check', () => {
    expect(e({ iat: 0, expires_at: 5 })).toBeNull();
    expect(e({ iat: 0, expires_at: 0 })).toBe('expires_at must be greater than iat');
    expect(e({ iat: 0, expires_at: -1 })).toBe('iat and expires_at must be non-negative safe integers');
  });
  it('a malformed render_digest is refused by name', () => {
    expect(e({ render_digest: 'x' })).toBe('render_digest must be canonical base64url (32 bytes)');
    expect(e({ render_digest: dg('r') })).toBeNull();
  });
});

describe('escalation.ts: verifyEscalationAnswer', () => {
  it('null and undefined entries in the pinned list are skipped, not dereferenced', () => {
    expect(verifyEscalationAnswer(sign(), [null, undefined, pub] as never, bind, NOW)).toEqual({ ok: true, principal: pub, decision: 'allow' });
  });
  it('a render-bound verifier refuses an answer without a render digest and one for another render', () => {
    const rb = { ...bind, render_digest: dg('r') };
    expect(verifyEscalationAnswer(sign(), [pub], rb, NOW)).toEqual({ ok: false, reason: 'the answer is not bound to the canonical approval render' });
    expect(verifyEscalationAnswer(sign({ render_digest: dg('s') }), [pub], rb, NOW)).toEqual({ ok: false, reason: 'the answer was given for another approval render' });
    expect(verifyEscalationAnswer(sign({ render_digest: dg('r') }), [pub], rb, NOW)).toEqual({ ok: true, principal: pub, decision: 'allow' });
  });
  it('a throw inside the check is a fail-closed refusal naming the error, or unknown for a non-Error', () => {
    const a = sign();
    const boom = { get pk(): string { throw new Error('boom'); } };
    expect(verifyEscalationAnswer(a, [boom] as never, bind, NOW)).toEqual({ ok: false, reason: 'escalation answer error (fail closed): boom' });
    const raw = { get pk(): string { throw 'raw'; } };
    expect(verifyEscalationAnswer(a, [raw] as never, bind, NOW)).toEqual({ ok: false, reason: 'escalation answer error (fail closed): unknown' });
  });
});
