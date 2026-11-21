import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { generateKeyPair, sign } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import {
  MAX_SAFETY_CHECKS,
  issueSafetyCertificate,
  safetyCertificateMessage,
  validateSafetyChecks,
  verifySafetyCertificate,
  type SafetyCertificate,
  type SafetyCheck,
} from './safety-certificate';

const chk = (over: Record<string, unknown> = {}): SafetyCheck => ({ id: 'fuzz', status: 'passed', evidence: { kind: 'url', ref: 'https://ci.example.com/run/1' }, at: 100, ...over }) as SafetyCheck;
const URL_ERR = "check 'fuzz' evidence URL must be a plain https URL";
const HEX_ERR = "check 'fuzz' evidence digest is not 64 lowercase hex";

describe('validateSafetyChecks: boundaries and each condition on its own', () => {
  it('exactly MAX_SAFETY_CHECKS checks is allowed', () => {
    expect(validateSafetyChecks(Array.from({ length: MAX_SAFETY_CHECKS }, (_, i) => chk({ id: `c${i}` })))).toBeNull();
  });
  it('a non-null primitive entry is "not an object"', () => {
    expect(validateSafetyChecks([5])).toBe('check is not an object');
    expect(validateSafetyChecks(['x'])).toBe('check is not an object');
  });
  it('a non-string id is refused even when it has no length', () => {
    expect(validateSafetyChecks([chk({ id: 5 })])).toBe('check id must be a 1..64 char string');
  });
  it('an id of exactly 64 chars and a time of exactly 0 are allowed', () => {
    expect(validateSafetyChecks([chk({ id: 'x'.repeat(64) })])).toBeNull();
    expect(validateSafetyChecks([chk({ at: 0 })])).toBeNull();
  });
  it('evidence null, or a non-string ref, is "no evidence link"', () => {
    expect(validateSafetyChecks([chk({ evidence: null })])).toBe("check 'fuzz' has no evidence link");
    expect(validateSafetyChecks([chk({ evidence: { kind: 'sha256', ref: 5 } })])).toBe("check 'fuzz' has no evidence link");
    expect(validateSafetyChecks([chk({ evidence: { kind: 'url', ref: 5 } })])).toBe("check 'fuzz' has no evidence link");
  });
  it('a digest must be the WHOLE ref (anchored at both ends)', () => {
    expect(validateSafetyChecks([chk({ evidence: { kind: 'sha256', ref: 'a'.repeat(64) } })])).toBeNull();
    expect(validateSafetyChecks([chk({ evidence: { kind: 'sha256', ref: `x${'a'.repeat(64)}` } })])).toBe(HEX_ERR);
    expect(validateSafetyChecks([chk({ evidence: { kind: 'sha256', ref: `${'a'.repeat(64)}x` } })])).toBe(HEX_ERR);
  });
  it('a URL of exactly 2048 chars is allowed, 2049 is not', () => {
    const base = 'https://ci.example.com/';
    const at = (n: number) => base + 'a'.repeat(n - base.length);
    expect(at(2048)).toHaveLength(2048);
    expect(validateSafetyChecks([chk({ evidence: { kind: 'url', ref: at(2048) } })])).toBeNull();
    expect(validateSafetyChecks([chk({ evidence: { kind: 'url', ref: at(2049) } })])).toBe(URL_ERR);
  });
  it('a username alone, or a password alone, makes the URL not plain', () => {
    expect(validateSafetyChecks([chk({ evidence: { kind: 'url', ref: 'https://u@ci.example.com/x' } })])).toBe(URL_ERR);
    expect(validateSafetyChecks([chk({ evidence: { kind: 'url', ref: 'https://:p@ci.example.com/x' } })])).toBe(URL_ERR);
  });
});

describe('verifySafetyCertificate: exact verdicts at the edges', () => {
  const G = generateKeyPair();
  const issue = (checks?: SafetyCheck[]) => issueSafetyCertificate({ policy: DEFAULT_RISK_POLICY, guardianSecret: G.secretKey, issuedAt: 1000, ...(checks ? { checks } : {}) });
  const resign = (c: SafetyCertificate, over: Record<string, unknown>): SafetyCertificate => {
    const { sig: _s, ...rest } = c;
    void _s;
    const body = { ...rest, ...over };
    return { ...body, sig: b64u(sign(G.secretKey, safetyCertificateMessage(body as never))) } as SafetyCertificate;
  };
  it('signed but malformed checks give ok: false with the reason (and nothing else)', () => {
    const c = resign(issue(), { checks: [chk({ id: '' })] });
    expect(verifySafetyCertificate(c)).toEqual({ ok: false, reason: 'invalid checks: check id must be a 1..64 char string' });
  });
  it('issued exactly now is not "in the future"', () => {
    const c = issue();
    expect(verifySafetyCertificate(c, { maxAgeMs: 500, now: 1000 })).toEqual({ ok: true, recomputedBound: c.bound });
    expect(verifySafetyCertificate(c, { maxAgeMs: 500, now: 999 })).toEqual({ ok: false, reason: 'certificate is issued in the future', recomputedBound: c.bound });
  });
});
