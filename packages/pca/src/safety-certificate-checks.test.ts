import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { generateKeyPair, sign } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import {
  MAX_SAFETY_CHECKS,
  SAFETY_CERT_SCOPE,
  issueSafetyCertificate,
  safetyCertificateForCompliance,
  safetyCertificateMessage,
  validateSafetyChecks,
  verifySafetyCertificate,
  type SafetyCertificate,
  type SafetyCheck,
} from './safety-certificate';

const G = generateKeyPair();
const SHA = 'a'.repeat(64);
const chk = (over: Partial<SafetyCheck> = {}): SafetyCheck => ({ id: 'fuzz', status: 'passed', evidence: { kind: 'url', ref: 'https://ci.example.com/run/1' }, at: 100, ...over });
const issue = (checks?: SafetyCheck[]) => issueSafetyCertificate({ policy: DEFAULT_RISK_POLICY, guardianSecret: G.secretKey, issuedAt: 1000, ...(checks ? { checks } : {}) });
const resign = (c: SafetyCertificate, over: Record<string, unknown>): SafetyCertificate => {
  const { sig: _s, ...rest } = c;
  void _s;
  const body = { ...rest, ...over };
  return { ...body, sig: b64u(sign(G.secretKey, safetyCertificateMessage(body as never))) } as SafetyCertificate;
};

describe('validateSafetyChecks: exact outcomes', () => {
  const rows: Array<[string, unknown, string | null]> = [
    ['valid url + sha256', [chk(), chk({ id: 'b', evidence: { kind: 'sha256', ref: SHA } })], null],
    ['empty list', [], null],
    ['not an array', {}, 'checks must be an array'],
    ['too many', Array.from({ length: MAX_SAFETY_CHECKS + 1 }, (_, i) => chk({ id: `c${i}` })), `more than ${MAX_SAFETY_CHECKS} checks`],
    ['non-object entry', [null], 'check is not an object'],
    ['empty id', [chk({ id: '' })], 'check id must be a 1..64 char string'],
    ['long id', [chk({ id: 'x'.repeat(65) })], 'check id must be a 1..64 char string'],
    ['duplicate id', [chk(), chk()], "duplicate check id 'fuzz'"],
    ['bad status', [chk({ status: 'ok' as never })], "check 'fuzz' has an invalid status"],
    ['bad time', [chk({ at: -1 })], "check 'fuzz' has an invalid time"],
    ['fractional time', [chk({ at: 1.5 })], "check 'fuzz' has an invalid time"],
    ['no evidence', [{ id: 'fuzz', status: 'passed', at: 1 }], "check 'fuzz' has no evidence link"],
    ['http url', [chk({ evidence: { kind: 'url', ref: 'http://ci.example.com/x' } })], "check 'fuzz' evidence URL must be a plain https URL"],
    ['url with credentials', [chk({ evidence: { kind: 'url', ref: 'https://u:p@ci.example.com/x' } })], "check 'fuzz' evidence URL must be a plain https URL"],
    ['unparseable url', [chk({ evidence: { kind: 'url', ref: 'not a url' } })], "check 'fuzz' evidence URL must be a plain https URL"],
    ['uppercase digest', [chk({ evidence: { kind: 'sha256', ref: 'A'.repeat(64) } })], "check 'fuzz' evidence digest is not 64 lowercase hex"],
    ['short digest', [chk({ evidence: { kind: 'sha256', ref: 'a'.repeat(63) } })], "check 'fuzz' evidence digest is not 64 lowercase hex"],
    ['unknown evidence kind', [chk({ evidence: { kind: 'ipfs', ref: 'x' } as never })], "check 'fuzz' has an invalid evidence kind"],
  ];
  for (const [name, input, out] of rows) it(name, () => expect(validateSafetyChecks(input)).toBe(out));
});

describe('issue + verify with checks', () => {
  it('scope is risk-budget-bound and the statement disclaims safety', () => {
    const c = issue();
    expect(c.scope).toBe(SAFETY_CERT_SCOPE);
    expect(c.statement).toContain('not a claim that the agent or the system is safe');
    expect('checks' in c).toBe(false);
  });
  it('issuing malformed checks throws', () => {
    expect(() => issue([chk({ id: '' })])).toThrow('issueSafetyCertificate: check id must be a 1..64 char string');
  });
  it('checks are signed: removing or changing one breaks the signature', () => {
    const c = issue([chk(), chk({ id: 'b' })]);
    expect(verifySafetyCertificate(c)).toMatchObject({ ok: true });
    expect(verifySafetyCertificate({ ...c, checks: [c.checks![0]!] }).reason).toBe('guardian signature does not verify');
    expect(verifySafetyCertificate({ ...c, checks: [{ ...c.checks![0]!, status: 'failed' }, c.checks![1]!] }).reason).toBe('guardian signature does not verify');
  });
  it('wrong scope is refused', () => {
    expect(verifySafetyCertificate({ ...issue(), scope: 'safe' as never })).toEqual({ ok: false, reason: 'unknown scope' });
    expect(verifySafetyCertificate({ ...issue(), scope: undefined } as never)).toEqual({ ok: false, reason: 'unknown scope' });
  });
  it('malformed signed checks are refused even when the guardian signed them', () => {
    const c = resign(issue(), { checks: [chk({ evidence: { kind: 'url', ref: 'http://x.example.com' } })] });
    expect(verifySafetyCertificate(c).reason).toBe("invalid checks: check 'fuzz' evidence URL must be a plain https URL");
  });
});

describe('requireChecks / maxAgeMs: missing X gives Y', () => {
  const c = issue([chk(), chk({ id: 'mutation', status: 'failed' }), chk({ id: 'audit', status: 'not_run' })]);
  const rows: Array<[string, Parameters<typeof verifySafetyCertificate>[1], string | true]> = [
    ['required check passed', { requireChecks: ['fuzz'] }, true],
    ['required check absent', { requireChecks: ['formal'] }, "required check 'formal' is not present"],
    ['required check failed', { requireChecks: ['mutation'] }, "required check 'mutation' is failed"],
    ['required check not run', { requireChecks: ['audit'] }, "required check 'audit' is not_run"],
    ['first failing requirement is named', { requireChecks: ['fuzz', 'formal', 'mutation'] }, "required check 'formal' is not present"],
    ['fresh enough', { maxAgeMs: 500, now: 1500 }, true],
    ['exactly at the age limit', { maxAgeMs: 500, now: 1500 }, true],
    ['too old', { maxAgeMs: 500, now: 1501 }, 'certificate is older than maxAgeMs'],
    ['issued in the future', { maxAgeMs: 500, now: 999 }, 'certificate is issued in the future'],
    ['non-finite maxAgeMs', { maxAgeMs: NaN, now: 1500 }, 'invalid age policy or issue time'],
    ['non-finite now', { maxAgeMs: 5, now: Infinity }, 'invalid age policy or issue time'],
  ];
  for (const [name, opts, out] of rows) {
    it(name, () => {
      const v = verifySafetyCertificate(c, opts);
      if (out === true) expect(v.ok).toBe(true);
      else expect(v).toMatchObject({ ok: false, reason: out });
    });
  }
  it('requireChecks on a certificate with no checks is refused', () => {
    expect(verifySafetyCertificate(issue(), { requireChecks: ['fuzz'] }).reason).toBe("required check 'fuzz' is not present");
  });
  it('an unsigned certificate fails on the signature before it reveals which check is missing', () => {
    expect(verifySafetyCertificate({ ...c, sig: 'AAAA' }, { requireChecks: ['formal'] }).reason).toBe('guardian signature does not verify');
  });
});

describe('safetyCertificateForCompliance', () => {
  it('returns an evidence row only for a verifying certificate', () => {
    const c = issue([chk(), chk({ id: 'b', evidence: { kind: 'sha256', ref: SHA } })]);
    expect(safetyCertificateForCompliance(c)).toEqual({
      control: 'risk-budget-bound',
      guardian: c.guardian,
      issued_at: 1000,
      bound: c.bound,
      checks: [
        { id: 'fuzz', status: 'passed', evidence: 'https://ci.example.com/run/1' },
        { id: 'b', status: 'passed', evidence: `sha256:${SHA}` },
      ],
    });
    expect(safetyCertificateForCompliance({ ...c, bound: 99 })).toBeNull();
    expect(safetyCertificateForCompliance(c, { requireChecks: ['missing'] })).toBeNull();
  });
  it('no checks gives an empty list', () => {
    expect(safetyCertificateForCompliance(issue())!.checks).toEqual([]);
  });
});
