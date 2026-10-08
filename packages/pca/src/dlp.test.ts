import { describe, expect, it } from 'vitest';
import { type DlpPolicy, defaultDlpPolicy, evaluateDlp } from './dlp';

const policy: DlpPolicy = {
  classes: [
    { name: 'pii', resource: 'customer:*', maxTaintForAuto: 0, hardDenyAbove: 2 },
    { name: 'secrets', resource: 'vault:*', maxTaintForAuto: 0, hardDenyAbove: 0 },
    { name: 'public', resource: 'public:*', maxTaintForAuto: 5 },
  ],
  defaultMaxTaintForAuto: 1,
};

describe('evaluateDlp', () => {
  it('allows clean flows to a sensitive sink, steps up tainted ones', () => {
    expect(evaluateDlp(policy, { verb: 'gmail.send', resource: 'customer:42', taint: 0 }).outcome).toBe('allow');
    const su = evaluateDlp(policy, { verb: 'gmail.send', resource: 'customer:42', taint: 1 });
    expect(su.outcome).toBe('step_up');
    expect(su.class).toBe('pii');
  });

  it('hard-denies above the class ceiling', () => {
    expect(evaluateDlp(policy, { verb: 'gmail.send', resource: 'customer:42', taint: 3 }).outcome).toBe('deny');
    // secrets hard-deny ANY taint > 0
    expect(evaluateDlp(policy, { verb: 'http.post', resource: 'vault:key', taint: 1 }).outcome).toBe('deny');
  });

  it('tolerates high taint for a permissive class', () => {
    expect(evaluateDlp(policy, { verb: 'http.post', resource: 'public:blog', taint: 4 }).outcome).toBe('allow');
    expect(evaluateDlp(policy, { verb: 'http.post', resource: 'public:blog', taint: 6 }).outcome).toBe('step_up');
  });

  it('falls back to the default max when no class matches', () => {
    expect(evaluateDlp(policy, { verb: 'files.write', resource: 'tmp:x', taint: 1 }).outcome).toBe('allow');
    expect(evaluateDlp(policy, { verb: 'files.write', resource: 'tmp:x', taint: 2 }).outcome).toBe('step_up');
  });

  it('no default + no match => allow (no DLP constraint)', () => {
    expect(evaluateDlp({ classes: [] }, { verb: 'x', resource: 'y', taint: 99 }).outcome).toBe('allow');
  });

  it('most specific class wins (exact/longest prefix)', () => {
    const p: DlpPolicy = {
      classes: [
        { name: 'all-customer', resource: 'customer:*', maxTaintForAuto: 3 },
        { name: 'vip', resource: 'customer:vip:*', maxTaintForAuto: 0 },
      ],
    };
    expect(evaluateDlp(p, { verb: 'x', resource: 'customer:vip:1', taint: 1 }).class).toBe('vip');
    expect(evaluateDlp(p, { verb: 'x', resource: 'customer:reg:1', taint: 1 }).class).toBe('all-customer');
  });

  it('defaultDlpPolicy preset', () => {
    const p = defaultDlpPolicy({ piiResource: 'customer:*', secretsResource: 'vault:*' });
    expect(evaluateDlp(p, { verb: 'x', resource: 'vault:k', taint: 1 }).outcome).toBe('deny');
    expect(evaluateDlp(p, { verb: 'x', resource: 'customer:1', taint: 0 }).outcome).toBe('allow');
  });
});
