import { describe, expect, it } from 'vitest';
import { buildRegistry, issuePassport, matchesBinding, passportFingerprint, trustScore } from './passport';
import type { AgentBinding } from './envelope';

const base = {
  model_id: 'claude-opus-4-8',
  weights_digest: 'w1',
  system_prompt_digest: 'sp1',
  tool_manifest_digest: 'tm1',
  runtime_measurement: '42',
  operator: 'acme',
  hardware_rooted: true,
  weights_measured: true,
  issued_at: 0,
};

describe('passport identity', () => {
  it('fingerprint is content-addressed and stable', () => {
    const id1 = passportFingerprint(base);
    const id2 = passportFingerprint({ ...base, issued_at: 999 }); // issued_at not part of identity
    expect(id1).toBe(id2);
    const id3 = passportFingerprint({ ...base, model_id: 'other' });
    expect(id3).not.toBe(id1);
    expect(issuePassport(base).id).toBe(id1);
  });
});

describe('matchesBinding', () => {
  const p = issuePassport(base);

  it('accepts a passport that satisfies every pinned field', () => {
    const b: AgentBinding = {
      model_allowlist: ['claude-opus-4-8'],
      weights_allowlist: ['w1'],
      system_prompt_allowlist: ['sp1'],
      tool_manifest_allowlist: ['tm1'],
      operator: 'acme',
      require_hardware: true,
      require_measured_weights: true,
      min_measurement: { svn: 40 },
    };
    expect(matchesBinding(p, b)).toEqual({ ok: true, reasons: [] });
  });

  it('rejects a model / weights / operator mismatch', () => {
    expect(matchesBinding(p, { model_allowlist: ['nope'] }).ok).toBe(false);
    expect(matchesBinding(p, { weights_allowlist: ['other'] }).ok).toBe(false);
    expect(matchesBinding(p, { operator: 'evilcorp' }).ok).toBe(false);
  });

  it('fails closed when a required field is absent', () => {
    const noWeights = issuePassport({ ...base, weights_digest: undefined });
    const m = matchesBinding(noWeights, { weights_allowlist: ['w1'] });
    expect(m.ok).toBe(false);
    expect(m.reasons[0]).toMatch(/weights_digest required/);
  });

  it('enforces hardware + measured-weights demands', () => {
    const soft = issuePassport({ ...base, hardware_rooted: false, weights_measured: false });
    expect(matchesBinding(soft, { require_hardware: true }).ok).toBe(false);
    expect(matchesBinding(soft, { require_measured_weights: true }).ok).toBe(false);
  });

  it('min_measurement: exact string vs monotone SVN lower bound', () => {
    expect(matchesBinding(p, { min_measurement: '42' }).ok).toBe(true);
    expect(matchesBinding(p, { min_measurement: '41' }).ok).toBe(false); // exact string mismatch
    expect(matchesBinding(p, { min_measurement: { svn: 42 } }).ok).toBe(true);
    expect(matchesBinding(p, { min_measurement: { svn: 43 } }).ok).toBe(false); // SVN too low
  });

  it('an empty binding accepts anything', () => {
    expect(matchesBinding(p, {}).ok).toBe(true);
  });
});

describe('registry + trustScore', () => {
  it('registry looks up by content id', () => {
    const p = issuePassport(base);
    const reg = buildRegistry([p]);
    expect(reg.get(p.id)).toEqual(p);
    expect(reg.has('missing')).toBe(false);
    expect(reg.all()).toHaveLength(1);
  });

  it('trustScore rewards hardware root, measured provenance and known operator', () => {
    const full = issuePassport(base);
    expect(trustScore(full, { knownOperators: ['acme'] })).toBeCloseTo(1, 6); // 0.4+0.2+0.1+0.1+0.2
    const soft = issuePassport({ ...base, hardware_rooted: false, weights_measured: false });
    expect(trustScore(soft)).toBeLessThan(trustScore(full));
  });
});
