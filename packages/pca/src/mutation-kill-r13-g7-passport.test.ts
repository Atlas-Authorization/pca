/**
 * r13 mutation kills for passport.ts: the fingerprint's exact canonical input, every matchesBinding reason string and
 * empty-allowlist case, the strict SVN parse (multi-digit, non-string runtime measurements), and exact trust scores.
 */
import { describe, expect, it } from 'vitest';
import { hashCanonical } from './hash';
import { matchesBinding, passportFingerprint, trustScore, type AgentPassport } from './passport';

const base: AgentPassport = { id: 'p', model_id: 'm', operator: 'op', hardware_rooted: false, issued_at: 1 };

describe('passportFingerprint', () => {
  it('hashes exactly the documented identity fields', () => {
    const p = { ...base, weights_digest: 'w', system_prompt_digest: 's', tool_manifest_digest: 't', runtime_measurement: 'r', hardware_rooted: true };
    expect(passportFingerprint(p)).toBe(
      hashCanonical({ d: 'atlas-pca/passport/v1', model_id: 'm', weights_digest: 'w', system_prompt_digest: 's', tool_manifest_digest: 't', runtime_measurement: 'r', operator: 'op', hardware_rooted: true }),
    );
    expect(passportFingerprint(base)).toBe(
      hashCanonical({ d: 'atlas-pca/passport/v1', model_id: 'm', weights_digest: null, system_prompt_digest: null, tool_manifest_digest: null, runtime_measurement: null, operator: 'op', hardware_rooted: false }),
    );
  });
});

describe('matchesBinding', () => {
  it('empty allowlists impose nothing', () => {
    expect(matchesBinding(base, { model_allowlist: [], weights_allowlist: [], system_prompt_allowlist: [], tool_manifest_allowlist: [] } as never)).toEqual({ ok: true, reasons: [] });
  });
  it('exact reasons', () => {
    const p = { ...base, weights_digest: 'w', system_prompt_digest: 's', tool_manifest_digest: 't' };
    const r = matchesBinding(p, {
      model_allowlist: ['x'], weights_allowlist: ['x'], system_prompt_allowlist: ['x'], tool_manifest_allowlist: ['x'], operator: 'other', require_hardware: true, require_measured_weights: true, min_measurement: 'pin',
    } as never);
    expect(r).toEqual({
      ok: false,
      reasons: [
        "model_id 'm' not in allowlist",
        "weights_digest 'w' not in allowlist",
        "system_prompt_digest 's' not in allowlist",
        "tool_manifest_digest 't' not in allowlist",
        "operator 'op' != required 'other'",
        'binding requires a hardware-rooted attestation',
        'binding requires hardware-measured weights',
        'runtime_measurement does not equal the pinned measurement',
      ],
    });
    expect(matchesBinding(base, { system_prompt_allowlist: ['x'], tool_manifest_allowlist: ['x'] } as never).reasons).toEqual([
      'system_prompt_digest required by binding but absent from passport',
      'tool_manifest_digest required by binding but absent from passport',
    ]);
  });
  it('SVN bounds parse canonical multi-digit decimals only', () => {
    expect(matchesBinding({ ...base, runtime_measurement: '123' }, { min_measurement: { svn: 100 } } as never)).toEqual({ ok: true, reasons: [] });
    expect(matchesBinding({ ...base, runtime_measurement: '99' }, { min_measurement: { svn: 100 } } as never).reasons).toEqual(['runtime SVN 99 < required 100']);
    expect(matchesBinding({ ...base, runtime_measurement: 5 as unknown as string }, { min_measurement: { svn: 1 } } as never).reasons).toEqual(['runtime SVN 5 < required 1']);
  });
});

describe('trustScore', () => {
  it('adds each documented component', () => {
    expect(trustScore(base)).toBe(0);
    expect(trustScore(base, { knownOperators: ['other'] })).toBe(0);
    expect(trustScore(base, { knownOperators: ['op'] })).toBe(0.2);
    expect(trustScore({ ...base, hardware_rooted: true })).toBe(0.4);
    expect(trustScore({ ...base, weights_digest: 'w' })).toBe(0.1);
    expect(trustScore({ ...base, weights_digest: 'w', weights_measured: true })).toBe(0.2);
    expect(trustScore({ ...base, system_prompt_digest: 's' })).toBe(0.1);
    expect(trustScore({ ...base, tool_manifest_digest: 't' })).toBe(0.1);
  });
});
