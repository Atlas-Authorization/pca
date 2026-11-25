import { agent, compilePolicy, generateKeyPair, unb64u } from '@atlasauth/pca';
import { lintPolicy, simulate } from '@atlasauth/pca/ext/research';
import { describe, expect, it } from 'vitest';
import { cmdDecode, cmdDiscovery, cmdExplain, cmdKeygen, cmdSimulate, parsePCActnInput } from './index';

const minimal = (over: Record<string, unknown> = {}) => ({
  action: { verb: 'v.x', resource: 'r:1', reversibility_class: 'reversible' },
  aud: 'aud1',
  iat: 1_700_000_000_000,
  exp: 1_700_000_300_000,
  counter: 3,
  cap_chain: [1, 2],
  risk_claim: { r: 0.5 },
  threshold: { t: 1 },
  zk_compliance: { z: 1 },
  ...over,
});
const raised = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return (e as Error).message;
  }
  throw new Error('did not throw');
};

describe('parsePCActnInput', () => {
  it('trims surrounding whitespace before detecting JSON', () => {
    const json = JSON.stringify(minimal());
    expect(parsePCActnInput(`  \n${json}\t `)).toEqual(minimal());
    expect(raised(() => parsePCActnInput('   \n '))).toBe('empty input: expected a PCActn as JSON text or base64url');
  });
  it('each failure stage has its own message', () => {
    expect(raised(() => parsePCActnInput('{not json'))).toMatch(/^not a valid PCActn \(JSON\): .+/);
    expect(raised(() => parsePCActnInput('!!!!'))).toMatch(/^input is neither JSON \(no leading '\{'\) nor valid base64url: .+/);
    expect(raised(() => parsePCActnInput(Buffer.from([0xff, 0xfe, 0xfd]).toString('base64url')))).toBe('base64url decoded to bytes that are not valid UTF-8; not a PCActn');
    expect(raised(() => parsePCActnInput(Buffer.from('hello').toString('base64url')))).toMatch(/^base64url decoded but is not a valid PCActn: .+/);
    expect(raised(() => parsePCActnInput(Buffer.from('[1]').toString('base64url')))).toMatch(/^base64url decoded but is not a valid PCActn: /);
  });
  it('base64url of valid UTF-8 JSON is accepted', () => {
    expect(parsePCActnInput(Buffer.from(JSON.stringify(minimal())).toString('base64url'))).toEqual(minimal());
  });
});

describe('cmdDecode: exact summary', () => {
  it('prints every field', () => {
    expect(cmdDecode(JSON.stringify(minimal()))).toBe(
      [
        'PCActn summary',
        '  verb          v.x',
        '  resource      r:1',
        '  reversibility reversible',
        '  audience      aud1',
        '  issued (iat)  2023-11-14T22:13:20.000Z  [1700000000000]',
        '  expires (exp) 2023-11-14T22:18:20.000Z  [1700000300000]',
        '  counter       3',
        '  cap-chain     depth 2',
        '  risk_claim.r  0.5',
        '  threshold     present',
        '  zk_compliance present',
      ].join('\n'),
    );
  });
  it('absent or odd values read as markers', () => {
    const out = cmdDecode(JSON.stringify(minimal({ aud: '', iat: 'x', exp: 8.64e15 + 1, cap_chain: 'x', risk_claim: [1], threshold: undefined, zk_compliance: undefined })));
    expect(out).toContain('  audience      (none)\n');
    expect(out).toContain('  issued (iat)  (none)  [x]\n');
    expect(out).toContain('  expires (exp) (invalid)  [8640000000000001]\n');
    expect(out).toContain('  cap-chain     depth 0\n');
    expect(out).toContain('  risk_claim.r  (none)\n');
    expect(out).toContain('  threshold     absent\n');
    expect(out.endsWith('  zk_compliance absent')).toBe(true);
    expect(cmdDecode(JSON.stringify(minimal({ risk_claim: { r: 'x' } })))).toContain('  risk_claim.r  (none)\n');
    expect(cmdDecode(JSON.stringify(minimal({ risk_claim: null })))).toContain('  risk_claim.r  (none)\n');
    expect(cmdDecode(JSON.stringify(minimal({ iat: null })))).toContain('  issued (iat)  (none)  [null]\n');
    expect(cmdDecode(JSON.stringify(minimal({ risk_claim: { r: 0 } })))).toContain('  risk_claim.r  0\n');
  });
});

describe('cmdExplain: exact report', () => {
  const mint = () => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_test' }).act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' }, { counter: 1 });
  const expectedText = (r: Awaited<ReturnType<typeof cmdExplain>>, verifierAud: string, withReasons: string[]) => {
    const width = Math.max(...Object.keys(r.checks).map((k) => k.length)) + 2;
    const lines = Object.entries(r.checks).map(([k, v]) => `  ${k.padEnd(width)}${v}${v === '—' ? ' (not enforced by this verifier profile)' : ''}`);
    return [
      'PCActn verification (explain)',
      '  verb            stripe.refund',
      '  resource        charge:ch_1',
      '  action audience ins_test',
      `  verifier aud    ${verifierAud}`,
      '',
      ...lines,
      '',
      `  VERDICT: ${r.allow ? 'ALLOW' : 'DENY'}`,
      ...(withReasons.length ? ['', '  reasons:', ...withReasons.map((x) => `    - ${x}`)] : []),
    ].join('\n');
  };
  it('an allowed action prints aligned checks with labels, notes and no reasons block', async () => {
    const { pcactn } = mint();
    const r = await cmdExplain(JSON.stringify(pcactn), { audience: 'ins_test', now: pcactn.iat });
    expect(r.allow).toBe(true);
    expect(r.reasons).toEqual([]);
    expect(Object.values(r.checks).every((v) => ['PASS', 'FAIL', '—'].includes(v))).toBe(true);
    expect(Object.values(r.checks)).toContain('—');
    expect(r.text).toBe(expectedText(r, 'ins_test', []));
    expect(r.text).toContain(' (not enforced by this verifier profile)');
  });
  it('a denied action lists its reason, and no audience reads as any', async () => {
    const { pcactn } = mint();
    const bad = await cmdExplain(JSON.stringify(pcactn), { audience: 'ins_wrong', now: pcactn.iat });
    expect(bad.allow).toBe(false);
    expect(bad.reasons.length).toBe(1);
    expect(bad.text).toBe(expectedText(bad, 'ins_wrong', bad.reasons));
    const any = await cmdExplain(JSON.stringify(pcactn), { now: pcactn.iat });
    expect(any.text).toBe(expectedText(any, 'any (not supplied)', any.reasons));
    const empty = await cmdExplain(JSON.stringify(pcactn), { audience: '', now: pcactn.iat });
    expect(empty.text).toContain('  verifier aud    \n');
  });
  it('an action audience that is empty reads as (none)', async () => {
    const { pcactn } = mint();
    const r = await cmdExplain(JSON.stringify({ ...pcactn, aud: '' }), { now: pcactn.iat });
    expect(r.text).toContain('  action audience (none)\n');
  });
  it('a chain-less action cannot be explained', async () => {
    const { pcactn } = mint();
    for (const cap_chain of [[], 'x', undefined]) {
      await expect(cmdExplain(JSON.stringify({ ...pcactn, cap_chain }), {})).rejects.toThrow('cannot explain: the PCActn has an empty capability chain (no root grant)');
    }
  });
});

describe('cmdKeygen: exact block', () => {
  it('labels the keys and warns about the secret', () => {
    const k = cmdKeygen();
    expect(k.text).toBe(
      [
        'PCA dev keypair (Ed25519)',
        `  public  ${k.publicKey}`,
        `  secret  ${k.secretKey}`,
        '',
        '  Keep the SECRET key private — it signs PCActns as this holder.',
        '  Share only the public key (a grant binds to it as `holder`).',
      ].join('\n'),
    );
    expect(unb64u(k.publicKey)).toHaveLength(32);
    expect(cmdKeygen().publicKey).not.toBe(k.publicKey);
  });
});

describe('cmdDiscovery', () => {
  it('empty suites and endpoints are left out, giving the defaults', () => {
    const plain = cmdDiscovery({ audience: 'a' });
    expect(cmdDiscovery({ audience: 'a', suites: [], endpoints: {} })).toBe(plain);
    expect(JSON.parse(plain)).not.toHaveProperty('endpoints');
  });
  it('given suites and endpoints are carried', () => {
    const doc = JSON.parse(cmdDiscovery({ audience: 'a', suites: ['custom-suite'], endpoints: { grant: 'https://x.example/g' } })) as { signature_suites: string[]; endpoints: Record<string, string> };
    expect(doc.signature_suites).toEqual(['custom-suite']);
    expect(doc.endpoints).toEqual({ grant: 'https://x.example/g' });
    expect(cmdDiscovery({ audience: 'a', suites: ['custom-suite'] })).toContain('custom-suite');
  });
});

describe('cmdSimulate', () => {
  const policySpec = { permissions: { stripe: ['refund'], gmail: ['send'] }, limits: { refund: '$100/day' } };
  const acts = [
    { verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount: 40 } },
    { verb: 'gmail.send', resource: 'thread:t1' },
    { verb: 'other.thing', resource: 'x:0123456789abcdef0123456789', at: 1_700_000_000_000 },
  ];
  const expected = (spec: typeof policySpec | { permissions: Record<string, string[]> }, actions: typeof acts) => {
    const policy = compilePolicy(spec as never);
    const report = simulate(policy, actions as never);
    const lints = lintPolicy(policy);
    const { bMax, kappa } = policy.riskPolicy;
    const pad = (s: string, w: number) => s.padEnd(w);
    return [
      `Policy simulation (${report.results.length} action${report.results.length === 1 ? '' : 's'})`,
      '',
      `  ${pad('#', 3)}${pad('verb', 18)}${pad('resource', 20)}${pad('outcome', 10)}budgetAfter`,
      ...report.results.map((r, i) => `  ${pad(String(i + 1), 3)}${pad(r.action.verb, 18)}${pad(r.action.resource, 20)}${pad(r.outcome, 10)}${r.budgetAfter.toFixed(2)}`),
      '',
      `  auto=${report.auto}  step_up=${report.stepUp}  deny=${report.deny}  endBudget=${report.endBudget.toFixed(2)}  peakRisk=${report.peakRisk.toFixed(3)}`,
      `  autonomy bound: ${(Math.max(0, bMax)).toFixed(2)} (most this grant can spend/risk between human co-signs)`,
      '',
      'Lints:',
      ...(lints.length ? lints.map((l) => `  [${l.level}] ${l.code}: ${l.message}`) : ['  (none)']),
    ].join('\n');
  };
  it('prints the whole report exactly, for several actions and for one', () => {
    expect(cmdSimulate(JSON.stringify(policySpec), JSON.stringify(acts))).toBe(expected(policySpec, acts));
    expect(cmdSimulate(JSON.stringify(policySpec), JSON.stringify(acts.slice(0, 1)))).toBe(expected(policySpec, acts.slice(0, 1)));
    const noLimits = { permissions: { stripe: ['refund'] } };
    expect(cmdSimulate(JSON.stringify(noLimits), JSON.stringify(acts))).toBe(expected(noLimits, acts));
    expect(cmdSimulate(JSON.stringify(policySpec), '[]')).toBe(expected(policySpec, []));
  });
  it('limits change the policy that is simulated', () => {
    const a = cmdSimulate(JSON.stringify(policySpec), JSON.stringify(acts));
    const b = cmdSimulate(JSON.stringify({ permissions: policySpec.permissions }), JSON.stringify(acts));
    expect(a).not.toBe(b);
  });
  it('malformed policy and actions are refused with exact messages', () => {
    const run = (p: unknown, a: unknown = []) => raised(() => cmdSimulate(typeof p === 'string' ? p : JSON.stringify(p), typeof a === 'string' ? a : JSON.stringify(a)));
    expect(run('not json')).toMatch(/^policy: invalid JSON: .+/);
    expect(run(policySpec, 'not json')).toMatch(/^actions: invalid JSON: .+/);
    for (const p of ['null', '5', '[]', '"x"']) expect(run(p)).toBe('policy must be a JSON object { permissions, limits? }');
    for (const p of [{}, { permissions: [] }, { permissions: null }]) expect(run(p)).toBe('policy.permissions must be an object { connector: [action, ...] }');
    expect(run({ permissions: { stripe: 'refund' } })).toBe('policy.permissions.stripe must be an array of action names');
    expect(run({ permissions: { stripe: ['refund', 5] } })).toBe('policy.permissions.stripe must contain only strings');
    expect(run({ permissions: { stripe: [] }, limits: [] })).toBe('policy.limits must be an object { action: "$X/period" }');
    expect(run({ permissions: { stripe: [] }, limits: 'x' })).toBe('policy.limits must be an object { action: "$X/period" }');
    expect(run({ permissions: { stripe: [] }, limits: { refund: 5 } })).toBe('policy.limits.refund must be a string like "$500/day"');
    for (const a of ['{}', '"x"', 'null']) expect(run(policySpec, a)).toBe('actions must be a JSON array of { verb, resource, params?, at? }');
    expect(run(policySpec, [5])).toBe('actions[0] must be an object');
    expect(run(policySpec, [null])).toBe('actions[0] must be an object');
    expect(run(policySpec, [[]])).toBe('actions[0] must be an object');
    expect(run(policySpec, [{ verb: 'a', resource: 'b' }, { verb: 5, resource: 'b' }])).toBe('actions[1].verb must be a string');
    expect(run(policySpec, [{ verb: 'a', resource: 5 }])).toBe('actions[0].resource must be a string');
    expect(run(policySpec, [{ verb: 'a', resource: 'b', params: 'x' }])).toBe('actions[0].params must be an object');
    expect(run(policySpec, [{ verb: 'a', resource: 'b', params: [] }])).toBe('actions[0].params must be an object');
    for (const at of ['5', null, true, {}]) expect(run(policySpec, [{ verb: 'a', resource: 'b', at }])).toBe('actions[0].at must be a number (epoch ms)');
    expect(() => cmdSimulate(JSON.stringify(policySpec), JSON.stringify([{ verb: 'a', resource: 'b', params: {}, at: 5 }]))).not.toThrow();
  });
  it('the JSON error is carried in the message, an infinite time is refused, and a clean policy prints (none) under Lints', () => {
    let jsonMsg = '';
    try { JSON.parse('not json'); } catch (e) { jsonMsg = (e as Error).message; }
    expect(raised(() => cmdSimulate('not json', '[]'))).toBe(`policy: invalid JSON: ${jsonMsg}`);
    expect(raised(() => cmdSimulate(JSON.stringify(policySpec), 'not json'))).toBe(`actions: invalid JSON: ${jsonMsg}`);
    expect(raised(() => cmdSimulate(JSON.stringify(policySpec), '[{"verb": "a", "resource": "b", "at": 1e999}]'))).toBe('actions[0].at must be a number (epoch ms)');
    const clean = { permissions: { github: ['read'] } };
    expect(lintPolicy(compilePolicy(clean as never))).toEqual([]);
    const out = cmdSimulate(JSON.stringify(clean), '[]');
    expect(out).toBe(expected(clean, []));
    expect(out.endsWith('\nLints:\n  (none)')).toBe(true);
  });
});
