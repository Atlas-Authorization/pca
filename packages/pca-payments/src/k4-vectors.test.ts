// Generates and drift-checks packages/pca/conformance/k4-vectors.json (escalation pricing, network-token binding, ERC-7715 check).
// The natives replay this file. Keys are fixed seeds, Ed25519 is deterministic, so the output is byte-stable.
// Regenerate: K4_VECTORS_WRITE=1 npx vitest run src/k4-vectors.test.ts
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { encodeKey, hashCanonical, publicKeyOf } from '@atlasauth/pca';
import { decideEscalation, freshCalibration, signAnswer, signPricingConfig, updateCalibration, pricingConfigError, type ActionRisk, type AnswerBody } from '../../pca-wallet/src/escalation-pricing';
import { grantToPermissionRequest, verifyGrantedPermission, type GrantEnvelope } from '../../pca-erc7715/src/index';
import { bindNetworkToken, verifyNetworkTokenBinding } from './network-token';

const PATH = join(__dirname, '../../pca/conformance/k4-vectors.json');
const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const pub = (sk: Uint8Array): Uint8Array => publicKeyOf(sk);

function build(): unknown {
  // ---- escalation
  const psk = seed(7), osk = seed(9);
  const principal = encodeKey(pub(psk));
  const body = { v: 1 as const, principal, currency: 'USD', interruptionCost: 100, maxInterruptionCost: 500, hardCeilingLoss: 100000, tightenStepPpm: 500000, epoch: 1 };
  const config = signPricingConfig(body, psk);
  const risk = (loss: number, p: number, currency = 'USD'): ActionRisk => ({ currency, loss, pBadUpperPpm: p });
  const decisionIn: Array<[number, number, number, string?]> = [
    [1000, 100000, 1000000], [1001, 100000, 1000000], [50, 0, 1000000], [1000, 100000, 1500000], [100001, 0, 1000000], [5000, 30000, 1000000],
    [1, 1000000, 1000000], [0, 1000000, 1000000], [1, 0, 1000000, 'EUR'], [1, 0, 1], [1, 1000001, 1000000], [1, 0, 100000001],
    [9007199254740991, 1000000, 100000000], [100000, 1000000, 100000000],
  ];
  const decisions = decisionIn.map(([loss, p, m, cur]) => {
    const calibration = { multiplierPpm: m, seen: [] as string[] }; const r = risk(loss, p, cur ?? 'USD');
    return { calibration, risk: r, expect: decideEscalation(config, calibration, r) };
  });
  const badConfigs = [
    { name: 'valid', config, expect: null },
    { name: 'tampered cost', config: { ...config, interruptionCost: 99 }, expect: pricingConfigError({ ...config, interruptionCost: 99 }) },
    { name: 'signed by another key', config: signPricingConfig(body, osk), expect: pricingConfigError(signPricingConfig(body, osk)) },
    { name: 'cost above max', config: signPricingConfig({ ...body, interruptionCost: 501 }, psk), expect: 'config_cost_above_max' },
    { name: 'negative amount', config: signPricingConfig({ ...body, hardCeilingLoss: -1 }, psk), expect: 'config_amounts_invalid' },
    { name: 'wrong version', config: { ...config, v: 2 }, expect: 'config_malformed' },
  ];
  for (const b of badConfigs) expect(pricingConfigError(b.config)).toBe(b.expect);
  const ans = (nonce: string, digest: string, answer: 'approve' | 'deny', sk = psk): unknown => signAnswer({ v: 1, principal, nonce, action_digest: digest, answer } as AnswerBody, sk);
  const risks = { d1: risk(1000, 100000), d2: risk(100000, 1000000), d3: risk(1001, 100000), d4: risk(1000, 0) };
  const rmap = new Map(Object.entries(risks));
  const calIn = [
    { name: 'deny of an auto-approved action tightens', answers: [ans('nonce-0001', 'd1', 'deny')] },
    { name: 'approve changes nothing', answers: [ans('nonce-0002', 'd1', 'approve')] },
    { name: 'deny of an already-asked action changes nothing', answers: [ans('nonce-0003', 'd3', 'deny')] },
    { name: 'replayed nonce counts once', answers: [ans('nonce-0004', 'd1', 'deny'), ans('nonce-0004', 'd1', 'deny')] },
    { name: 'forged answer ignored', answers: [ans('nonce-0005', 'd1', 'deny', osk)] },
    { name: 'unknown action ignored', answers: [ans('nonce-0006', 'dX', 'deny')] },
    { name: 'short nonce ignored', answers: [ans('n1', 'd1', 'deny')] },
    { name: 'step then second miss', answers: [ans('nonce-0007', 'd1', 'deny'), ans('nonce-0008', 'd1', 'deny'), ans('nonce-0009', 'd1', 'deny')] },
    { name: 'multiplier cap', answers: Array.from({ length: 3 }, (_, i) => ans(`nonce-cap${i}`, 'd4', 'deny')), cap: true },
  ];
  const calibration = calIn.map((c) => {
    const start = c.cap ? { multiplierPpm: 99_800_000, seen: [] as string[] } : freshCalibration();
    const out = c.cap ? updateCalibration(signPricingConfig({ ...body, tightenStepPpm: 100_000_000 }, psk), start, c.answers as never[], rmap) : updateCalibration(config, start, c.answers as never[], rmap);
    return c.cap
      ? { name: c.name, config: signPricingConfig({ ...body, tightenStepPpm: 100_000_000 }, psk), start, answers: c.answers, risks, expect: out }
      : { name: c.name, config, start, answers: c.answers, risks, expect: out };
  });

  // ---- network token binding
  const hsk = seed(3), ssk = seed(4);
  const grant = { kind: 'k4-vector-grant', n: 1 };
  const holder = encodeKey(pub(hsk));
  const nonce = 'issuer-nonce-0123456789';
  const good = bindNetworkToken({ provider: 'visa_ic', tokenRef: 'tok_abcdef123456', grant, issuerNonce: nonce, holderSecret: hsk, holderPublic: pub(hsk) });
  const ex = { grant, holder, issuer_nonce: nonce };
  const nb = (name: string, b: unknown, e: Record<string, unknown> = {}) => ({ name, binding: b, expect_in: { ...ex, ...e }, expect: verifyNetworkTokenBinding(b, { grant: (e.grant ?? grant) as unknown, holder: (e.holder ?? holder) as string, issuerNonce: (e.issuer_nonce ?? nonce) as string, ...(e.provider !== undefined ? { provider: e.provider as string } : {}) }) });
  const flip = (s: string) => s.slice(0, 10) + (s[10] === 'A' ? 'B' : 'A') + s.slice(11);
  const pan = bindNetworkToken({ provider: 'x', tokenRef: 'tok_x_4111111', grant, issuerNonce: nonce, holderSecret: hsk, holderPublic: pub(hsk) });
  const bindings = [
    nb('valid', good),
    nb('wrong provider', good, { provider: 'mastercard_agent_pay' }),
    nb('right provider', good, { provider: 'visa_ic' }),
    nb('other grant', good, { grant: { kind: 'other' } }),
    nb('other holder', good, { holder: encodeKey(pub(ssk)) }),
    nb('other nonce', good, { issuer_nonce: 'issuer-nonce-other-0123' }),
    nb('token_ref changed', { ...good, token_ref: 'tok_other_123456' }),
    nb('proof flipped', { ...good, binding_proof: flip(good.binding_proof) }),
    nb('PAN-shaped token_ref', { ...good, token_ref: '4111111111111111' }),
    nb('PAN-shaped inside', { ...good, token_ref: 'tok_4111-1111-1111-1111' }),
    nb('Luhn-invalid digits are fine', pan),
    nb('short token_ref', { ...good, token_ref: 'short' }),
    nb('wrong kind', { ...good, kind: 'nope' }),
    nb('null', null),
  ];
  // the Luhn-invalid but long ref: sign it directly to keep it a valid binding
  const luhnBad = bindNetworkToken({ provider: 'visa_ic', tokenRef: 'tok_4111111111111112', grant, issuerNonce: nonce, holderSecret: hsk, holderPublic: pub(hsk) });
  bindings.push(nb('19-digit Luhn-invalid run is not a PAN', luhnBad));

  // ---- ERC-7715
  const g: GrantEnvelope = { grantDigest: 'gd1', capMinor: 1000, expiresAtSec: 1_800_086_400 };
  const SESSION = '0x' + '11'.repeat(20), TOKEN = '0x' + '22'.repeat(20), MGR = '0x' + 'ab'.repeat(20);
  const req = grantToPermissionRequest(g, { chainId: 8453n, sessionAccount: SESSION, tokenAddress: TOKEN, baseUnitsPerMinor: '10000' });
  const nat = grantToPermissionRequest(g, { chainId: 1n, sessionAccount: SESSION, baseUnitsPerMinor: '1' });
  const resp = (r: typeof req, over: Record<string, unknown> = {}, data: Record<string, unknown> = {}) => ({ ...r, context: '0xabc123', dependencies: [], delegationManager: MGR, ...over, permission: { ...r.permission, ...(over.permission as object ?? {}), data: { ...r.permission.data, ...data } } });
  const opts = { allowedManagers: [MGR], contexts: { '0xabc123': 'gd1' } as Record<string, string> };
  const e7 = (name: string, sent: typeof req, got: unknown, o: { allowedManagers: string[]; contexts?: Record<string, string> } = opts) => ({ name, envelope: g, sent, got, opts: o, expect: verifyGrantedPermission(g, sent, got, { allowedManagers: o.allowedManagers, contextOwner: (c) => o.contexts?.[c] }) });
  const cases = [
    e7('as requested (erc20)', req, resp(req)),
    e7('as requested (native)', nat, resp(nat)),
    e7('narrowed allowance', req, resp(req, {}, { allowance: '0x1' })),
    e7('earlier expiry', req, resp(req, { rules: [{ type: 'expiry', data: { timestamp: g.expiresAtSec - 5 } }] })),
    e7('allowance widened', req, resp(req, {}, { allowance: '0x' + (10_000_001n).toString(16) })),
    e7('allowance not hex', req, resp(req, {}, { allowance: '10' })),
    e7('allowance leading zero', req, resp(req, {}, { allowance: '0x0001' })),
    e7('other token', req, resp(req, {}, { tokenAddress: '0x' + '44'.repeat(20) })),
    e7('other chain', req, resp(req, { chainId: '0x1' })),
    e7('other recipient', req, resp(req, { to: '0x' + '55'.repeat(20) })),
    e7('untrusted manager', req, resp(req, { delegationManager: '0x' + '66'.repeat(20) })),
    e7('manager compare is case-insensitive', req, resp(req, { delegationManager: '0x' + 'AB'.repeat(20) })),
    e7('expiry extended', req, resp(req, { rules: [{ type: 'expiry', data: { timestamp: g.expiresAtSec + 1 } }] })),
    e7('no expiry rule', req, resp(req, { rules: [] })),
    e7('rules absent', req, (() => { const r = resp(req) as Record<string, unknown>; delete r.rules; return r; })()),
    e7('unknown rule type', req, resp(req, { rules: [{ type: 'redeemer', data: {} }] })),
    e7('duplicate expiry', req, resp(req, { rules: [{ type: 'expiry', data: { timestamp: 1 } }, { type: 'expiry', data: { timestamp: 2 } }] })),
    e7('type changed', req, resp(req, { permission: { type: 'native-token-allowance' } })),
    e7('type not allowed', { ...req, permission: { ...req.permission, type: 'erc721-token-allowance' } }, resp({ ...req, permission: { ...req.permission, type: 'erc721-token-allowance' } })),
    e7('bad context', req, resp(req, { context: 'abc' })),
    e7('context of another grant', req, resp(req), { allowedManagers: [MGR], contexts: { '0xabc123': 'other' } }),
    e7('adjustment turned on', { ...req, permission: { ...req.permission, isAdjustmentAllowed: false } }, resp({ ...req, permission: { ...req.permission, isAdjustmentAllowed: false } }, { permission: { isAdjustmentAllowed: true } })),
    e7('null response', req, null),
    e7('permission null', req, { permission: null }),
  ];
  return {
    doc: 'K4 vectors: escalation pricing (C-284..287), network-token binding (C-280), ERC-7715 granted-permission check (C-288..290). Generated by packages/pca-payments/src/k4-vectors.test.ts; natives replay it.',
    escalation: { config, config_cases: badConfigs, decisions, calibration },
    network_binding: { cases: bindings },
    erc7715: { cases },
    _hash: hashCanonical({ config, cases: cases.length }),
  };
}

describe('k4 vectors (T-703)', () => {
  it('the committed file is exactly what the generator writes', () => {
    const text = JSON.stringify(build(), null, 1) + '\n';
    if (process.env.K4_VECTORS_WRITE === '1') writeFileSync(PATH, text);
    expect(readFileSync(PATH, 'utf8')).toBe(text);
  });
  it('covers both outcomes of every section', () => {
    const v = JSON.parse(readFileSync(PATH, 'utf8'));
    for (const sec of [v.escalation.decisions, v.escalation.config_cases, v.network_binding.cases, v.erc7715.cases]) {
      const outcomes = new Set(sec.map((c: { expect: unknown }) => JSON.stringify(c.expect === null ? null : typeof c.expect === 'object' ? (c.expect as { ask: boolean }).ask : 'err')));
      expect(outcomes.size).toBeGreaterThanOrEqual(2);
    }
    expect(v.erc7715.cases.length).toBeGreaterThanOrEqual(24);
  });
});
