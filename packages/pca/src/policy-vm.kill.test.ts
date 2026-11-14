import { afterEach, describe, expect, it, vi } from 'vitest';
import { attenuate, type Capability } from './capability';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { decide, type DecideInput } from './policy-vm';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;
const G: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'secure my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e12 }] as never,
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;
const lowRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };
const input = (over: Partial<DecideInput> = {}): DecideInput => ({
  grant: G,
  action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: {} } },
  risk: lowRisk,
  budget: fresh,
  now: NOW,
  ...over,
});
const sealedLeaf = () => attenuate(G, [{ type: 'sealed' }], A.secretKey);
const NOT_CONFIGURED = 'caveat language: sealed: the caveat language is not configured (no k1 input)';
const grantWithSealed = (): Capability => ({ ...G, caveats: [...G.caveats, { type: 'sealed' }] });
const k1Reasons = (reasons: string[]) => reasons.filter((r) => r.startsWith('caveat language: '));

describe('caveat-language caveats on the leaf hop', () => {
  it('a K1 caveat added by a delegation hop is evaluated and refused without a K1 input', () => {
    const d = decide(input({ chain: [G, sealedLeaf()] }));
    expect(d.reasons).toContain(NOT_CONFIGURED);
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.admit).toBe(false);
    expect(d.needStepUp).toBe(true);
    expect(Array.isArray(d.k1Bound)).toBe(true);
  });
  it('the same hop is accepted when the K1 input is configured, and the bound caveats are reported', () => {
    const d = decide(input({ chain: [G, sealedLeaf()], k1: {} }));
    expect(d.reasons).toEqual([]);
    expect(d.releaseGuardianShare).toBe(true);
    expect(d.k1Bound).toHaveLength(1);
    expect(d.k1Bound![0]!.caveat).toEqual({ type: 'sealed' });
    expect('k1Bound' in decide(input())).toBe(false);
  });
  it('a K1 caveat on the root grant is evaluated when the chain is empty', () => {
    const d = decide(input({ grant: grantWithSealed(), chain: [], chainVerified: true }));
    expect(d.reasons).toContain('delegation chain is empty or malformed');
    expect(k1Reasons(d.reasons).length).toBeGreaterThan(0);
  });
  it('a K1 caveat on the root grant is evaluated when the chain is not an array', () => {
    const d = decide(input({ grant: grantWithSealed(), chain: 'abc' as never, chainVerified: true }));
    expect(d.reasons).toContain('delegation chain is empty or malformed');
    expect(k1Reasons(d.reasons).length).toBeGreaterThan(0);
  });
  it('a narrow block alone switches the K1 evaluation on, and a bad one is refused with its reason', () => {
    const d = decide(input({ k1: { narrow: {} as never } }));
    expect(k1Reasons(d.reasons)).toHaveLength(1);
    expect(d.reasons.some((r) => r.startsWith('caveat language: narrow: '))).toBe(true);
    expect(d.releaseGuardianShare).toBe(false);
  });
  it('a plain delegation hop without K1 caveats does not start the K1 evaluation', () => {
    const plain = attenuate(G, [{ type: 'expires', at: 9e12 }], A.secretKey);
    const d = decide(input({ chain: [G, plain] }));
    expect(k1Reasons(d.reasons)).toEqual([]);
    expect(d.releaseGuardianShare).toBe(true);
  });
});

describe('proved policy VM names the unmet limit like the hand-written path', () => {
  async function load() {
    vi.resetModules();
    const vm = await import('./policy-vm');
    const mode = await import('./verified-core-mode');
    return { vm, mode };
  }
  let last: Awaited<ReturnType<typeof load>> | undefined;
  afterEach(() => last?.mode.__setVerifiedCoreModeForTests(undefined));

  const limited = (): DecideInput =>
    input({
      grant: mintGrant({
        principalSecret: P.secretKey,
        principalPublic: encodeKey(P.publicKey),
        holder: encodeKey(A.publicKey),
        goal: 'g',
        envelope: {
          predicates: [{ verb: 'pay', resource: '/acct/*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }] as never,
          caveats: [],
          agent_binding: {},
          risk_policy: DEFAULT_RISK_POLICY,
        },
      }).grant,
      action: { action: { verb: 'pay', resource: '/acct/1', params: { amount: 500 } } },
    });

  it('an unmet where-limit is named under the opt-in, exactly as without it', async () => {
    const m = (last = await load());
    const i = limited();
    m.mode.__setVerifiedCoreModeForTests('');
    const ref = m.vm.decide(i);
    m.mode.__setVerifiedCoreModeForTests('policyvm');
    const proved = m.vm.decide(i);
    expect(ref.reasons[0]).toBe('amount <= 100 not satisfied for pay on /acct/1');
    expect(proved.reasons).toEqual(ref.reasons);
    expect(proved.releaseGuardianShare).toBe(false);
  });
  it('a plain denial keeps the plain wording under the opt-in', async () => {
    const m = (last = await load());
    const i = input({ action: { action: { verb: 'nope', resource: '/x' } } });
    m.mode.__setVerifiedCoreModeForTests('policyvm');
    expect(m.vm.decide(i).reasons).toEqual(['no predicate permits nope on /x']);
  });
});
