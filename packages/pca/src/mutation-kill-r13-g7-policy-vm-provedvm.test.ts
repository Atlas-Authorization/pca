/**
 * r13 mutation kills for policy-vm.ts vmOf(): under the `policyvm` opt-in the proved Policy VM must be built with the
 * real oracles (regex guard + charged full-match, tool_schema evaluator) and evaluate agent caveats under the 'agent'
 * label, so its decisions equal the hand-written evaluator's on regex predicates, tool_schema caveats and a failing
 * caveat. Each test loads fresh modules so the VM is rebuilt from the (possibly mutated) config.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

async function load() {
  vi.resetModules();
  const vm = await import('./policy-vm');
  const mode = await import('./verified-core-mode');
  const env = await import('./envelope');
  const keys = await import('./keys');
  const risk = await import('./risk');
  const an = await import('./agent-native');
  return { vm, mode, env, keys, risk, an };
}
type M = Awaited<ReturnType<typeof load>>;

const NOW = 1_800_000_000_000;
function input(m: M, predicates: unknown[], caveats: unknown[], action: unknown) {
  const P = m.keys.generateKeyPair();
  const A = m.keys.generateKeyPair();
  const grant = m.env.mintGrant({
    principalSecret: P.secretKey,
    principalPublic: m.keys.encodeKey(P.publicKey),
    holder: m.keys.encodeKey(A.publicKey),
    goal: 'g',
    envelope: { predicates: predicates as never, caveats: caveats as never, agent_binding: {}, risk_policy: m.risk.DEFAULT_RISK_POLICY },
  }).grant;
  return {
    grant,
    action: action as never,
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
    budget: { B: 1, tau: NOW, asOf: NOW },
    now: NOW,
  };
}
/** The decision with the opt-in off, then on (same input object). */
function both(m: M, i: ReturnType<typeof input>) {
  m.mode.__setVerifiedCoreModeForTests('');
  const ref = m.vm.decide(i);
  m.mode.__setVerifiedCoreModeForTests('policyvm');
  const proved = m.vm.decide(i);
  return { ref, proved };
}

let last: M | undefined;
afterEach(() => last?.mode.__setVerifiedCoreModeForTests(undefined));

describe('policyvm opt-in: the proved VM uses the real oracles', () => {
  it('a regex resource predicate', async () => {
    const m = (last = await load());
    const { ref, proved } = both(m, input(m, [{ verb: 'read', resource: 're:/doc/[0-9]+' }], [], { action: { verb: 'read', resource: '/doc/7' } }));
    expect(ref.releaseGuardianShare).toBe(true);
    expect(proved).toEqual(ref);
  });
  it('a regex predicate that does not match', async () => {
    const m = (last = await load());
    const { ref, proved } = both(m, input(m, [{ verb: 'read', resource: 're:/doc/[0-9]+' }], [], { action: { verb: 'read', resource: '/doc/x' } }));
    expect(ref.releaseGuardianShare).toBe(false);
    expect(proved).toEqual(ref);
  });
  it('a tool_schema caveat (pass and fail)', async () => {
    const m = (last = await load());
    const cav = m.an.toolSchemaCaveat('revoke_session', { props: { device: { type: 'string' } }, required: ['device'] } as never);
    const preds = [{ verb: 'revoke_session', resource: '*' }];
    const ok = both(m, input(m, preds, [cav], { action: { verb: 'revoke_session', resource: '/s', params: { device: 'laptop' } }, toolBinding: cav.signature_digest }));
    expect(ok.ref.releaseGuardianShare).toBe(true);
    expect(ok.proved).toEqual(ok.ref);
    const bad = both(m, input(m, preds, [cav], { action: { verb: 'revoke_session', resource: '/s', params: { device: 5 } }, toolBinding: cav.signature_digest }));
    expect(bad.ref.releaseGuardianShare).toBe(false);
    expect(bad.proved).toEqual(bad.ref);
  });
  it('a failing agent caveat reports the same reasons', async () => {
    const m = (last = await load());
    const { ref, proved } = both(m, input(m, [{ verb: 'read', resource: '*' }], [{ type: 'expires', at: NOW - 1 }], { action: { verb: 'read', resource: '/r' } }));
    expect(ref.releaseGuardianShare).toBe(false);
    expect(proved).toEqual(ref);
  });
});
