/** The README failure-mode table, one row per cause, with the exact outcome (contract C-128). */
import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, buildPCActn, delegate, encodeKey, generateKeyPair, mintGrant, type CapabilityChain, type PlanNode } from '@atlasauth/pca';
import { importEd25519PrivateKey, importEd25519PublicKey, issuePcaSdJwt, present, verifyPcaSdJwt, verifyRecovered } from './index';

const now = Date.now();
function setup() {
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const pp = encodeKey(principal.publicKey);
  const { grant } = mintGrant({
    principalSecret: principal.secretKey, principalPublic: pp, holder: pp, goal: 'g',
    envelope: { predicates: [{ verb: 'revoke_session', resource: 'session:*' }], caveats: [{ type: 'expires', at: now + 3_600_000 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const chain: CapabilityChain = [grant, delegate(grant, encodeKey(agent.publicKey), [{ type: 'expires', at: now + 600_000 }], principal.secretKey)];
  const plan: PlanNode[] = [{ id: 'n1', verb: 'revoke_session', resource: 'session:s2', params_digest: undefined, reversibility_class: 'reversible' }];
  const pcActn = buildPCActn({ grant, chain, plan, nodeId: 'n1', counter: 1, signerSecret: agent.secretKey, aud: 'rs', now, ttlMs: 600_001, nonce: 'n' });
  return { principal, agent, grant, pcActn };
}
const issue = (s: ReturnType<typeof setup>, o: Record<string, unknown> = {}) => issuePcaSdJwt(s.pcActn, { issuerKey: importEd25519PrivateKey(s.principal.secretKey), ...o });
const vk = (s: ReturnType<typeof setup>) => importEd25519PublicKey(s.principal.publicKey);

describe('verifyPcaSdJwt fails closed', () => {
  it.each([[''], ['abc'], ['a.b.c'], ['~'], ['~~'], [undefined as unknown as string], [42 as unknown as string]])('malformed input %j is { ok: false }', async (input) => {
    const s = setup();
    const r = await verifyPcaSdJwt(input, { issuerKey: vk(s) });
    expect(r.ok).toBe(false);
    expect(typeof (r as { reason: string }).reason).toBe('string');
  });
  it('a different issuer key is refused', async () => {
    const s = setup();
    const r = await verifyPcaSdJwt(await issue(s), { issuerKey: importEd25519PublicKey(generateKeyPair().publicKey) });
    expect(r.ok).toBe(false);
  });
  it('an expired token and a wrong audience are refused', async () => {
    const s = setup();
    const sd = await issue(s);
    expect((await verifyPcaSdJwt(sd, { issuerKey: vk(s), now: now + 7 * 24 * 3_600_000 })).ok).toBe(false);
    expect((await verifyPcaSdJwt(sd, { issuerKey: vk(s), expectedAudience: 'other' })).ok).toBe(false);
    expect((await verifyPcaSdJwt(sd, { issuerKey: vk(s), expectedAudience: 'rs' })).ok).toBe(true);
  });
  it('a disallowed algorithm list is refused', async () => {
    const s = setup();
    expect((await verifyPcaSdJwt(await issue(s), { issuerKey: vk(s), algorithms: ['ES256'] })).ok).toBe(false);
  });
  it('requireKeyBinding without a KB-JWT: the exact reason', async () => {
    const s = setup();
    expect(await verifyPcaSdJwt(await issue(s, { keyBinding: {} }), { issuerKey: vk(s), requireKeyBinding: true })).toEqual({ ok: false, reason: 'key binding required but no KB-JWT was presented' });
    expect(await verifyPcaSdJwt(await issue(s, { keyBinding: {} }), { issuerKey: vk(s), keyBindingKey: importEd25519PublicKey(s.agent.publicKey) })).toEqual({ ok: false, reason: 'key binding required but no KB-JWT was presented' });
  });
  it('a required disclosure that was withheld: the exact reason', async () => {
    const s = setup();
    const pres = await present(await issue(s), ['action']);
    expect(await verifyPcaSdJwt(pres, { issuerKey: vk(s), requiredDisclosures: ['action', 'sig'] })).toEqual({ ok: false, reason: "required disclosure 'sig' was not presented" });
  });
  it('a duplicated disclosure and an empty disclosure segment are refused', async () => {
    const s = setup();
    const sd = await issue(s);
    const parts = sd.split('~');
    const dup = [parts[0], parts[1], parts[1], ...parts.slice(2)].join('~');
    expect((await verifyPcaSdJwt(dup, { issuerKey: vk(s) })).ok).toBe(false);
    const empty = [parts[0], '', ...parts.slice(1)].join('~');
    expect(await verifyPcaSdJwt(empty, { issuerKey: vk(s) })).toEqual({ ok: false, reason: 'pca-sdjwt: empty disclosure segment' });
  });
  it('a disclosure from another token is refused as tampered or unreferenced', async () => {
    const s = setup();
    const other = await issue(setup());
    const foreign = other.split('~')[1]!;
    const sd = await issue(s);
    const withForeign = sd.replace(/~$/, `~${foreign}~`);
    expect((await verifyPcaSdJwt(withForeign, { issuerKey: vk(s) })).ok).toBe(false);
  });
  it('a KB-JWT presented to a token with no cnf key is refused', async () => {
    const s = setup();
    const noCnf = await issue(s);
    const kbKey = importEd25519PrivateKey(s.agent.secretKey);
    const pres = await present(noCnf, ['action'], { keyBinding: { holderKey: kbKey, audience: 'rs', nonce: 'n' } });
    expect(await verifyPcaSdJwt(pres, { issuerKey: vk(s) })).toEqual({ ok: false, reason: 'KB-JWT presented but issuer JWT has no cnf key' });
  });
  it('key binding: wrong nonce, wrong key, stale iat', async () => {
    const s = setup();
    const sd = await issue(s, { keyBinding: {} });
    const holderKey = importEd25519PrivateKey(s.agent.secretKey);
    const pres = await present(sd, ['action'], { keyBinding: { holderKey, audience: 'rs', nonce: 'n1', iat: Math.floor(now / 1000) - 3600 } });
    expect(await verifyPcaSdJwt(pres, { issuerKey: vk(s), expectedNonce: 'n2', now })).toEqual({ ok: false, reason: 'KB-JWT nonce does not match' });
    expect(await verifyPcaSdJwt(pres, { issuerKey: vk(s), kbMaxAgeSec: 60, now })).toEqual({ ok: false, reason: 'KB-JWT is older than the accepted window' });
    expect(await verifyPcaSdJwt(pres, { issuerKey: vk(s), keyBindingKey: importEd25519PublicKey(generateKeyPair().publicKey), now })).toEqual({ ok: false, reason: 'cnf key does not match the expected keyBindingKey' });
    expect((await verifyPcaSdJwt(pres, { issuerKey: vk(s), expectedNonce: 'n1', now, expectedKbAudience: 'elsewhere' })).ok).toBe(false);
    expect((await verifyPcaSdJwt(pres, { issuerKey: vk(s), expectedNonce: 'n1', now })).ok).toBe(true);
  });
});

describe('verifyRecovered fails closed', () => {
  const coreOf = (s: ReturnType<typeof setup>) => ({ grant: s.grant, audience: 'rs', nowEpoch: now });
  it.each(['action', 'cap_chain', 'plan', 'sig', 'grant_ref', 'counter'])('a withheld %s is denied with the exact reason', async (claim) => {
    const s = setup();
    const all = ['action', 'cap_chain', 'plan', 'sig', 'grant_ref', 'counter', 'iat_ms', 'exp_ms'].filter((c) => c !== claim);
    const pres = await present(await issue(s), all);
    const r = await verifyPcaSdJwt(pres, { issuerKey: vk(s) });
    if (!r.ok) throw new Error(r.reason);
    expect(await verifyRecovered(r, coreOf(s))).toEqual({ allow: false, checks: {}, reason: `pca-sdjwt: required claim '${claim}' was not disclosed` });
  });
  it('without a stored grant or audience the core denies (nothing is inferred from the token)', async () => {
    const s = setup();
    const r = await verifyPcaSdJwt(await issue(s), { issuerKey: vk(s) });
    if (!r.ok) throw new Error(r.reason);
    expect((await verifyRecovered(r, { grant: s.grant, nowEpoch: now } as never)).allow).toBe(false);
  });
});
