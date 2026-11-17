import { DEFAULT_RISK_POLICY, b64u, generateKeyPair, mintGrant, type Caveat, type Predicate } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { toolDigest } from './actions';
import { ConfigError, parseConfig } from './config';
import { Engine } from './engine';
import { GrantOverlay } from './grant-overlay';
import { createIssue, readIssue, rules } from './test-support/fakes';
import { ALL_TOOLS, setup } from './test-support/harness';

const guardian = generateKeyPair();
const signer = b64u(guardian.publicKey);
const grantOf = (predicates: Predicate[], caveats: Caveat[] = [], key = guardian) =>
  mintGrant({ principalSecret: key.secretKey, principalPublic: b64u(key.publicKey), holder: b64u(generateKeyPair().publicKey), goal: 'test', envelope: { predicates, caveats, agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const call = (verb: string, params: Record<string, unknown> = {}, resource = 'x') => ({ verb, resource, params, reversibility: 'reversible', blastRadius: 0.1 });
const NOW = 1_800_000_000_000;

describe('an issued grant, loaded', () => {
  it('is accepted only under the key that signed it', () => {
    const g = grantOf([{ verb: 'gh.create_issue' }]);
    expect(() => new GrantOverlay(g, signer)).not.toThrow();
    expect(() => new GrantOverlay(g, b64u(generateKeyPair().publicKey))).toThrow(ConfigError);
  });
  it('is refused when its content was edited after signing', () => {
    const g = grantOf([{ verb: 'gh.create_issue' }]);
    const edited = JSON.parse(JSON.stringify(g)) as typeof g;
    (edited.caveats[0] as { predicates?: Predicate[] }).predicates = [{ verb: '*' }];
    expect(() => new GrantOverlay(edited, signer)).toThrow(ConfigError);
  });
  it('is refused when it is not a grant at all', () => {
    expect(() => GrantOverlay.load('g.json', signer, () => '{"nope":1}')).toThrow(ConfigError);
    expect(() => GrantOverlay.load('g.json', signer, () => 'not json')).toThrow(/cannot be read/);
  });
});

describe('what the grant admits', () => {
  it('admits its verbs and refuses every other, and a parameter above its cap', async () => {
    const o = new GrantOverlay(grantOf([{ verb: 'gh.create_issue', where: [{ field: 'action.params.n', op: 'lte', value: 5 }] }]), signer);
    expect(await o.decide(call('gh.create_issue', { n: 5 }), NOW)).toEqual({ outcome: 'auto' });
    expect((await o.decide(call('gh.create_issue', { n: 6 }), NOW)).outcome).toBe('deny');
    expect((await o.decide(call('gh.create_issue', {}), NOW)).outcome).toBe('deny');
    expect((await o.decide(call('gh.delete_repo', { n: 1 }), NOW)).outcome).toBe('deny');
  });
  it('refuses once the grant has expired, and past its rate caveat', async () => {
    const exp = new GrantOverlay(grantOf([{ verb: 'gh.create_issue' }], [{ type: 'expires', at: NOW - 1 }]), signer);
    expect((await exp.decide(call('gh.create_issue'), NOW)).outcome).toBe('deny');
    const rate = new GrantOverlay(grantOf([{ verb: 'gh.create_issue' }], [{ type: 'rate', max: 2, per_secs: 60 }]), signer);
    for (let i = 0; i < 2; i++) {
      expect((await rate.decide(call('gh.create_issue'), NOW + i)).outcome).toBe('auto');
      await rate.record(NOW + i);
    }
    expect((await rate.decide(call('gh.create_issue'), NOW + 3)).outcome).toBe('deny');
    expect((await rate.decide(call('gh.create_issue'), NOW + 61_000)).outcome).toBe('auto');
  });
});

describe('through the proxy in enforce mode', () => {
  const held = () => rules({ create_issue: { policy: 'approve', effect: 'write', pin: toolDigest(createIssue) } });
  const make = (overlay: GrantOverlay) => setup({ mode: 'enforce' }, held(), ALL_TOOLS, (cfg, candidates) => Engine.create({ cfg, candidates, overlay }));

  it('lets a call the grant admits through with no human, and refuses a call it does not, whatever the rule says', async () => {
    const t = make(new GrantOverlay(grantOf([{ verb: 'gh.issue.create' }]), signer));
    const ok = await t.call('create_issue', { title: 'hello' });
    expect(t.denied(ok)).toBe('');
    expect(t.up.calls.map((c) => (c.params as { name?: string })?.name)).toContain('create_issue');
    // read_issue's rule is `allow`, but the grant does not name it
    expect(t.denied(await t.call('read_issue', { id: 1 }))).toMatch(/grant_denied/);
    // delete_repo is `deny` in the rules: a grant cannot loosen that
    expect(t.denied(await t.call('delete_repo', { name: 'x' }))).toMatch(/policy_deny|grant_denied/);
  });

  it('refuses a call that exceeds a cap the human signed', async () => {
    const t = setup({ mode: 'enforce' }, rules({ read_issue: { policy: 'allow', effect: 'read', pin: toolDigest(readIssue) } }), ALL_TOOLS, (cfg, candidates) =>
      Engine.create({ cfg, candidates, overlay: new GrantOverlay(grantOf([{ verb: 'gh.issue.read', where: [{ field: 'action.params.id', op: 'lte', value: 10 }] }]), signer) }),
    );
    expect(t.denied(await t.call('read_issue', { id: 10 }))).toBe('');
    expect(t.denied(await t.call('read_issue', { id: 11 }))).toMatch(/grant_denied/);
  });
});

describe('the config key', () => {
  it('needs a file and a 43-character signer', () => {
    expect(parseConfig({ mcp: { ns: 'x' }, agent: { issuedGrant: { file: 'g.json', signer } } }).agent.issuedGrant).toEqual({ file: 'g.json', signer });
    expect(() => parseConfig({ mcp: { ns: 'x' }, agent: { issuedGrant: { file: 'g.json', signer: 'short' } } })).toThrow(ConfigError);
    expect(() => parseConfig({ mcp: { ns: 'x' }, agent: { issuedGrant: { file: 'g.json', signer, extra: 1 } } })).toThrow(ConfigError);
  });
});
