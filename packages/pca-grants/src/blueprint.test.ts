import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, delegate, encodeKey, generateKeyPair, mintGrant, type Capability } from '@atlasauth/pca';
import { FreshAtIssuer, checkFreshAt } from './fresh-at';
import { signerOf } from './sig';
import { BlueprintRegistry, MemoryBlueprintStore, checkBlueprints, groupKill, signBlueprint, verifyBlueprint, type AgentBlueprint, type BlueprintStore, type NewBlueprint } from './blueprint';

const NOW = 1_800_000_000_000;
const principal = generateKeyPair();
const operator = generateKeyPair();
const OP = signerOf(operator.secretKey);
const bpKey = generateKeyPair();
const BP = encodeKey(bpKey.publicKey);
const inst1 = generateKeyPair();
const inst2 = generateKeyPair();

// principal -> blueprint key (holder of the grant) -> instance (hop issued by the blueprint key)
const grant: Capability = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  holder: BP,
  goal: 'support fleet',
  envelope: { predicates: [{ verb: '*', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;
const hop = (inst: { publicKey: Uint8Array }) => delegate(grant, encodeKey(inst.publicKey), [], bpKey.secretKey);
const chainOf = (...caps: Capability[]) => caps.map((c) => ({ issuer: c.issuer, holder: c.holder }));
const I1 = chainOf(grant, hop(inst1));
const I2 = chainOf(grant, hop(inst2)); // an instance minted later, never seen by the verifier before the kill
const bare = chainOf(grant); // the agent holds the grant directly: not an instance

const base: NewBlueprint = { id: 'support-bot', key: BP, ceiling: [{ type: 'reversibility_max', class: 'reversible' }], max_depth: 2, epoch: 1, status: 'active', issued_at: NOW };
const mk = (over: Partial<NewBlueprint> = {}) => signBlueprint(operator.secretKey, { ...base, ...over });
const fresh = async (bp: AgentBlueprint = mk()) => {
  const reg = new BlueprintRegistry([OP], new MemoryBlueprintStore());
  expect((await reg.accept(bp)).ok).toBe(true);
  return reg;
};
const act = { verb: 'mail.draft', resource: 'inbox/1' };
const opts = { now: NOW, mode: 'require' as const, action: act, caveatContext: { reversibilityClass: 'reversible' } };

describe('agent blueprints: ceiling and group kill - T-588', () => {
  it('a signed record verifies, and any change to it does not', () => {
    const bp = mk();
    expect(verifyBlueprint(bp)).toBe(true);
    expect(verifyBlueprint({ ...bp, status: 'disabled' })).toBe(false);
    expect(verifyBlueprint({ ...bp, ceiling: [] })).toBe(false);
    expect(verifyBlueprint({ ...bp, epoch: 2 })).toBe(false);
    expect(verifyBlueprint({ ...bp, extra: 1 } as never)).toBe(true); // unsigned members are ignored by the body, not trusted
    expect(() => signBlueprint(operator.secretKey, { ...base, max_depth: 0 })).toThrow(RangeError);
    expect(() => signBlueprint(operator.secretKey, { ...base, epoch: -1 })).toThrow(RangeError);
  });

  it('an instance passes while the blueprint is active and the action is inside the ceiling', async () => {
    const reg = await fresh();
    expect(await checkBlueprints(I1, reg, opts)).toEqual({ decision: 'allow', governed: ['support-bot'] });
  });

  it('the ceiling is tighten-only: an action outside it is refused, and an unevaluable ceiling denies', async () => {
    const reg = await fresh();
    const r = await checkBlueprints(I1, reg, { ...opts, caveatContext: { reversibilityClass: 'irreversible' } });
    expect(r).toEqual({ decision: 'deny', code: 'ceiling_violated', blueprint: 'support-bot', failed: ['reversibility_max'] });
    expect(await checkBlueprints(I1, reg, { now: NOW, mode: 'require' })).toMatchObject({ decision: 'deny', code: 'ceiling_unevaluable' });
    // a custom evaluator is honoured, and it can say no
    expect(await checkBlueprints(I1, reg, { now: NOW, mode: 'require', evaluateCeiling: () => ({ ok: false, failed: ['x'] }) })).toMatchObject({ code: 'ceiling_violated', failed: ['x'] });
    // an empty ceiling needs no evaluator
    const open = await fresh(mk({ ceiling: [] }));
    expect(await checkBlueprints(I1, open, { now: NOW, mode: 'require' })).toMatchObject({ decision: 'allow' });
  });

  it('GROUP KILL: one signed record refuses every instance, including one the verifier never saw', async () => {
    const reg = await fresh();
    const revoked: unknown[] = [];
    const k = await groupKill(operator.secretKey, reg, BP, { now: NOW, revocation: { revoke: async (i) => { revoked.push(i); } } });
    expect(k.ok && k.record.epoch).toBe(2);
    expect(revoked).toEqual([{ kind: 'issuer', value: BP, reason: 'blueprint disabled (group kill)', revokedAt: NOW }]);
    for (const c of [I1, I2]) expect(await checkBlueprints(c, reg, opts)).toEqual({ decision: 'deny', code: 'blueprint_disabled', blueprint: 'support-bot' });
  });

  it('a verifier that only receives the record (a second registry) is killed the same way', async () => {
    const a = await fresh();
    const b = await fresh();
    const k = await groupKill(operator.secretKey, a, BP, { now: NOW });
    expect(k.ok).toBe(true);
    if (k.ok) expect(await b.accept(k.record)).toEqual({ ok: true, replaced: true });
    expect(await checkBlueprints(I2, b, opts)).toMatchObject({ decision: 'deny', code: 'blueprint_disabled' });
  });

  it('a disabled blueprint cannot be revived by an older or equal-epoch record, only by a higher one', async () => {
    const reg = await fresh();
    await groupKill(operator.secretKey, reg, BP, { now: NOW });
    expect(await reg.accept(mk({ epoch: 1 }))).toEqual({ ok: false, code: 'stale_epoch' });
    expect(await reg.accept(mk({ epoch: 2, status: 'active' }))).toEqual({ ok: false, code: 'epoch_fork' });
    expect(await checkBlueprints(I1, reg, opts)).toMatchObject({ code: 'blueprint_disabled' });
    expect(await reg.accept(mk({ epoch: 3, status: 'active' }))).toEqual({ ok: true, replaced: true });
    expect(await checkBlueprints(I1, reg, opts)).toMatchObject({ decision: 'allow' });
  });

  it('refuses records from unknown operators, forged records, an operator change and an unknown blueprint to kill', async () => {
    const reg = await fresh();
    const rogue = generateKeyPair();
    expect(await reg.accept(signBlueprint(rogue.secretKey, { ...base, epoch: 9 }))).toEqual({ ok: false, code: 'unknown_operator' });
    expect(await reg.accept({ ...mk({ epoch: 9 }), sig: mk().sig })).toEqual({ ok: false, code: 'bad_record' });
    expect(await reg.accept('x')).toEqual({ ok: false, code: 'bad_record' });
    const two = new BlueprintRegistry([OP, signerOf(rogue.secretKey)], new MemoryBlueprintStore());
    await two.accept(mk());
    expect(await two.accept(signBlueprint(rogue.secretKey, { ...base, epoch: 5 }))).toEqual({ ok: false, code: 'operator_changed' });
    expect(await groupKill(operator.secretKey, reg, 'unknown-key', { now: NOW })).toEqual({ ok: false, code: 'unknown_blueprint' });
    expect(await reg.accept(mk())).toEqual({ ok: true, replaced: false }); // the identical record again is a no-op
  });

  it('expiry, depth and a broken link are refused', async () => {
    expect(await checkBlueprints(I1, await fresh(mk({ expires_at: NOW })), opts)).toMatchObject({ code: 'blueprint_expired' });
    expect(await checkBlueprints(I1, await fresh(mk({ expires_at: NOW + 1 })), opts)).toMatchObject({ decision: 'allow' });
    const sub = generateKeyPair();
    const deep = chainOf(grant, hop(inst1), delegate(hop(inst1), encodeKey(sub.publicKey), [], inst1.secretKey));
    expect(await checkBlueprints(deep, await fresh(mk({ max_depth: 2 })), opts)).toMatchObject({ decision: 'allow' });
    expect(await checkBlueprints(deep, await fresh(mk({ max_depth: 1 })), opts)).toMatchObject({ code: 'too_deep' });
    // a hop issued by the blueprint key with no hop before it that made the key a holder
    expect(await checkBlueprints([{ issuer: BP, holder: 'x' }], await fresh(), opts)).toMatchObject({ code: 'broken_link' });
    expect(await checkBlueprints([{ issuer: 'other', holder: 'y' }, { issuer: BP, holder: 'x' }], await fresh(), opts)).toMatchObject({ code: 'broken_link' });
  });

  it('require mode refuses a chain that is not an instance; any mode lets it pass ungoverned', async () => {
    const reg = await fresh();
    expect(await checkBlueprints(bare, reg, opts)).toEqual({ decision: 'deny', code: 'no_blueprint' });
    expect(await checkBlueprints(bare, reg, { ...opts, mode: 'any' })).toEqual({ decision: 'allow', governed: [] });
  });

  it('staleness: a registry behind the epoch the caller proved it has seen escalates, never allows', async () => {
    const reg = await fresh();
    expect(await checkBlueprints(I1, reg, { ...opts, minEpoch: 1 })).toMatchObject({ decision: 'allow' });
    expect(await checkBlueprints(I1, reg, { ...opts, minEpoch: 2 })).toEqual({ decision: 'escalate', code: 'stale_blueprint_state', have: 1, need: 2 });
  });

  it('composes with fresh_at: the kill advances the verifier epoch and the token orders it', async () => {
    const reg = await fresh();
    const verifierKey = generateKeyPair();
    const issuer = new FreshAtIssuer(verifierKey.secretKey, 'inst_1', { revocation_epoch: 1, ledger_tree_size: 0, budget_version: 0, policy_revision: 1, policy_digest: 'd' });
    const k = await groupKill(operator.secretKey, reg, BP, { now: NOW, freshAt: issuer });
    expect(k.ok && k.freshAt).toBeDefined();
    expect(issuer.current.revocation_epoch).toBe(2);
    // a lagging verifier (state at epoch 1) shown the token escalates on the fresh_at check ...
    const lag = checkFreshAt(k.ok ? k.freshAt : undefined, { revocation_epoch: 1, ledger_tree_size: 0, budget_version: 0, policy_revision: 1, policy_digest: 'd' }, { signer: signerOf(verifierKey.secretKey), scope: 'inst_1', now: NOW });
    expect(lag).toMatchObject({ decision: 'escalate' });
    // ... and a blueprint registry that has not taken the record escalates on the epoch the token carried
    const stale = await fresh();
    expect(await checkBlueprints(I1, stale, { ...opts, minEpoch: 2 })).toMatchObject({ decision: 'escalate' });
  });

  it('fail closed: an unreachable store denies, malformed input denies', async () => {
    const broken: BlueprintStore = { get: async () => { throw new Error('down'); }, put: async () => {}, maxEpoch: async () => 0 };
    expect(await checkBlueprints(I1, new BlueprintRegistry([OP], broken), opts)).toEqual({ decision: 'deny', code: 'store_unreachable' });
    const reg = await fresh();
    expect(await checkBlueprints([], reg, opts)).toEqual({ decision: 'deny', code: 'bad_input' });
    expect(await checkBlueprints([{ issuer: 1 } as never], reg, opts)).toEqual({ decision: 'deny', code: 'bad_input' });
    expect(await checkBlueprints(I1, reg, { ...opts, now: 1.5 })).toEqual({ decision: 'deny', code: 'bad_input' });
    expect(new MemoryBlueprintStore()).toBeDefined();
  });
});
