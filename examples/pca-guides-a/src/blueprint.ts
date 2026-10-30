/**
 * Agent blueprints: a fleet ceiling and a group kill for every instance minted from one template.
 * Every outcome below is printed; the script exits non-zero if any differs from the guide.
 */
import { DEFAULT_RISK_POLICY, delegate, encodeKey, generateKeyPair, mintGrant, type Capability } from '@atlasauth/pca';
import { BlueprintRegistry, MemoryBlueprintStore, checkBlueprints, groupKill, signBlueprint, type NewBlueprint } from '@atlasauth/pca-grants';
import { expectEq, run } from './check.js';

const NOW = 1_800_000_000_000;
const principal = generateKeyPair(); // owns the authority
const operator = generateKeyPair(); // signs blueprint records, and is the only key that can group-kill
const blueprintKey = generateKeyPair(); // the template's own key: it issues every instance hop
const BP = encodeKey(blueprintKey.publicKey);
const OPERATOR = encodeKey(operator.publicKey);

// principal -> blueprint key (holder of the grant) -> each instance (a hop issued by the blueprint key)
const grant: Capability = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  holder: BP,
  goal: 'support fleet',
  envelope: { predicates: [{ verb: '*', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;
const instanceChain = () => {
  const instance = generateKeyPair();
  const hop = delegate(grant, encodeKey(instance.publicKey), [], blueprintKey.secretKey);
  return [grant, hop].map((c) => ({ issuer: c.issuer, holder: c.holder }));
};
const directChain = [{ issuer: grant.issuer, holder: grant.holder }]; // the agent holds the grant itself: not an instance

const template: NewBlueprint = { id: 'support-bot', key: BP, ceiling: [{ type: 'reversibility_max', class: 'reversible' }], max_depth: 2, epoch: 1, status: 'active', issued_at: NOW };
const record = (over: Partial<NewBlueprint> = {}) => signBlueprint(operator.secretKey, { ...template, ...over });
const opts = (reversibilityClass: string) => ({ now: NOW, mode: 'require' as const, action: { verb: 'mail.draft', resource: 'inbox/1' }, caveatContext: { reversibilityClass } });
const out = (r: { decision: string; code?: string }) => [r.decision, r.code ?? null];

run(async () => {
  const registry = new BlueprintRegistry([OPERATOR], new MemoryBlueprintStore());
  expectEq('the verifier accepts the operator-signed record', await registry.accept(record()), { ok: true, replaced: true });

  const first = instanceChain();
  expectEq('an instance inside the ceiling', await checkBlueprints(first, registry, opts('reversible')), { decision: 'allow', governed: ['support-bot'] });
  expectEq('the same instance outside the ceiling', out(await checkBlueprints(first, registry, opts('irreversible'))), ['deny', 'ceiling_violated']);
  expectEq('a chain that skips the blueprint (mode require)', out(await checkBlueprints(directChain, registry, opts('reversible'))), ['deny', 'no_blueprint']);

  const rogue = generateKeyPair();
  expectEq('a record from a key the verifier does not trust', await registry.accept(signBlueprint(rogue.secretKey, { ...template, epoch: 9 })), { ok: false, code: 'unknown_operator' });

  // group kill: one record, every instance, including ones created after it
  const killed = await groupKill(operator.secretKey, registry, BP, { now: NOW });
  expectEq('group kill moves the epoch forward', killed.ok && killed.record.epoch, 2);
  expectEq('the instance seen before the kill is refused', out(await checkBlueprints(first, registry, opts('reversible'))), ['deny', 'blueprint_disabled']);
  expectEq('an instance minted after the kill is refused too', out(await checkBlueprints(instanceChain(), registry, opts('reversible'))), ['deny', 'blueprint_disabled']);

  const behind = await checkBlueprints(first, registry, { ...opts('reversible'), minEpoch: 5 });
  expectEq('a caller who has seen a newer epoch makes a lagging verifier ask a human', behind, { decision: 'escalate', code: 'stale_blueprint_state', have: 2, need: 5 });

  // reviving needs a strictly higher epoch signed by the operator
  expectEq('an older record cannot revive it', await registry.accept(record({ epoch: 1 })), { ok: false, code: 'stale_epoch' });
  expectEq('an equal-epoch record with other content is a fork', await registry.accept(record({ epoch: 2 })), { ok: false, code: 'epoch_fork' });
  expectEq('a higher epoch re-enables it', await registry.accept(record({ epoch: 3 })), { ok: true, replaced: true });
  expectEq('and instances pass again', out(await checkBlueprints(first, registry, opts('reversible'))), ['allow', null]);
});
