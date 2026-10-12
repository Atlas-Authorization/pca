import { describe, expect, it } from 'vitest';
import { mintRoot } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn } from './pcactn';
import * as vm from './policy-vm';

/**
 * R6-CORE-04 follow-up: deriveDecideInput used to fall back to the presented artifact's own chain root when the caller
 * passed no `ctx.grant`, so the Policy VM evaluated an attacker-minted root's predicates (a self-granted `*`). It now
 * fails closed with a typed error: the caller must pass the grant from its own store.
 */
describe('deriveDecideInput: no ctx.grant is a typed error, never the chain root', () => {
  const attacker = generateKeyPair();
  const self = mintRoot({ principalSecret: attacker.secretKey, principalPublic: encodeKey(attacker.publicKey), holder: encodeKey(attacker.publicKey), caveats: [{ type: 'ttl', secs: 3600 }] });
  const plan = [{ id: 'n', verb: 'github.delete_repo', resource: 'repo:prod', reversibility_class: 'irreversible' as const }];
  const p = buildPCActn({ grant: self, chain: [self], plan, nodeId: 'n', counter: 1, signerSecret: attacker.secretKey, aud: 'rs', now: 1_000 });
  const base = { plan, params: {}, risk: {}, budget: { B: 1, tau: 1_000, asOf: 1_000 }, now: 1_000 };

  it('throws DecideInputGrantRequired when ctx.grant is omitted', () => {
    expect(typeof (vm as Record<string, unknown>)['DecideInputGrantRequired']).toBe('function');
    let err: unknown;
    try {
      vm.deriveDecideInput(p, base as Parameters<typeof vm.deriveDecideInput>[1]);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf((vm as unknown as { DecideInputGrantRequired: new () => Error }).DecideInputGrantRequired);
    expect((err as { code?: string }).code).toBe('grant_required');
  });

  it('uses exactly the supplied grant (never the chain root) when given', () => {
    const owner = generateKeyPair();
    const stored = mintRoot({ principalSecret: owner.secretKey, principalPublic: encodeKey(owner.publicKey), holder: encodeKey(owner.publicKey), caveats: [{ type: 'ttl', secs: 3600 }] });
    const d = vm.deriveDecideInput(p, { ...base, grant: stored });
    expect(d.grant).toBe(stored);
  });
});
