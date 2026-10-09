import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  type Capability,
  type KeyPair,
  b64u,
  delegate,
  generateKeyPair,
  mintGrant,
} from '@atlasauth/pca';
import {
  Attr,
  type Policy,
  capabilityAttributes,
  decryptWithCapability,
  encryptToolPayload,
  keygenForCapability,
  setup,
} from './index';

/** Mint a real PCA root grant whose policy envelope names `verb` on `resource`, bound to `holder`. */
function mintCap(args: {
  principal: KeyPair;
  holder: string;
  verb: string | string[];
  resource: string;
}): Capability {
  return mintGrant({
    principalSecret: args.principal.secretKey,
    principalPublic: b64u(args.principal.publicKey),
    holder: args.holder,
    goal: 'read a ticket for the user',
    envelope: {
      predicates: [{ verb: args.verb, resource: args.resource }],
      caveats: [],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  }).grant;
}

describe('PCA composition: capability -> key -> decrypt', () => {
  it('capabilityAttributes derives holder/verb/resource from a signed grant', () => {
    const principal = generateKeyPair();
    const agent = generateKeyPair();
    const agentPub = b64u(agent.publicKey);
    const cap = mintCap({ principal, holder: agentPub, verb: 'read', resource: '/tickets/*' });

    const attrs = capabilityAttributes(cap);
    expect(attrs.has(Attr.holder(agentPub))).toBe(true);
    expect(attrs.has(Attr.verb('read'))).toBe(true);
    expect(attrs.has(Attr.resource('/tickets/*'))).toBe(true);
  });

  it('round-trips a tool payload for a SATISFYING capability', () => {
    const { mpk, msk } = setup();
    const principal = generateKeyPair();
    const agent = generateKeyPair();
    const agentPub = b64u(agent.publicKey);
    const cap = mintCap({ principal, holder: agentPub, verb: 'read', resource: '/tickets/*' });

    // Policy: only an agent that both IS this holder AND carries verb:read may read the result.
    const policy: Policy = { allOf: [{ attr: Attr.holder(agentPub) }, { attr: Attr.verb('read') }] };
    const payload = { ticketId: 'T-42', body: 'customer PII', tags: ['urgent'] };
    const { ciphertext } = encryptToolPayload(mpk, policy, payload);

    const key = keygenForCapability(msk, cap);
    const res = decryptWithCapability(key, ciphertext);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.payload).toEqual(payload);
  });

  it('DENIES a capability that does not satisfy the policy (wrong holder / wrong verb)', () => {
    const { mpk, msk } = setup();
    const principal = generateKeyPair();
    const agentA = b64u(generateKeyPair().publicKey);
    const agentB = b64u(generateKeyPair().publicKey);

    const policy: Policy = { allOf: [{ attr: Attr.holder(agentA) }, { attr: Attr.verb('read') }] };
    const { ciphertext } = encryptToolPayload(mpk, policy, { secret: true });

    // Different holder, and only verb:write -> fails both conjuncts.
    const capB = mintCap({ principal, holder: agentB, verb: 'write', resource: '/tickets/*' });
    const keyB = keygenForCapability(msk, capB);
    const res = decryptWithCapability(keyB, ciphertext);
    expect(res.ok).toBe(false);

    // Same holder but the policy also requires a scope the capability does not carry.
    const scoped: Policy = { allOf: [{ attr: Attr.holder(agentA) }, { attr: Attr.scope('pii') }] };
    const capA = mintCap({ principal, holder: agentA, verb: 'read', resource: '/tickets/*' });
    const { ciphertext: ct2 } = encryptToolPayload(mpk, scoped, { secret: true });
    expect(decryptWithCapability(keygenForCapability(msk, capA), ct2).ok).toBe(false);
  });

  it('extraAttributes extend the capability-derived key (e.g. out-of-band scopes)', () => {
    const { mpk, msk } = setup();
    const principal = generateKeyPair();
    const agentPub = b64u(generateKeyPair().publicKey);
    const cap = mintCap({ principal, holder: agentPub, verb: 'read', resource: '/tickets/*' });

    const policy: Policy = { allOf: [{ attr: Attr.verb('read') }, { attr: Attr.scope('pii') }] };
    const { ciphertext } = encryptToolPayload(mpk, policy, { ok: 1 });

    // Without the scope: denied.
    expect(decryptWithCapability(keygenForCapability(msk, cap), ciphertext).ok).toBe(false);
    // With the scope granted out-of-band into the key: allowed.
    const key = keygenForCapability(msk, cap, [Attr.scope('pii')]);
    expect(decryptWithCapability(key, ciphertext).ok).toBe(true);
  });

  it('delegation rebinds the holder, so a holder-bound payload no longer decrypts for the sub-agent', () => {
    const { mpk, msk } = setup();
    const principal = generateKeyPair();
    const agent = generateKeyPair();
    const subAgent = generateKeyPair();
    const agentPub = b64u(agent.publicKey);
    const subPub = b64u(subAgent.publicKey);

    const root = mintCap({ principal, holder: agentPub, verb: 'read', resource: '/tickets/*' });
    // Agent delegates to a sub-agent (holder rebinds to subPub; the envelope/verb is preserved).
    const child = delegate(root, subPub, [], agent.secretKey);

    // Payload readable only by the ORIGINAL holder.
    const holderPolicy: Policy = { attr: Attr.holder(agentPub) };
    const { ciphertext } = encryptToolPayload(mpk, holderPolicy, { note: 'for the root agent only' });

    expect(decryptWithCapability(keygenForCapability(msk, root), ciphertext).ok).toBe(true);
    // The sub-agent's capability carries holder:subPub, not holder:agentPub -> denied.
    expect(decryptWithCapability(keygenForCapability(msk, child), ciphertext).ok).toBe(false);

    // But a payload gated on the preserved verb is still readable by the delegate.
    const verbPolicy: Policy = { attr: Attr.verb('read') };
    const { ciphertext: ct2 } = encryptToolPayload(mpk, verbPolicy, { note: 'any reader' });
    expect(decryptWithCapability(keygenForCapability(msk, child), ct2).ok).toBe(true);
  });
});
