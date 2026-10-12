import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  type Capability,
  type KeyPair,
  b64u,
  delegate,
  generateKeyPair,
  goalCommitOf,
  mintGrant,
  encodeMlDsaPublicKey,
  mintRoot,
  mlDsa65Keygen,
} from '@atlasauth/pca';
import {
  Attr,
  type Policy,
  capabilityAttributes,
  decryptText,
  decryptWithCapability,
  encryptForPolicy,
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

    // R3-09: without the verified chain a delegated hop carries NO envelope attributes (fail closed).
    expect(decryptWithCapability(keygenForCapability(msk, child), encryptToolPayload(mpk, { attr: Attr.verb('read') }, { n: 1 }).ciphertext).ok).toBe(false);
    // But a payload gated on the preserved verb is still readable by the delegate WITH the verified chain (attributes come from the root).
    const chainOpts = { chain: [root, child], principal: b64u(principal.publicKey) };
    const verbPolicy: Policy = { attr: Attr.verb('read') };
    const { ciphertext: ct2 } = encryptToolPayload(mpk, verbPolicy, { note: 'any reader' });
    expect(decryptWithCapability(keygenForCapability(msk, child, [], chainOpts), ct2).ok).toBe(true);
  });
});

describe('RT-08: verb x resource pairing is preserved', () => {
  function multi(): Capability {
    const principal = generateKeyPair();
    return mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: b64u(principal.publicKey),
      holder: b64u(generateKeyPair().publicKey),
      goal: 'g',
      envelope: {
        predicates: [
          { verb: 'read', resource: '/public/*' },
          { verb: 'write', resource: '/acct/42' },
        ],
        caveats: [],
        agent_binding: {},
        risk_policy: DEFAULT_RISK_POLICY,
      },
    }).grant;
  }
  it('read:/public/* + write:/acct/42 does not open "read /acct/42"', () => {
    const cap = multi();
    const { mpk, msk } = setup();
    const key = keygenForCapability(msk, cap);
    const bad = encryptForPolicy(mpk, { attr: Attr.act('read', '/acct/42') }, 'secret');
    expect(decryptText(key, bad.ciphertext)).toBeNull();
    const ok = encryptForPolicy(mpk, { attr: Attr.act('write', '/acct/42') }, 'yes');
    expect(decryptText(key, ok.ciphertext)).toBe('yes');
    const attrs = capabilityAttributes(cap);
    expect(attrs.has(Attr.verb('read'))).toBe(false);
    expect(attrs.has(Attr.resource('/acct/42'))).toBe(false);
  });
  it('the old flat-token policy (the PoC) no longer opens', () => {
    const cap = multi();
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(
      mpk,
      { allOf: [{ attr: 'verb:read' }, { attr: 'resource:/acct/42' }] },
      'secret',
    );
    expect(decryptText(keygenForCapability(msk, cap), ciphertext)).toBeNull();
  });
});

describe('R2-07: scope attributes come only from the root capability', () => {
  const setupChain = (rootCaveats: { type: string; value?: string }[] = []) => {
    const P = generateKeyPair(), A = generateKeyPair();
    const root = mintCap({ principal: P, holder: b64u(A.publicKey), verb: 'read', resource: '/public/*' });
    const withRoot = rootCaveats.length ? { ...root, caveats: [...root.caveats, ...rootCaveats] } : root;
    return { P, A, root: withRoot };
  };
  it('a delegatee appending scope:admin does not obtain a scope:admin key', () => {
    const { P, A, root } = setupChain();
    const child = delegate(root, b64u(A.publicKey), [{ type: 'scope', value: 'admin' } as never], A.secretKey);
    const chain = [root, child];
    // with the verified chain: no scope token (root carried none)
    expect([...capabilityAttributes(child, { chain, principal: b64u(P.publicKey) })].filter((a) => a.startsWith('scope:'))).toEqual([]);
    // without a chain a delegated hop yields no scope tokens either
    expect([...capabilityAttributes(child)].some((a) => a.startsWith('scope:'))).toBe(false);
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, { attr: Attr.scope('admin') }, 'admin-only secret');
    expect(decryptText(keygenForCapability(msk, child, [], { chain, principal: b64u(P.publicKey) }), ciphertext)).toBeNull();
    expect(decryptText(keygenForCapability(msk, child), ciphertext)).toBeNull();
  });
  it('an invalid or foreign chain yields no attributes; a root capability keeps its own scope caveats', () => {
    const { P, A, root } = setupChain();
    const child = delegate(root, b64u(A.publicKey), [], A.secretKey);
    expect(capabilityAttributes(child, { chain: [root, child], principal: b64u(generateKeyPair().publicKey) }).size).toBe(0);
    expect(capabilityAttributes(child, { chain: [root] }).size).toBe(0);
    expect(capabilityAttributes(child, { chain: [root, child], principal: b64u(P.publicKey) }).size).toBeGreaterThan(0);
  });
});

describe('R3-09: a delegatee-appended envelope cannot self-grant act/verb/resource attributes', () => {
  it('root without an envelope: a child envelope {verb:*,resource:*} yields no act tokens', () => {
    const P = generateKeyPair(), H = generateKeyPair(), A = generateKeyPair();
    const root = mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(H.publicKey), caveats: [{ type: 'expires', at: Date.now() + 1e7 } as never] });
    const env = { type: 'envelope', goal_commit: goalCommitOf('x', 's'), predicates: [{ verb: '*', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } as never;
    const child = delegate(root, b64u(A.publicKey), [env], H.secretKey);
    const attrs = [...capabilityAttributes(child, { chain: [root, child], principal: b64u(P.publicKey) })];
    expect(attrs.filter((a) => /^(act|verb|resource):/.test(a))).toEqual([]);
    expect([...capabilityAttributes(child)].filter((a) => /^(act|verb|resource):/.test(a))).toEqual([]);
  });
});

// R3-01: a pure-PQ root is verified under the principal's pin, never its own pq_pk.
describe('R3-01: forged pure-PQ root', () => {
  it('capabilityAttributes yields nothing for a forged root, and the genuine one only under the pin', () => {
    const victim = generateKeyPair();
    const vPub = b64u(victim.publicKey);
    const atk = generateKeyPair();
    const aPub = b64u(atk.publicKey);
    const vMl = mlDsa65Keygen(new Uint8Array(32).fill(7));
    const aMl = mlDsa65Keygen(new Uint8Array(32).fill(9));
    const caveats = [{ type: 'scope', value: 'billing' }] as never;
    const forged = mintRoot({ principalSecret: atk.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: aMl } });
    expect(capabilityAttributes(forged, { chain: [forged], principal: vPub }).size).toBe(0);
    const pins = { [vPub]: encodeMlDsaPublicKey(vMl.publicKey) };
    expect(capabilityAttributes(forged, { chain: [forged], principal: vPub, pqPins: pins }).size).toBe(0);
    const genuine = mintRoot({ principalSecret: victim.secretKey, principalPublic: vPub, holder: aPub, caveats, suite: { alg: 'ml-dsa-65', mlDsa: vMl } });
    expect(capabilityAttributes(genuine, { chain: [genuine], principal: vPub }).size).toBe(0);
    expect(capabilityAttributes(genuine, { chain: [genuine], principal: vPub, pqPins: pins }).has(Attr.scope('billing'))).toBe(true);
  });
});
