import { describe, expect, it } from 'vitest';
import {
  type PCActn,
  attenuate,
  b64u,
  commitPlan,
  conditionsDigest,
  delegate,
  encodeKey,
  generateKeyPair,
  mintRoot,
  paramsDigest,
  signPCActn,
} from '@atlasauth/pca';
import {
  type FieldDisclosure,
  type NotaryAttestation,
  ATTESTED_FACT_CAVEAT,
  bindFactToPcActn,
  discloseField,
  evaluateAttestedFactCaveat,
  factMatchesPcActn,
  factRef,
  isAttestedFactCaveat,
  notarizeResponse,
  requireAttestedFact,
  verifyDisclosedField,
  verifyNotaryAttestation,
} from './index';

const NOW = 1_800_000_000_000;

/** A representative external API response (the "order service"). */
function orderResponse() {
  return {
    request: { method: 'get', url: 'https://api.shop.example/orders/42', headers: { authorization: 'Bearer secret-token', accept: 'application/json' } },
    response: {
      status: 200,
      body: { order: { id: 42, status: 'shipped', total: 1999 }, customer: { email: 'alice@example.com' }, items: ['widget', 'gadget'] },
    },
  };
}

/**
 * Build an authentic signed PCActn whose provenance commits to the given fact refs. Uses the same
 * grant/chain/plan construction the core pcactn tests use.
 */
function buildActn(opts: { trustedRefs: string[]; counter?: number }): PCActn {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const S = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [{ type: 'ttl', secs: 60 }] });
  const c1 = attenuate(grant, [{ type: 'x' }], A.secretKey);
  const sub = delegate(c1, encodeKey(S.publicKey), [], A.secretKey);
  const nodes = [{ id: 'n1', verb: 'refund', resource: 'orders/42', params_digest: paramsDigest({ amount: 1999 }), reversibility_class: 'R2', pre: { ok: true } }];
  const plan = commitPlan(nodes);
  const n = nodes[0]!;
  return signPCActn(
    {
      ver: 2,
      action: { verb: n.verb, resource: n.resource, params_digest: n.params_digest, reversibility_class: n.reversibility_class },
      grant_ref: grant.id,
      cap_chain: [grant, c1, sub],
      plan: { root: plan.root, inclusion_proof: plan.proofFor(n.id), node_id: n.id, conditions_digest: conditionsDigest(n.pre, undefined) },
      attestation: { quote_digest: 'q', epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
      provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: opts.trustedRefs },
      freshness: { beacon_ref: 'b', epoch: 1, accumulator_witness: 'w' },
      counter: opts.counter ?? 1,
      risk_claim: { r: 0.1, inputs: {} },
      aud: 'rs-1',
      iat: NOW,
      exp: NOW + 60_000,
    },
    S.secretKey,
  );
}

describe('notarizeResponse / verifyNotaryAttestation', () => {
  it('notarizes a response and verifies under the notary key', () => {
    const notaryKey = generateKeyPair();
    const { attestation, witness } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });

    expect(attestation.notary).toBe(b64u(notaryKey.publicKey));
    expect(attestation.session.method).toBe('GET');
    expect(attestation.session.responseStatus).toBe(200);
    expect(attestation.session.responseBodyCommit.alg).toBe('salted-merkle-sha256-v1');
    expect(attestation.session.responseBodyCommit.size).toBe(witness.leaves.length);
    // the request headers are committed only as a digest (the bearer token is never in the record)
    expect(JSON.stringify(attestation)).not.toContain('secret-token');

    expect(verifyNotaryAttestation(attestation, { notaryKey: b64u(notaryKey.publicKey) })).toBe(true);
    expect(verifyNotaryAttestation(attestation, { notaryKey })).toBe(true);
  });

  it('fails closed under the WRONG notary key', () => {
    const notaryKey = generateKeyPair();
    const other = generateKeyPair();
    const { attestation } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    expect(verifyNotaryAttestation(attestation, { notaryKey: b64u(other.publicKey) })).toBe(false);
  });

  it('tampered session field fails', () => {
    const notaryKey = generateKeyPair();
    const { attestation } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const tampered: NotaryAttestation = { ...attestation, session: { ...attestation.session, responseStatus: 500 } };
    expect(verifyNotaryAttestation(tampered, { notaryKey })).toBe(false);
  });

  it('tampered body root fails', () => {
    const notaryKey = generateKeyPair();
    const { attestation } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const badRoot = b64u(new Uint8Array(32).fill(7));
    const tampered: NotaryAttestation = {
      ...attestation,
      session: { ...attestation.session, responseBodyCommit: { ...attestation.session.responseBodyCommit, root: badRoot } },
    };
    expect(verifyNotaryAttestation(tampered, { notaryKey })).toBe(false);
  });

  it('tampered signature fails', () => {
    const notaryKey = generateKeyPair();
    const { attestation } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const tampered: NotaryAttestation = { ...attestation, sig: b64u(new Uint8Array(64).fill(1)) };
    expect(verifyNotaryAttestation(tampered, { notaryKey })).toBe(false);
  });
});

describe('discloseField / verifyDisclosedField (selective redaction)', () => {
  it('discloses one field + verifies its inclusion while others stay hidden', () => {
    const notaryKey = generateKeyPair();
    const { attestation, witness } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });

    const status = discloseField(attestation, witness, ['order', 'status']);
    expect(status.value).toBe('shipped');
    expect(verifyDisclosedField(attestation, status, { notaryKey })).toBe(true);

    // a DIFFERENT field is disclosed independently and also verifies
    const email = discloseField(attestation, witness, ['customer', 'email']);
    expect(email.value).toBe('alice@example.com');
    expect(verifyDisclosedField(attestation, email, { notaryKey })).toBe(true);

    // the status disclosure reveals ONLY the status — the email/total are not present in it
    expect(JSON.stringify(status)).not.toContain('alice@example.com');
    expect(JSON.stringify(status)).not.toContain('1999');

    // an array element can be disclosed by index
    const item0 = discloseField(attestation, witness, ['items', 0]);
    expect(item0.value).toBe('widget');
    expect(verifyDisclosedField(attestation, item0, { notaryKey })).toBe(true);
  });

  it('a LIE about the disclosed value fails inclusion', () => {
    const notaryKey = generateKeyPair();
    const { attestation, witness } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const status = discloseField(attestation, witness, ['order', 'status']);

    const lie: FieldDisclosure = { ...status, value: 'delivered' };
    expect(verifyDisclosedField(attestation, lie, { notaryKey })).toBe(false);

    // a lie about the salt or the path also fails
    expect(verifyDisclosedField(attestation, { ...status, salt: b64u(new Uint8Array(16).fill(9)) }, { notaryKey })).toBe(false);
    expect(verifyDisclosedField(attestation, { ...status, path: ['order', 'total'] }, { notaryKey })).toBe(false);
  });

  it('a disclosure under the wrong notary key, or with a wrong proof size, fails', () => {
    const notaryKey = generateKeyPair();
    const other = generateKeyPair();
    const { attestation, witness } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const status = discloseField(attestation, witness, ['order', 'status']);

    expect(verifyDisclosedField(attestation, status, { notaryKey: other })).toBe(false);
    expect(verifyDisclosedField(attestation, { ...status, proof: { ...status.proof, size: status.proof.size + 1 } }, { notaryKey })).toBe(false);
  });

  it('discloseField throws for an unknown path', () => {
    const notaryKey = generateKeyPair();
    const { attestation, witness } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    expect(() => discloseField(attestation, witness, ['order', 'nope'])).toThrow();
  });

  it('commits a text body as chunks when textChunkSize is set', () => {
    const notaryKey = generateKeyPair();
    const { attestation, witness } = notarizeResponse(
      { request: { method: 'GET', url: 'https://api.example/doc' }, response: { status: 200, body: 'HELLO-WORLD-1234' } },
      { notaryKey, observedAt: NOW, textChunkSize: 4 },
    );
    expect(attestation.session.responseBodyCommit.size).toBe(4);
    const c0 = discloseField(attestation, witness, ['#chunk', 0]);
    expect(c0.value).toBe('HELL');
    expect(verifyDisclosedField(attestation, c0, { notaryKey })).toBe(true);
  });
});

describe('PCA binding (factRef / bindFactToPcActn / factMatchesPcActn)', () => {
  it('binds a fact two-ways to the right PCActn; false for another', () => {
    const notaryKey = generateKeyPair();
    const { attestation } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const ref = factRef(attestation);

    // the agent builds its action committing to the fact (provenance.trusted_refs), then binds
    const actn = buildActn({ trustedRefs: [ref] });
    const bound = bindFactToPcActn(attestation, actn);

    expect(factMatchesPcActn(bound, actn)).toBe(true);

    // a DIFFERENT action (also committing the ref, but a different digest) does not match the binding
    const otherActn = buildActn({ trustedRefs: [ref], counter: 2 });
    expect(factMatchesPcActn(bound, otherActn)).toBe(false);

    // an unbound attestation never matches
    expect(factMatchesPcActn(attestation, actn)).toBe(false);
  });

  it('fails when the action does NOT commit to the fact ref (one-way only)', () => {
    const notaryKey = generateKeyPair();
    const { attestation } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const actn = buildActn({ trustedRefs: [] }); // action forgot to commit the fact
    const bound = bindFactToPcActn(attestation, actn);
    expect(factMatchesPcActn(bound, actn)).toBe(false);
  });

  it('swapping the fact for a different attestation breaks the action-side commitment', () => {
    const notaryKey = generateKeyPair();
    const good = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW }).attestation;
    const evil = notarizeResponse(
      { request: { method: 'GET', url: 'https://api.shop.example/orders/42' }, response: { status: 200, body: { order: { status: 'shipped' } } } },
      { notaryKey, observedAt: NOW + 1 },
    ).attestation;

    const actn = buildActn({ trustedRefs: [factRef(good)] });
    const boundEvil = bindFactToPcActn(evil, actn);
    expect(factMatchesPcActn(boundEvil, actn)).toBe(false); // evil's ref is not in trusted_refs
  });
});

describe('policy caveat: require an attested external fact', () => {
  it('admits only when the disclosed field satisfies the caveat', () => {
    const notaryKey = generateKeyPair();
    const { attestation, witness } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const status = discloseField(attestation, witness, ['order', 'status']);

    // "only refund if the notarized order status == 'shipped'"
    const caveat = requireAttestedFact({ notary: notaryKey, path: ['order', 'status'], equals: 'shipped', url: 'https://api.shop.example/orders/42' });
    expect(isAttestedFactCaveat(caveat)).toBe(true);
    expect(caveat.type).toBe(ATTESTED_FACT_CAVEAT);

    expect(evaluateAttestedFactCaveat(caveat, { attestation, disclosure: status }).ok).toBe(true);
  });

  it('refuses when the attested value is not what the policy requires', () => {
    const notaryKey = generateKeyPair();
    // this order is 'processing', not 'shipped'
    const { attestation, witness } = notarizeResponse(
      { request: { method: 'GET', url: 'https://api.shop.example/orders/42' }, response: { status: 200, body: { order: { status: 'processing' } } } },
      { notaryKey, observedAt: NOW },
    );
    const status = discloseField(attestation, witness, ['order', 'status']);
    const caveat = requireAttestedFact({ notary: notaryKey, path: ['order', 'status'], equals: 'shipped' });
    const res = evaluateAttestedFactCaveat(caveat, { attestation, disclosure: status });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/does not satisfy/);
  });

  it('refuses a wrong-notary, wrong-URL, or wrong-path disclosure', () => {
    const notaryKey = generateKeyPair();
    const other = generateKeyPair();
    const { attestation, witness } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const status = discloseField(attestation, witness, ['order', 'status']);

    // wrong notary in the caveat
    expect(evaluateAttestedFactCaveat(requireAttestedFact({ notary: other, path: ['order', 'status'], equals: 'shipped' }), { attestation, disclosure: status }).ok).toBe(false);
    // URL mismatch
    expect(
      evaluateAttestedFactCaveat(requireAttestedFact({ notary: notaryKey, path: ['order', 'status'], equals: 'shipped', url: 'https://evil.example/' }), { attestation, disclosure: status }).ok,
    ).toBe(false);
    // caveat requires a DIFFERENT path than the one disclosed
    expect(evaluateAttestedFactCaveat(requireAttestedFact({ notary: notaryKey, path: ['order', 'total'], equals: 'shipped' }), { attestation, disclosure: status }).ok).toBe(false);
  });

  it('with bindToPcActn, admits only when the fact is bound to the supplied PCActn', () => {
    const notaryKey = generateKeyPair();
    const { attestation, witness } = notarizeResponse(orderResponse(), { notaryKey, observedAt: NOW });
    const status = discloseField(attestation, witness, ['order', 'status']);

    const actn = buildActn({ trustedRefs: [factRef(attestation)] });
    const bound = bindFactToPcActn(attestation, actn);
    const caveat = requireAttestedFact({ notary: notaryKey, path: ['order', 'status'], equals: 'shipped', bindToPcActn: true });

    // bound attestation + matching PCActn => admit
    expect(evaluateAttestedFactCaveat(caveat, { attestation: bound, disclosure: status, pcActn: actn }).ok).toBe(true);
    // unbound attestation => refuse
    expect(evaluateAttestedFactCaveat(caveat, { attestation, disclosure: status, pcActn: actn }).ok).toBe(false);
    // no PCActn supplied => refuse
    expect(evaluateAttestedFactCaveat(caveat, { attestation: bound, disclosure: status }).ok).toBe(false);
  });
});
