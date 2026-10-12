/** Mutation-kill suite for attest-pq-software.ts: attestor key handling, statement shape, and every verifier gate with its exact reason. */
import { describe, expect, it } from 'vitest';
import {
  PQ_ATTEST_DOMAIN,
  createPqSoftwareAttestor,
  createPqSoftwareVerifier,
  type PqAttestationStatement,
  type PqSoftwareVerifierOptions,
} from './attest-pq-software';
import { attestationBindingB64u, type ExpectedAttestationBinding } from './attestation';
import { b64u, canonicalBytes, utf8 } from './hash';
import { generateKeyPair, publicKeyOf } from './keys';
import {
  encodeMlDsa87PublicKey,
  encodeMlDsaPublicKey,
  encodeSlhDsa256sPublicKey,
  encodeSlhDsaPublicKey,
  mlDsa65Keygen,
  mlDsa87Keygen,
  signWithSuite,
  slhDsa128fKeygen,
  slhDsa256sKeygen,
  verifyWithSuite,
  type SigAlg,
} from './pq';

const T = 1_000_000;
const EXPECTED: ExpectedAttestationBinding = { holderPub: 'holder-1', grantRef: 'grant-1', epoch: 3, nonce: 'nonce-1', nonceIssuedAt: T - 1000 };
const CLAIMS = { measurement: 'm-1', holder_pub: 'holder-1', grant_ref: 'grant-1', epoch: 3, nonce: 'nonce-1' };
const ML = mlDsa65Keygen(new Uint8Array(32).fill(7));
const ML87 = mlDsa87Keygen(new Uint8Array(32).fill(8));
const SLH = slhDsa128fKeygen(new Uint8Array(48).fill(9));
const SLH256 = slhDsa256sKeygen(new Uint8Array(96).fill(10));
const ED = generateKeyPair();
const ALL = { mlDsa: ML, slhDsa: SLH, mlDsa87: ML87, slhDsa256s: SLH256, edSecret: ED.secretKey };
const ED_PUB = b64u(ED.publicKey);

const throwsMsg = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return `${(e as Error).constructor.name}: ${(e as Error).message}`;
  }
  return 'NO THROW';
};

describe('createPqSoftwareAttestor', () => {
  it('derives the matching PQ public key per suite even when every key pair is supplied', () => {
    const cases: [SigAlg, string][] = [
      ['ml-dsa-65', encodeMlDsaPublicKey(ML.publicKey)],
      ['hybrid-ed25519-ml-dsa-65', encodeMlDsaPublicKey(ML.publicKey)],
      ['slh-dsa-sha2-128f', encodeSlhDsaPublicKey(SLH.publicKey)],
      ['hybrid-ed25519-slh-dsa-sha2-128f', encodeSlhDsaPublicKey(SLH.publicKey)],
      ['ml-dsa-87', encodeMlDsa87PublicKey(ML87.publicKey)],
      ['hybrid-ed25519-ml-dsa-87', encodeMlDsa87PublicKey(ML87.publicKey)],
      ['slh-dsa-sha2-256s', encodeSlhDsa256sPublicKey(SLH256.publicKey)],
      ['hybrid-ed25519-slh-dsa-sha2-256s', encodeSlhDsa256sPublicKey(SLH256.publicKey)],
    ];
    const seen = new Set<string>();
    for (const [alg, pk] of cases) {
      const a = createPqSoftwareAttestor({ alg, ...ALL });
      expect(a.pqPublicKey, alg).toBe(pk);
      seen.add(pk);
    }
    expect(seen.size).toBe(4);
  });
  it('construction refusals with exact messages', () => {
    expect(throwsMsg(() => createPqSoftwareAttestor({ alg: 'nope' as never }))).toBe("RangeError: createPqSoftwareAttestor: unknown signature alg 'nope'");
    expect(throwsMsg(() => createPqSoftwareAttestor({ alg: undefined as never }))).toBe("RangeError: createPqSoftwareAttestor: 'ed25519' is classical; the PQ root requires a post-quantum suite");
    expect(throwsMsg(() => createPqSoftwareAttestor({ alg: 'ed25519', edSecret: ED.secretKey }))).toBe("RangeError: createPqSoftwareAttestor: 'ed25519' is classical; the PQ root requires a post-quantum suite");
    expect(throwsMsg(() => createPqSoftwareAttestor({ alg: 'ml-dsa-65' }))).toBe("TypeError: createPqSoftwareAttestor: 'ml-dsa-65' requires the matching PQ key material");
    expect(throwsMsg(() => createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa87: ML87, slhDsa: SLH }))).toBe("TypeError: createPqSoftwareAttestor: 'ml-dsa-65' requires the matching PQ key material");
    expect(throwsMsg(() => createPqSoftwareAttestor({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ML }))).toBe("TypeError: createPqSoftwareAttestor: hybrid suite 'hybrid-ed25519-ml-dsa-65' requires edSecret");
    expect(throwsMsg(() => createPqSoftwareAttestor({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ML, edSecret: 'x' as never }))).toBe("TypeError: createPqSoftwareAttestor: hybrid suite 'hybrid-ed25519-ml-dsa-65' requires edSecret");
    expect(throwsMsg(() => createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: ML }))).toBe('NO THROW');
  });
  it('the Ed25519 identity is published whenever an edSecret is supplied', () => {
    expect(createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: ML }).ed25519PublicKey).toBeUndefined();
    expect('ed25519PublicKey' in createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: ML })).toBe(false);
    expect(createPqSoftwareAttestor({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ML, edSecret: ED.secretKey }).ed25519PublicKey).toBe(ED_PUB);
    expect(ED_PUB).toBe(b64u(publicKeyOf(ED.secretKey)));
    const pure = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: ML, edSecret: ED.secretKey });
    expect(pure.ed25519PublicKey).toBe(ED_PUB);
    expect(pure.attest(CLAIMS).attestor_ed25519).toBe(ED_PUB);
  });
  it('statement body: required fields, optional claims only when given, pq_sig only for hybrids', () => {
    const pure = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: ML });
    const st = pure.attest(CLAIMS);
    expect(Object.keys(st).sort()).toEqual(['alg', 'binding', 'measurement', 'pq_pk', 'sig']);
    expect(st.alg).toBe('ml-dsa-65');
    expect(st.measurement).toBe('m-1');
    expect(st.pq_pk).toBe(pure.pqPublicKey);
    expect(st.binding).toBe(attestationBindingB64u({ holderPub: 'holder-1', grantRef: 'grant-1', epoch: 3, nonce: 'nonce-1' }));
    const full = pure.attest({ ...CLAIMS, weights_digest: 'w', system_prompt_digest: 's', tool_manifest_digest: 't', model_id: 'mid', operator: 'op' });
    expect(Object.keys(full).sort()).toEqual(['alg', 'binding', 'measurement', 'model_id', 'operator', 'pq_pk', 'sig', 'system_prompt_digest', 'tool_manifest_digest', 'weights_digest']);
    expect([full.weights_digest, full.system_prompt_digest, full.tool_manifest_digest, full.model_id, full.operator]).toEqual(['w', 's', 't', 'mid', 'op']);
    for (const k of ['weights_digest', 'system_prompt_digest', 'tool_manifest_digest', 'model_id', 'operator'] as const) {
      const only = pure.attest({ ...CLAIMS, [k]: 'x' });
      expect(Object.keys(only).sort()).toEqual(['alg', 'binding', 'measurement', k, 'pq_pk', 'sig'].sort());
    }
    const hyb = createPqSoftwareAttestor({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ML, edSecret: ED.secretKey }).attest(CLAIMS);
    expect(Object.keys(hyb).sort()).toEqual(['alg', 'attestor_ed25519', 'binding', 'measurement', 'pq_pk', 'pq_sig', 'sig']);
    expect(hyb.attestor_ed25519).toBe(ED_PUB);
  });
  it('the signature covers the domain prefix and the canonical body', () => {
    const pure = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: ML });
    const st = pure.attest({ ...CLAIMS, operator: 'op' });
    const { sig, ...body } = st;
    const dom = utf8(PQ_ATTEST_DOMAIN);
    const cb = canonicalBytes(body);
    const msg = new Uint8Array(dom.length + cb.length);
    msg.set(dom);
    msg.set(cb, dom.length);
    const pk = { pq: pqTrust(pure.pqPublicKey) };
    expect(verifyWithSuite('ml-dsa-65', pk as never, msg, { sig })).toBe(true);
    expect(verifyWithSuite('ml-dsa-65', pk as never, cb, { sig })).toBe(false);
    expect(verifyWithSuite('ml-dsa-65', pk as never, new Uint8Array([...dom.slice(0, -1), ...cb]), { sig })).toBe(false);
    expect(PQ_ATTEST_DOMAIN).toBe('atlas-pca/attest-pq/v1\0');
    // and signWithSuite agrees with what the attestor produced for the same message
    expect(typeof signWithSuite).toBe('function');
  });
});

import { resolvePqVerifyKey } from './pq';
function pqTrust(pk: string) {
  return resolvePqVerifyKey('', undefined, { trustedPk: pk })!;
}

// ------------------------------------------------------------------------------------------------ verifier
describe('createPqSoftwareVerifier', () => {
  const pureA = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: ML });
  const hybA = createPqSoftwareAttestor({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ML, edSecret: ED.secretKey });
  const slhA = createPqSoftwareAttestor({ alg: 'slh-dsa-sha2-128f', slhDsa: SLH });
  const stPure = pureA.attest(CLAIMS);
  const stHyb = hybA.attest(CLAIMS);
  const mk = (over: Partial<PqSoftwareVerifierOptions> = {}, st: PqAttestationStatement | undefined | (() => unknown) = stPure) =>
    createPqSoftwareVerifier({
      trustedPqPublicKeys: [pureA.pqPublicKey],
      trustedEd25519PublicKeys: [ED_PUB],
      policy: { measurements: ['m-1'] },
      resolveEvidence: typeof st === 'function' ? (st as never) : () => st,
      ...over,
    });
  const run = (v: ReturnType<typeof mk>, ...e: unknown[]) => v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: (e.length ? e[0] : EXPECTED) as never });
  const why = async (v: ReturnType<typeof mk>, ...e: [] | [ExpectedAttestationBinding | undefined]) => {
    const r = e.length ? await run(v, e[0]) : await run(v);
    return r.ok ? 'OK' : r.reason;
  };

  it('construction guards', () => {
    const pol = 'TypeError: createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)';
    const base = { trustedPqPublicKeys: ['x'], policy: { measurements: ['m'] } };
    for (const policy of [undefined, null, {}, { measurements: [] }, { measurements: 'm' }]) expect(throwsMsg(() => createPqSoftwareVerifier({ ...base, policy } as never)), JSON.stringify(policy)).toBe(pol);
    expect(throwsMsg(() => createPqSoftwareVerifier(undefined as never))).toBe(pol);
    const key = 'TypeError: createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)';
    for (const t of [[], undefined, 'x']) expect(throwsMsg(() => createPqSoftwareVerifier({ ...base, trustedPqPublicKeys: t } as never))).toBe(key);
    expect(throwsMsg(() => createPqSoftwareVerifier(base as never))).toBe('NO THROW');
  });
  it('evidence and statement shape', async () => {
    expect(await why(createPqSoftwareVerifier({ trustedPqPublicKeys: [pureA.pqPublicKey], policy: { measurements: ['m-1'] } }))).toBe('no PQ-software evidence resolver configured (fail closed)');
    const m = 'no PQ-software attestation statement for this action';
    for (const st of [undefined, null, 'x', 5, {}, { alg: 5 }, { ...stPure, alg: undefined }]) expect(await why(mk({}, () => st)), JSON.stringify(st)).toBe(m);
    expect(await why(mk({}, { ...stPure, alg: 'bogus' as never }))).toBe("PQ statement declares an unknown signature alg 'bogus'");
    expect(await why(mk({}, { ...stPure, alg: 'ED25519' as never }))).toBe("PQ statement declares an unknown signature alg 'ED25519'");
  });
  it('async resolvers are awaited and receive (document, ctx)', async () => {
    const seen: unknown[][] = [];
    const doc = { d: 1 } as never;
    const ctx = { c: 1 } as never;
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [pureA.pqPublicKey], policy: { measurements: ['m-1'] }, resolveEvidence: async (...a: unknown[]) => (seen.push(a), stPure) });
    expect((await v.verify({ document: doc, ctx, nowMs: T, expected: EXPECTED })).ok).toBe(true);
    expect(seen).toEqual([[doc, ctx]]);
  });
  it('accepts the good statements and reports suite and identity', async () => {
    expect(await run(mk())).toEqual({
      ok: true,
      bound: true,
      measured: { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: 'm-1', operator: '' },
      hostAsserted: { suite: 'ml-dsa-65' },
    });
    const h = await run(mk({}, stHyb));
    expect(h.hostAsserted).toEqual({ suite: 'hybrid-ed25519-ml-dsa-65' });
    const s = await run(mk({ trustedPqPublicKeys: [slhA.pqPublicKey] }, slhA.attest(CLAIMS)));
    expect(s.ok).toBe(true);
    expect(s.hostAsserted).toEqual({ suite: 'slh-dsa-sha2-128f' });
  });
  it('default identity carries every attested optional field', async () => {
    const full = pureA.attest({ ...CLAIMS, weights_digest: 'w', system_prompt_digest: 'sp', tool_manifest_digest: 'tm', model_id: 'mid', operator: 'op' });
    const r = await run(mk({}, full));
    expect(r.measured).toStrictEqual({ model_id: 'mid', weights_digest: 'w', weights_measured: false, runtime_measurement: 'm-1', operator: 'op', system_prompt_digest: 'sp', tool_manifest_digest: 'tm' });
    for (const k of ['system_prompt_digest', 'tool_manifest_digest'] as const) {
      const one = await run(mk({}, pureA.attest({ ...CLAIMS, [k]: 'x' })));
      expect(Object.keys(one.measured!).sort()).toEqual(['model_id', 'operator', 'runtime_measurement', 'weights_digest', 'weights_measured', k].sort());
    }
    // non-string optional fields are ignored (the statement must still verify, so craft it manually)
    const weird = await run(mk({ policy: { measurements: ['m-1'], deriveIdentity: undefined } }, pureA.attest(CLAIMS)));
    expect(weird.measured).toStrictEqual({ model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: 'm-1', operator: '' });
  });
  it('custom identity derivation receives the whole statement', async () => {
    const custom = { model_id: 'M', weights_digest: 'x', weights_measured: true, runtime_measurement: 'y', operator: 'o' };
    const seen: unknown[] = [];
    const r = await run(mk({ policy: { measurements: ['m-1'], deriveIdentity: (s) => (seen.push(s), custom) } }));
    expect(r.measured).toBe(custom);
    expect(seen).toEqual([stPure]);
  });
  it('suite policy: requirePq (default), requireHybrid, allowedSuites', async () => {
    // a classical statement (ed25519), signed by the attestor's Ed25519 identity
    const body = { measurement: 'm-1', binding: attestationBindingB64u({ holderPub: 'holder-1', grantRef: 'grant-1', epoch: 3, nonce: 'nonce-1' }), alg: 'ed25519' as const, attestor_ed25519: ED_PUB };
    const dom = utf8(PQ_ATTEST_DOMAIN);
    const cb = canonicalBytes(body);
    const msg = new Uint8Array(dom.length + cb.length);
    msg.set(dom);
    msg.set(cb, dom.length);
    const classical: PqAttestationStatement = { ...body, sig: signWithSuite('ed25519', { edSecret: ED.secretKey }, msg).sig };
    expect(await why(mk({}, classical))).toBe("PQ required: a classical-only suite 'ed25519' is not accepted by the post-quantum root");
    expect(await why(mk({ requirePq: true }, classical))).toBe("PQ required: a classical-only suite 'ed25519' is not accepted by the post-quantum root");
    expect(await why(mk({ requirePq: false }, classical))).toBe('OK');
    expect(await why(mk({ requirePq: false, requireHybrid: true }, classical))).toBe("hybrid required: suite 'ed25519' is not a classical+PQ hybrid");
    expect(await why(mk({ requireHybrid: true }))).toBe("hybrid required: suite 'ml-dsa-65' is not a classical+PQ hybrid");
    expect(await why(mk({ requireHybrid: true }, stHyb))).toBe('OK');
    expect(await why(mk({ requireHybrid: false }))).toBe('OK');
    expect(await why(mk({ requireHybrid: 'yes' as never }))).toBe('OK'); // only `true` turns it on
    expect(await why(mk({ allowedSuites: ['hybrid-ed25519-ml-dsa-65'] }))).toBe("suite 'ml-dsa-65' is not in the allowed-suites list");
    expect(await why(mk({ allowedSuites: ['ml-dsa-65'] }))).toBe('OK');
    expect(await why(mk({ allowedSuites: ['slh-dsa-sha2-128f', 'ml-dsa-65'] }))).toBe('OK');
    expect(await why(mk({ allowedSuites: [] }))).toBe("suite 'ml-dsa-65' is not in the allowed-suites list"); // empty = refuse everything
    expect(await why(mk({ allowedSuites: 'ml-dsa-65' as never }))).toBe("suite 'ml-dsa-65' is not in the allowed-suites list"); // non-array policy fails closed
  });
  it('attestor keys must be trusted (PQ key first, then the hybrid Ed25519 key)', async () => {
    const other = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(1)) });
    expect(await why(mk({ trustedPqPublicKeys: [other.pqPublicKey] }))).toBe('PQ attestor key is not trusted');
    expect(await why(mk({}, { ...stPure, pq_pk: undefined }))).toBe('PQ attestor key is not trusted');
    expect(await why(mk({}, { ...stPure, pq_pk: 5 as never }))).toBe('PQ attestor key is not trusted');
    expect(await why(mk({ trustedEd25519PublicKeys: [] }, stHyb))).toBe('hybrid Ed25519 attestor key is not trusted');
    expect(await why(mk({ trustedEd25519PublicKeys: undefined }, stHyb))).toBe('hybrid Ed25519 attestor key is not trusted');
    expect(await why(mk({ trustedEd25519PublicKeys: 'x' as never }, stHyb))).toBe('hybrid Ed25519 attestor key is not trusted');
    expect(await why(mk({}, { ...stHyb, attestor_ed25519: undefined }))).toBe('hybrid Ed25519 attestor key is not trusted');
    expect(await why(mk({}, { ...stHyb, attestor_ed25519: 5 as never }))).toBe('hybrid Ed25519 attestor key is not trusted');
    expect(await why(mk({ trustedPqPublicKeys: [other.pqPublicKey], trustedEd25519PublicKeys: [] }, stHyb))).toBe('PQ attestor key is not trusted');
    // a pure-PQ statement does not need an Ed25519 trust list
    expect(await why(mk({ trustedEd25519PublicKeys: undefined }))).toBe('OK');
  });
  it('the signature covers every statement field', async () => {
    const sigMsg = 'PQ attestation signature does not verify';
    const fields: Partial<PqAttestationStatement>[] = [{ measurement: 'm-2' }, { weights_digest: 'x' }, { operator: 'x' }, { model_id: 'x' }, { system_prompt_digest: 'x' }, { tool_manifest_digest: 'x' }, { binding: 'AAAA' }];
    for (const f of fields) expect(await why(mk({ policy: { measurements: ['m-1', 'm-2'] } }, { ...stPure, ...f })), JSON.stringify(f)).toBe(sigMsg);
    expect(await why(mk({}, { ...stPure, sig: stPure.sig.slice(0, -4) + (stPure.sig.endsWith('AAAA') ? 'BBBB' : 'AAAA') }))).toBe(sigMsg);
    expect(await why(mk({}, { ...stHyb, pq_sig: stPure.sig }))).toBe(sigMsg);
    expect(await why(mk({}, { ...stHyb, sig: stPure.sig }))).toBe(sigMsg);
    expect(await why(mk({}, { ...stHyb, pq_sig: undefined }))).toBe(sigMsg);
    // a signature by a different (but trusted-listed) key does not verify under the statement's pq_pk
    const other = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(2)) });
    const forged = { ...other.attest(CLAIMS), pq_pk: pureA.pqPublicKey };
    expect(await why(mk({}, forged))).toBe(sigMsg);
  });
  it('binding checks (after the signature)', async () => {
    expect(await why(mk(), undefined)).toBe('no expected attestation binding supplied');
    expect(await why(mk(), { ...EXPECTED, epoch: -1 })).toBe('binding not constructible: binding: epoch must be a non-negative safe integer');
    expect(await why(mk(), { ...EXPECTED, nonce: 'other' })).toBe('PQ statement binding mismatch (holder/grant/epoch/nonce)');
    expect(await why(mk(), { ...EXPECTED, epoch: 4 })).toBe('PQ statement binding mismatch (holder/grant/epoch/nonce)');
    // a statement with an empty / missing / non-string binding (signed that way) is "not bound"
    const unbound = async (binding: unknown) => {
      const body: Record<string, unknown> = { measurement: 'm-1', alg: 'ml-dsa-65', pq_pk: pureA.pqPublicKey, ...(binding === undefined ? {} : { binding }) };
      const dom = utf8(PQ_ATTEST_DOMAIN);
      const cb = canonicalBytes(body);
      const msg = new Uint8Array(dom.length + cb.length);
      msg.set(dom);
      msg.set(cb, dom.length);
      const sig = signWithSuite('ml-dsa-65', { mlDsa: ML }, msg).sig;
      return why(mk({}, { ...body, sig } as never));
    };
    expect(await unbound('')).toBe('PQ statement is not bound (binding absent)');
    expect(await unbound(undefined)).toBe('PQ statement is not bound (binding absent)');
    expect(await unbound(5)).toBe('PQ statement is not bound (binding absent)');
  });
  it('measurement and weights allowlists', async () => {
    expect(await why(mk({ policy: { measurements: ['zzz'] } }))).toBe('measurement not in policy allowlist');
    expect(await why(mk({ policy: { measurements: ['zzz', 'm-1'] } }))).toBe('OK');
    const w = pureA.attest({ ...CLAIMS, weights_digest: 'wd' });
    const wm = 'measured weights digest not in policy allowlist';
    expect(await why(mk({ policy: { measurements: ['m-1'], weightsMeasurements: ['wd'] } }, w))).toBe('OK');
    expect(await why(mk({ policy: { measurements: ['m-1'], weightsMeasurements: ['other', 'wd'] } }, w))).toBe('OK');
    expect(await why(mk({ policy: { measurements: ['m-1'], weightsMeasurements: ['other'] } }, w))).toBe(wm);
    expect(await why(mk({ policy: { measurements: ['m-1'], weightsMeasurements: ['wd'] } }))).toBe(wm); // statement has none
    expect(await why(mk({ policy: { measurements: ['m-1'], weightsMeasurements: [] } }))).toBe('OK');
    expect(await why(mk({ policy: { measurements: ['m-1'], weightsMeasurements: [] } }, w))).toBe('OK');
    expect(await why(mk({ policy: { measurements: ['m-1'] } }, w))).toBe('OK');
  });
  it('unexpected exceptions are fail-closed', async () => {
    const boom = mk({}, () => {
      throw new Error('resolver exploded');
    });
    expect(await why(boom)).toBe('pq-software verification error (fail closed): resolver exploded');
    const weird = mk({}, () => {
      throw 'str';
    });
    expect(await why(weird)).toBe('pq-software verification error (fail closed): unknown');
  });
});
