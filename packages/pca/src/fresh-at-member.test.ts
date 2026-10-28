import { describe, expect, it } from 'vitest';
import { mintRoot } from './capability';
import { encodeKey, generateKeyPair, publicKeyOf } from './keys';
import { buildPCActn, signPCActn, type PCActn } from './pcactn';
import { validateWireV2, verifyPCActnCore } from './pcactn-full';
import { validateWireV2 as coreWire } from './wire';
import { signFreshAt, validateFreshAtWire, type FreshAtPolicy, type FreshAtState } from './fresh-at';
import { verifyPCActn } from './server/verify';
import { decisionOf } from './decision';
import { b64u } from './hash';

const NOW = 1_800_000_000_000;
const AUD = 'inst_A';
const S: FreshAtState = { revocation_epoch: 5, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest: 'pd3' };

function fx() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const T = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
  const plan = [{ id: 'n1', verb: 'read', resource: 'acct', reversibility_class: 'R0' }];
  const token = signFreshAt(T.secretKey, 'inst_A', S, NOW - 1000);
  const act = (freshAt?: unknown): PCActn =>
    buildPCActn({ aud: AUD, grant, chain: [grant], plan, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, iat: NOW, exp: NOW + 60_000, ...(freshAt !== undefined ? { freshAt: freshAt as never } : {}) });
  const policy = (local: FreshAtState = S, extra: Partial<FreshAtPolicy> = {}): FreshAtPolicy => ({ signer: b64u(publicKeyOf(T.secretKey)), scope: 'inst_A', local, ...extra });
  const core = (p: PCActn, freshAt?: FreshAtPolicy) => verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: AUD, ...(freshAt ? { freshAt } : {}) });
  return { A, T, grant, token, act, policy, core };
}

describe('fresh_at as a PCActn member', () => {
  it('is signed by the leaf signature: swapping the token breaks leaf_signature', async () => {
    const f = fx();
    const p = f.act(f.token);
    const other = signFreshAt(f.T.secretKey, 'inst_A', { ...S, revocation_epoch: 0 }, NOW - 1000);
    const r = await f.core({ ...p, fresh_at: other }, f.policy());
    expect(r.allow).toBe(false);
    expect(r.checks.leaf_signature).toBe('fail');
  });
  it('passes when the verifier is at or past the token; the check is reported', async () => {
    const f = fx();
    const r = await f.core(f.act(f.token), f.policy({ ...S, ledger_tree_size: 120 }));
    expect(r.allow).toBe(true);
    expect(r.checks.fresh_at).toBe('pass');
  });
  it('a lagging verifier fails fresh_at with an ESCALATE-class reason (decision escalate, never allow)', async () => {
    const f = fx();
    const r = await f.core(f.act(f.token), f.policy({ ...S, revocation_epoch: 4 }));
    expect(r.allow).toBe(false);
    expect(r.checks.fresh_at).toBe('fail');
    expect(r.reason).toBe('fresh_at: escalate: stale_state (verifier state is behind the token on revocation_epoch)');
    expect(decisionOf({ allow: r.allow, checks: r.checks, reasons: [r.reason!] })).toBe('escalate');
  });
  it('wrong scope, wrong signer and an over-age token are hard denials', async () => {
    const f = fx();
    expect((await f.core(f.act(f.token), f.policy(S, { scope: 'inst_B' }))).reason).toBe('fresh_at: wrong_scope');
    expect((await f.core(f.act(f.token), f.policy(S, { signer: b64u(publicKeyOf(generateKeyPair().secretKey)) }))).reason).toBe('fresh_at: bad_token');
    expect((await f.core(f.act(f.token), f.policy(S, { maxTokenAgeMs: 10 }))).reason).toBe('fresh_at: token_too_old');
  });
  it('a PCActn that carries the member with no policy is refused; no member and no policy is byte-identical (check absent)', async () => {
    const f = fx();
    const r = await f.core(f.act(f.token));
    expect(r.allow).toBe(false);
    expect(r.reason).toBe('fresh_at: the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)');
    const plain = await f.core(f.act());
    expect(plain.allow).toBe(true);
    expect('fresh_at' in plain.checks).toBe(false);
  });
  it('require: no token escalates; the side-carried form is still read for one release, but the member wins', async () => {
    const f = fx();
    const need = await f.core(f.act(), f.policy(S, { require: true }));
    expect(need.reason).toBe('fresh_at: escalate: a consistency token is required (refresh and retry with the token of your latest write)');
    const side = await f.core(f.act(), f.policy(S, { sideCarried: f.token }));
    expect(side.allow).toBe(true);
    expect(side.checks.fresh_at).toBe('pass');
    const stale = signFreshAt(f.T.secretKey, 'inst_A', { ...S, revocation_epoch: 99 }, NOW - 1000);
    expect((await f.core(f.act(f.token), f.policy(S, { sideCarried: stale }))).allow).toBe(true); // the signed member counts, not the header beside it
  });
  it('wire: shape is validated, unknown keys rejected, and the core entry without the extension refuses the member', () => {
    const f = fx();
    const p = f.act(f.token);
    expect(validateWireV2(p)).toBeNull();
    expect(coreWire(p)).toBe("'fresh_at' is a consistency-token extension field and this verifier does not load it (use the root @atlasauth/pca entry)");
    const { sig: _sig, ...body } = p;
    void _sig;
    const bad = (m: unknown) => validateWireV2(signPCActn({ ...body, fresh_at: m } as never, f.A.secretKey));
    expect(bad({ ...f.token, extra: 1 })).toBe("'fresh_at' has an unknown field 'extra'");
    expect(bad({ ...f.token, revocation_epoch: -1 })).toBe("'fresh_at.revocation_epoch' must be a non-negative safe integer");
    expect(bad({ ...f.token, sig: 'AAAA' })).toBe("'fresh_at.sig' is not canonical base64url (64 bytes)");
    expect(validateFreshAtWire('x')).toBe("'fresh_at' must be an object");
  });
  it('the server verifier forwards the policy; the failure carries the escalate-class reason (other checks of this bare fixture deny on their own)', async () => {
    const f = fx();
    const v = await verifyPCActn(f.act(f.token), { insecureSkipPlanRootCheck: true, grant: f.grant, audience: AUD, now: NOW, require: [], freshAt: f.policy({ ...S, budget_version: 1 }) });
    expect(v.allow).toBe(false);
    expect(v.checks.fresh_at).toBe('fail');
    expect(v.reasons[0]).toBe('fresh_at: escalate: stale_state (verifier state is behind the token on budget_version)');
  });
});
