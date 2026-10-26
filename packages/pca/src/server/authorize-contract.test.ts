/** Exact-outcome tests for the parts of authorize.ts that are not the passport branch (targeted mutation run over the whole file). */
import { describe, expect, it } from 'vitest';
import { mintRoot } from '../capability';
import { mintGrant } from '../envelope';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn } from '../pcactn';
import type { RiskPolicy } from '../risk';
import { createAuthorizer, isAuthorizedFor, missingAuthorizeComponents, requireAuthorized, type AuthorizeOptions } from './authorize';
import { memoryPcaStore } from './require-pca';

const SP: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const principal = generateKeyPair();
const holder = generateKeyPair();
const pPub = encodeKey(principal.publicKey);
const hPub = encodeKey(holder.publicKey);
const grant = mintGrant({ principalSecret: principal.secretKey, principalPublic: pPub, holder: hPub, goal: 'g', envelope: { predicates: [{ verb: ['do'], resource: '*', where: [] }], caveats: [], agent_binding: {}, risk_policy: SP } }).grant;
let c = 0;
const params = { payee: 'acme', amount: 1 };
const node = (): PlanNode => ({ id: 'n1', verb: 'do', resource: 'r', params_digest: paramsDigest(params), reversibility_class: 'reversible' });
const act = (g = grant, aud = 'rs') => buildPCActn({ grant: g, chain: [g], plan: [node()], nodeId: 'n1', params, counter: ++c, signerSecret: holder.secretKey, aud, now: NOW });
const options = (over: Partial<AuthorizeOptions> = {}, g = grant): AuthorizeOptions => ({
  audience: 'rs', resolveGrant: async (r) => (r === g.id ? g : null), budgetStore: memoryPcaStore(), hooks: { revocation: () => ({ enforced: true, ok: true }) }, plan: 'single-step', now: () => NOW,
  risk: (x) => ({ blastRadius: Math.min(1, Number(x?.params?.amount) / 100), semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }), ...over,
});
const op = { verb: 'do', resource: 'r', params };
const WORST = { t: 3, proof: 'strong', optimisticAllowed: false };

describe('authorize: refusals before verification', () => {
  it('an invalid operation is refused with the exact text, the worst threshold and a failing operation check', async () => {
    const az = createAuthorizer(options());
    const want = { allow: false, status: 403, reason: 'operation: authorize needs the operation to execute (verb, resource, params) (fail closed)', assurance: { operation: { outcome: 'fail' } } };
    const bad = [undefined, null, {}, { ...op, verb: '' }, { ...op, verb: 5 }, { ...op, verb: ['x'] }, { ...op, resource: '' }, { ...op, resource: 5 }, { ...op, resource: ['a'] }, { ...op, params: 'x' }, { ...op, params: null }, { ...op, params: [] }, { ...op, params: undefined }];
    for (const o of bad) {
      const r = await az({ operation: o as never, pcactn: act() });
      expect(r, JSON.stringify(o)).toMatchObject(want);
      if (!r.allow) expect(r.verdict).toEqual({ allow: false, r: 1, requiredThreshold: WORST, checks: { operation: 'fail' }, reasons: [want.reason] });
    }
    expect(await az(undefined as never)).toMatchObject(want);
  });
  it('the two refusal severities never alias: each refusal gets its own threshold object', async () => {
    const az = createAuthorizer(options());
    const a = await az({ operation: undefined as never });
    const b = await az({ operation: undefined as never });
    if (a.allow || b.allow) throw new Error('x');
    (a.verdict.requiredThreshold as { t: number }).t = 0;
    expect(b.verdict.requiredThreshold).toEqual(WORST);
  });
  it('missing components are listed in order, joined by ", ", and each part of the checks counts', async () => {
    expect(missingAuthorizeComponents({} as never)).toEqual(['audience', 'resolveGrant', 'budgetStore', 'hooks.revocation']);
    expect(missingAuthorizeComponents({ audience: '' } as never)).toContain('audience');
    expect(missingAuthorizeComponents({ audience: 5 } as never)).toContain('audience');
    const ok = options();
    expect(missingAuthorizeComponents(ok)).toEqual([]);
    expect(missingAuthorizeComponents({ ...ok, budgetStore: { get: () => undefined } as never })).toEqual(['budgetStore']);
    expect(missingAuthorizeComponents({ ...ok, budgetStore: { put: () => undefined } as never })).toEqual(['budgetStore']);
    expect(missingAuthorizeComponents({ ...ok, hooks: {} })).toEqual(['hooks.revocation']);
    expect(missingAuthorizeComponents({ ...ok, hooks: undefined })).toEqual(['hooks.revocation']);
    expect(missingAuthorizeComponents({ ...ok, insecureAllowUnenforced: true })).toEqual(['insecureAllowUnenforced is not accepted by authorize']);
    const r = await createAuthorizer({ audience: 'rs' } as never)({ operation: op });
    expect(r).toMatchObject({ allow: false, status: 403, reason: 'authorize: missing required component(s): resolveGrant, budgetStore, hooks.revocation (fail closed)', missing: ['resolveGrant', 'budgetStore', 'hooks.revocation'], assurance: { authorize_config: { outcome: 'fail' } } });
  });
});

describe('authorize: the decision and its report', () => {
  it('an allowed result carries the bound operation and the full assurance report (not the per-check fallback)', async () => {
    const r = await createAuthorizer(options())({ operation: op, pcactn: act() });
    expect(r.allow).toBe(true);
    if (!r.allow) return;
    expect(r.status).toBe(200);
    expect(r.verdict).not.toHaveProperty('assurance');
    expect(r.assurance.leaf_signature).toEqual({ outcome: 'pass', suites: ['ed25519'], level: 'ed25519' });
    expect(r.assurance.counter).toEqual({ outcome: 'pass' });
    expect(r.assurance.taint_gate).toEqual({ outcome: 'not-enforced' });
    expect(r.operation).toMatchObject({ verb: 'do', resource: 'r' });
  });
  it('assurance: true keeps the report on the verdict too', async () => {
    const r = await createAuthorizer(options({ assurance: true }))({ operation: op, pcactn: act() });
    expect(r.allow && r.verdict.assurance).toBeTruthy();
    const r2 = await createAuthorizer(options({ assurance: false }))({ operation: op, pcactn: act() });
    expect(r2.allow && r2.verdict.assurance).toBeUndefined();
  });
  it('a refusal before verification reports each failing check as {outcome}', async () => {
    const az = createAuthorizer(options());
    const g = await az({ operation: op, pcactn: 'garbage' });
    expect(g).toMatchObject({ allow: false, status: 401, reason: 'undecodable PCActn: strict JSON: unexpected token (at offset 0)', assurance: { pcactn: { outcome: 'fail' } }, wwwAuthenticate: 'PCA realm="pca", error="invalid_pcactn", hint="send PCA-Action: <base64url PCActn> or JSON body {pcactn}"' });
    if (!g.allow) expect(g.assurance).toEqual({ pcactn: { outcome: 'fail' } });
    const e = await az({ operation: op });
    expect(e).toMatchObject({ allow: false, status: 401, reason: 'no PCActn presented', wwwAuthenticate: 'PCA realm="pca", error="missing_pcactn", hint="send PCA-Action: <base64url PCActn> or JSON body {pcactn}"' });
    const ok = await az({ operation: op, pcactn: act() });
    expect(ok).not.toHaveProperty('wwwAuthenticate');
  });
  it('the decisive reason is the operation binding first, then the first failing check, then the first reason', async () => {
    const az = createAuthorizer(options());
    const wrongAud = await az({ operation: op, pcactn: act(grant, 'other') });
    expect(wrongAud).toMatchObject({ allow: false, status: 401, reason: 'audience: aud does not match this resource server / instance' });
    const both = await az({ operation: { ...op, params: { payee: 'acme', amount: 2 } }, pcactn: act(grant, 'other') });
    expect(both).toMatchObject({ allow: false, reason: "operation: the proof's params_digest does not match the params of this do operation" });
    const opOnly = await az({ operation: { ...op, params: { payee: 'acme', amount: 2 } }, pcactn: act() });
    if (opOnly.allow) throw new Error('x');
    expect(opOnly.verdict.checks).toMatchObject({ operation: 'fail', params_digest: 'fail', plan_root_authorized: 'fail', audience: 'pass' });
    expect(opOnly.reason).toBe("operation: the proof's params_digest does not match the params of this do operation");
  });
  it('a request object reused without a PCActn does not remember the previous one', async () => {
    const az = createAuthorizer(options());
    const req = { headers: {} };
    expect(await az({ operation: op, request: req, pcactn: act() })).toMatchObject({ allow: true });
    expect(await az({ operation: op, request: req })).toMatchObject({ allow: false, status: 401, reason: 'no PCActn presented' });
  });
  it('without a request the default one has headers (the extractor never throws)', async () => {
    const r = await createAuthorizer(options())({ operation: op });
    expect(r).toMatchObject({ allow: false, status: 401, reason: 'no PCActn presented' });
  });
});

describe('authorize: configured checks are required, plans and budgets', () => {
  it('a configured revocation epoch or beacon that yields nothing denies (the check is required, not skipped)', async () => {
    const fresh = await createAuthorizer(options({ revocationEpoch: async () => undefined }))({ operation: op, pcactn: act() });
    expect(fresh).toMatchObject({ allow: false, reason: 'freshness: required check is not-enforced (default-deny: not enforced by this resource server)' });
    const beacon = await createAuthorizer(options({ beacon: async () => undefined }))({ operation: op, pcactn: act() });
    expect(beacon).toMatchObject({ allow: false, reason: 'beacon: required check is not-enforced (default-deny: not enforced by this resource server)' });
  });
  it('options.require can only add checks', async () => {
    const r = await createAuthorizer(options({ require: ['attestation'] }))({ operation: op, pcactn: act() });
    expect(r.allow).toBe(false);
    if (!r.allow) expect(r.verdict.checks.attestation).toBe('fail');
  });
  it("a plan the caller's context supplies is not replaced by the single-step plan", async () => {
    const r = await createAuthorizer(options({ context: async () => ({ plan: [{ ...node(), id: 'other' }], planAuthorized: true }) }))({ operation: op, pcactn: act() });
    expect(r.allow).toBe(false);
    if (!r.allow) expect(r.verdict.checks.plan_root_authorized).toBe('fail');
  });
  it('a PCActn whose committed plan has more nodes than the single operation is not plan-authorized', async () => {
    const two: PlanNode[] = [node(), { ...node(), id: 'n2' }];
    const a = buildPCActn({ grant, chain: [grant], plan: two, nodeId: 'n1', params, counter: ++c, signerSecret: holder.secretKey, aud: 'rs', now: NOW });
    const r = await createAuthorizer(options())({ operation: op, pcactn: a });
    expect(r.allow).toBe(false);
    if (!r.allow) expect(r.verdict.checks.plan_root_authorized).toBe('fail');
  });
  it('a PCActn without a plan is left to the verifier (never an internal error)', async () => {
    const { plan: _p, ...noPlan } = act();
    const r = await createAuthorizer(options())({ operation: op, pcactn: noPlan as never });
    expect(r.allow).toBe(false);
    expect(r.allow ? '' : r.reason).not.toMatch(/^authorize error/);
  });
  it('the default budget seed needs an envelope with a finite numeric bMax', async () => {
    const plain = mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: hPub, caveats: [] });
    const r = await createAuthorizer(options({}, plain))({ operation: op, pcactn: act(plain) });
    expect(r).toMatchObject({ allow: false, reason: 'policy: grant carries no valid envelope' });
    if (!r.allow) expect(r.verdict.checks.budget).toBe('not-enforced');
    const env = grant.caveats[0] as unknown as { risk_policy: Record<string, unknown> };
    const bad = mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: hPub, caveats: [{ ...env, risk_policy: { ...env.risk_policy, bMax: 'lots' } } as never] });
    const r2 = await createAuthorizer(options({}, bad))({ operation: op, pcactn: act(bad) });
    const ref = await createAuthorizer(options({}, plain))({ operation: op, pcactn: act(plain) });
    expect(r2.allow).toBe(ref.allow);
    expect(r2.allow ? '' : r2.reason).toBe(ref.allow ? '' : ref.reason);
  });
});

describe('isAuthorizedFor and requireAuthorized', () => {
  it('true only for exactly the authorized operation', async () => {
    const r = await createAuthorizer(options())({ operation: op, pcactn: act() });
    expect(isAuthorizedFor(r, op)).toBe(true);
    expect(isAuthorizedFor(r, { ...op, verb: 'undo' })).toBe(false);
    expect(isAuthorizedFor(r, { ...op, resource: 'q' })).toBe(false);
    expect(isAuthorizedFor(r, { ...op, params: { payee: 'acme', amount: 2 } })).toBe(false);
    expect(isAuthorizedFor(r, { ...op, verb: '' })).toBe(false);
    expect(isAuthorizedFor(r, undefined as never)).toBe(false);
    const cyc: Record<string, unknown> = {};
    cyc.self = cyc;
    expect(isAuthorizedFor(r, { ...op, params: cyc })).toBe(false);
    expect(isAuthorizedFor(r, { ...op, params: { n: 10n } as never })).toBe(false);
  });
  it('never for a denial or a result without a bound operation, in either result shape', async () => {
    const r = await createAuthorizer(options())({ operation: op, pcactn: act() });
    if (!r.allow) throw new Error('x');
    expect(isAuthorizedFor({ ...r, allow: false } as never, op)).toBe(false);
    const { operation: _o, ...unbound } = r;
    expect(isAuthorizedFor(unbound as never, op)).toBe(false);
    expect(isAuthorizedFor({ ok: true, verdict: r.verdict, pcactn: r.pcactn, operation: r.operation }, op)).toBe(true);
    expect(isAuthorizedFor({ ok: false, status: 403, verdict: r.verdict }, op)).toBe(false);
    expect(isAuthorizedFor({ ok: true, verdict: r.verdict, pcactn: r.pcactn } as never, op)).toBe(false);
  });
  it('requireAuthorized maps the request to the operation, returns the guard shape and surfaces the challenge', async () => {
    const g = requireAuthorized({ ...options(), operation: () => op });
    const ok = await g({ headers: {}, body: { pcactn: act() } });
    expect(ok).toMatchObject({ ok: true, operation: { verb: 'do', resource: 'r' } });
    const missing = await g({ headers: {} });
    expect(missing).toMatchObject({ ok: false, status: 401, wwwAuthenticate: 'PCA realm="pca", error="missing_pcactn", hint="send PCA-Action: <base64url PCActn> or JSON body {pcactn}"' });
    expect(await requireAuthorized({ ...options(), operation: () => { throw new Error('route'); } })({ headers: {}, body: { pcactn: act() } })).toMatchObject({ ok: false, status: 403 });
    expect(await requireAuthorized({ ...options(), operation: async () => null })({ headers: {}, body: { pcactn: act() } })).toMatchObject({ ok: false, status: 403 });
    const ok2 = await g({ headers: {}, body: { pcactn: act() } });
    expect(ok2).not.toHaveProperty('wwwAuthenticate');
  });
});
