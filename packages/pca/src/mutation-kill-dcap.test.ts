/** Mutation-kill tests for attest-intel-dcap.ts: the quote and collateral verifiers are mocked so every branch/argument is observable. */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const tdx = vi.hoisted(() => ({ q: vi.fn() }));
const coll = vi.hoisted(() => ({ c: vi.fn() }));
vi.mock('./attest-intel-tdx', async (orig) => ({ ...(await orig<typeof import('./attest-intel-tdx')>()), verifyGenuineTdxQuote: tdx.q }));
vi.mock('./attest-intel-collateral', async (orig) => ({ ...(await orig<typeof import('./attest-intel-collateral')>()), verifyIntelTdxCollateral: coll.c }));

import { createHash } from 'node:crypto';
import { checkAzureRuntimeDataBinding, createIntelDcapVerifier } from './attest-intel-dcap';
import { attestationBinding } from './attestation';
import type { ExpectedAttestationBinding } from './attestation';

const EXP: ExpectedAttestationBinding = { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' };
const WANT = attestationBinding(EXP);
const M = 'ab'.repeat(48);
const ok = (over: Record<string, unknown> = {}) => ({ ok: true, report: { reportData: WANT }, measured: { runtime_measurement: M }, fmspc: '00806f050000', ...over });
const base = (policy: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) =>
  createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [M], ...policy } as never, resolveEvidence: () => ({ quote: new Uint8Array(4), collateral: {} as never }), ...extra } as never);
const run = (v: ReturnType<typeof base>) => v.verify({ document: {} as never, ctx: {} as never, nowMs: 1234, expected: EXP });

beforeEach(() => {
  tdx.q.mockReset();
  coll.c.mockReset();
  tdx.q.mockResolvedValue(ok());
  coll.c.mockResolvedValue({ ok: true });
});

describe('createIntelDcapVerifier constructor validation (exact messages)', () => {
  const mk = (o: unknown) => () => createIntelDcapVerifier(o as never);
  it('rejects a missing/odd binding with its own message, even for undefined options', () => {
    expect(mk(undefined)).toThrow("binding must be 'report-data' or 'azure-runtime-data'");
    expect(mk({ binding: 'report-data' })).not.toThrow(/binding must be/);
    expect(mk({ binding: 'x', policy: { mrtds: [M] } })).toThrow("binding must be 'report-data' or 'azure-runtime-data'");
    expect(mk({ binding: 'azure-runtime-data', policy: { mrtds: [M] } })).not.toThrow();
  });
  it('requires a non-empty mrtds allowlist, even when policy is absent', () => {
    expect(mk({ binding: 'report-data' })).toThrow('policy.mrtds must be a NON-EMPTY allowlist');
    expect(mk({ binding: 'report-data', policy: { mrtds: [] } })).toThrow('NON-EMPTY allowlist');
    expect(mk({ binding: 'report-data', policy: { mrtds: 'x' } })).toThrow('NON-EMPTY allowlist');
  });
  it('rejects a bad MRTD anywhere in the list (some, not every) for each defect separately', () => {
    for (const bad of ['zz'.repeat(48), 'ab'.repeat(47), 'ab'.repeat(49)]) {
      expect(mk({ binding: 'report-data', policy: { mrtds: [M, bad] } })).toThrow('every MRTD must be 96 hex chars');
      expect(mk({ binding: 'report-data', policy: { mrtds: [bad, M] } })).toThrow('every MRTD must be 96 hex chars');
    }
  });
  it('lower-cases the MRTD allowlist before handing it to the quote verifier; upper-case input is accepted', async () => {
    await run(base({ mrtds: [M.toUpperCase()] }));
    expect(tdx.q.mock.calls[0]![0].policy.mrtds).toEqual([M]);
  });
  for (const name of ['mrSeams', 'mrSignerSeams']) {
    it(`${name}: empty / non-array / per-entry defects each rejected, anywhere in the list`, () => {
      const o = (list: unknown) => ({ binding: 'report-data', policy: { mrtds: [M], [name]: list } });
      expect(mk(o([]))).toThrow(`policy.${name}, if given, must be a NON-EMPTY list`);
      expect(mk(o('x'))).toThrow(`policy.${name}, if given, must be a NON-EMPTY list`);
      for (const bad of [5, 'zz'.repeat(48), 'ab'.repeat(47), 'ab'.repeat(49)]) {
        expect(mk(o([M, bad]))).toThrow(`every ${name} entry must be 96 hex chars`);
        expect(mk(o([bad, M]))).toThrow(`every ${name} entry must be 96 hex chars`);
      }
      // a String OBJECT passes the regex and has length 96: only the typeof test refuses it
      expect(mk(o([new String(M)]))).toThrow(`every ${name} entry must be 96 hex chars`);
      expect(mk(o([M, M.toUpperCase()]))).not.toThrow();
      expect(mk(o(undefined))).not.toThrow();
    });
  }
});

describe('createIntelDcapVerifier.verify: quote verifier arguments', () => {
  it('forwards time, pin (lower-cased), and every policy field; omits absent/false ones', async () => {
    await run(base({ mrSeams: [M], mrSignerSeams: [M], fmspcs: ['aa'], rtmrs: { 0: 'x' }, allowDebug: true }, { trustAnchorRootCaSpkiSha256: 'ABCDEF' }));
    const a = tdx.q.mock.calls[0]![0];
    expect(a.nowMs).toBe(1234);
    expect(a.trustAnchorRootCaSpkiSha256).toBe('abcdef');
    expect(a.policy).toEqual({ mrtds: [M], mrSeams: [M], mrSignerSeams: [M], fmspcs: ['aa'], rtmrs: { 0: 'x' }, allowDebug: true });
    await run(base({ allowDebug: false }));
    expect(tdx.q.mock.calls[1]![0].policy).toEqual({ mrtds: [M] });
    await run(base({ mrSignerSeams: [M] }));
    expect(tdx.q.mock.calls[2]![0].policy).toEqual({ mrtds: [M], mrSignerSeams: [M] });
  });
  it('each of ok/report/measured/fmspc missing is a quote failure carrying the reason (or "unknown")', async () => {
    for (const drop of ['report', 'measured', 'fmspc'] as const) {
      tdx.q.mockResolvedValueOnce(ok({ [drop]: undefined, reason: 'because' }));
      expect(await run(base())).toEqual({ ok: false, reason: 'DCAP quote invalid: because' });
    }
    tdx.q.mockResolvedValueOnce(ok({ ok: false, reason: 'bad sig' }));
    expect(await run(base())).toEqual({ ok: false, reason: 'DCAP quote invalid: bad sig' });
    tdx.q.mockResolvedValueOnce({ ok: false });
    expect(await run(base())).toEqual({ ok: false, reason: 'DCAP quote invalid: unknown' });
    tdx.q.mockResolvedValueOnce(ok({ fmspc: '' }));
    expect((await run(base())).ok).toBe(false);
  });
  it('report-data binding mismatch and unconstructible binding fail', async () => {
    tdx.q.mockResolvedValueOnce(ok({ report: { reportData: new Uint8Array(64) } }));
    expect(await run(base())).toEqual({ ok: false, reason: 'report_data does not bind holder/grant/epoch/nonce' });
    const r = await createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [M] }, resolveEvidence: () => ({ quote: new Uint8Array(4) }) }).verify({ document: {} as never, ctx: {} as never, nowMs: 1, expected: { ...EXP, nonce: '' } });
    expect(r).toEqual({ ok: false, reason: 'binding not constructible: binding: nonce required' });
  });
  it('a longer report_data whose prefix equals the binding does not bind', async () => {
    tdx.q.mockResolvedValueOnce(ok({ report: { reportData: new Uint8Array([...WANT, 0]) } }));
    expect((await run(base())).ok).toBe(false);
  });
});

describe('createIntelDcapVerifier.verify: collateral and result', () => {
  it('passes the collateral policy/allowDebug/pin/time through and records tcb status + advisory ids', async () => {
    coll.c.mockResolvedValueOnce({ ok: true, status: 'UpToDate', advisoryIds: ['A-1', 'A-2'] });
    const r = await run(base({ allowDebug: true, collateral: { x: 1 } }, { trustAnchorRootCaSpkiSha256: 'AB' }));
    const a = coll.c.mock.calls[0]![0];
    expect(a.now).toEqual(new Date(1234));
    expect(a.trustAnchorRootCaSpkiSha256).toBe('ab');
    expect(a.allowDebug).toBe(true);
    expect(a.policy).toEqual({ x: 1 });
    expect(r).toEqual({ ok: true, bound: true, measured: { runtime_measurement: M }, hostAsserted: { attestation_type: 'tdx-dcap', fmspc: '00806f050000', tcb_status: 'UpToDate', advisory_ids: 'A-1,A-2' } });
  });
  it('omits allowDebug / policy when unset, status when absent and advisory ids when empty or absent', async () => {
    coll.c.mockResolvedValueOnce({ ok: true, advisoryIds: [] });
    const r = await run(base());
    const a = coll.c.mock.calls[0]![0];
    expect('allowDebug' in a).toBe(false);
    expect('policy' in a).toBe(false);
    expect(r).toMatchObject({ ok: true, hostAsserted: { attestation_type: 'tdx-dcap', fmspc: '00806f050000' } });
    expect(Object.keys((r as { hostAsserted: object }).hostAsserted).sort()).toEqual(['attestation_type', 'fmspc']);
    coll.c.mockResolvedValueOnce({ ok: true });
    expect(Object.keys(((await run(base())) as { hostAsserted: object }).hostAsserted).sort()).toEqual(['attestation_type', 'fmspc']);
    coll.c.mockResolvedValueOnce({ ok: true, advisoryIds: ['only'] });
    expect(((await run(base())) as { hostAsserted: Record<string, string> }).hostAsserted.advisory_ids).toBe('only');
  });
  it('a rejected collateral fails with its reason (or "rejected")', async () => {
    coll.c.mockResolvedValueOnce({ ok: false, reason: 'revoked', status: 'Revoked' });
    expect(await run(base())).toEqual({ ok: false, reason: 'Intel collateral: revoked' });
    coll.c.mockResolvedValueOnce({ ok: false });
    expect(await run(base())).toEqual({ ok: false, reason: 'Intel collateral: rejected' });
  });
  it('missing collateral: refused by default, "unevaluated" only with the explicit opt-out', async () => {
    const mk = (extra: Record<string, unknown>) => createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [M] }, resolveEvidence: () => ({ quote: new Uint8Array(4) }), ...extra } as never);
    expect((await run(mk({} as never))).reason).toMatch(/collateral required but not supplied/);
    expect((await run(mk({ allowMissingCollateral: false }))).ok).toBe(false);
    const r = await run(mk({ allowMissingCollateral: true }));
    expect(r).toMatchObject({ ok: true, hostAsserted: { tcb_status: 'unevaluated' } });
    expect(coll.c).not.toHaveBeenCalled();
  });
  it('resolver failures: absent, throwing (Error or non-Error), no quote, no expected binding', async () => {
    const v = (resolveEvidence?: unknown) => createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [M] }, ...(resolveEvidence ? { resolveEvidence } : {}) } as never);
    expect((await run(v())).reason).toBe('no Intel DCAP evidence resolver configured (fail closed)');
    expect((await run(v(() => { throw new Error('boom'); }))).reason).toBe('intel-dcap verification error (fail closed): boom');
    expect((await run(v(() => { throw 'str'; }))).reason).toBe('intel-dcap verification error (fail closed): unknown');
    expect((await run(v(() => undefined))).reason).toBe('no Intel DCAP quote for this action');
    expect((await run(v(() => ({ quote: [1, 2] })))).reason).toBe('no Intel DCAP quote for this action');
    const r = await createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [M] }, resolveEvidence: () => ({ quote: new Uint8Array(4) }) }).verify({ document: {} as never, ctx: {} as never, nowMs: 1 } as never);
    expect(r.reason).toBe('no expected attestation binding supplied');
  });
  it('azure-runtime-data binding needs runtime bytes', async () => {
    const v = createIntelDcapVerifier({ binding: 'azure-runtime-data', policy: { mrtds: [M] }, resolveEvidence: () => ({ quote: new Uint8Array(4) }) });
    expect((await run(v as never)).reason).toBe('azure-runtime-data binding needs the runtime-data JSON bytes');
  });
});

describe('checkAzureRuntimeDataBinding', () => {
  const rd = (obj: unknown) => new TextEncoder().encode(JSON.stringify(obj));
  const report = (runtime: Uint8Array) => { const r = new Uint8Array(64); r.set(createHash('sha256').update(runtime).digest()); return r; };
  it('rejects a report_data whose upper half is only partly non-zero', () => {
    const r = new Uint8Array(64); r[40] = 1; r[33] = 0; r[63] = 0;
    expect(checkAzureRuntimeDataBinding(r, rd({}), EXP)).toMatch(/not zero/);
    const r2 = new Uint8Array(64); r2[32] = 1;
    expect(checkAzureRuntimeDataBinding(r2, rd({}), EXP)).toMatch(/not zero/);
  });
  it('accepts a bound runtime-data document and reports each failure distinctly', () => {
    const good = rd({ 'user-data': Buffer.from(WANT).toString('hex') });
    expect(checkAzureRuntimeDataBinding(report(good), good, EXP)).toBeUndefined();
    expect(checkAzureRuntimeDataBinding(new Uint8Array(63), good, EXP)).toBe('report_data is not 64 bytes');
    expect(checkAzureRuntimeDataBinding(report(good), rd({}), EXP)).toBe('sha256(runtime data) does not equal the quote report_data');
    const nonJson = new TextEncoder().encode('{');
    expect(checkAzureRuntimeDataBinding(report(nonJson), nonJson, EXP)).toBe('runtime data is not valid JSON');
    for (const v of [[], null, 'x']) { const b = rd(v); expect(checkAzureRuntimeDataBinding(report(b), b, EXP)).toBe('runtime data is not a JSON object'); }
    for (const ud of [undefined, 5, 'ab', 'zz'.repeat(64), 'ab'.repeat(65)]) { const b = rd({ 'user-data': ud }); expect(checkAzureRuntimeDataBinding(report(b), b, EXP)).toBe('runtime data carries no 64-byte hex user-data'); }
    const other = rd({ 'user-data': 'ab'.repeat(64) });
    expect(checkAzureRuntimeDataBinding(report(other), other, EXP)).toMatch(/does not bind holder/);
    expect(checkAzureRuntimeDataBinding(report(good), good, { ...EXP, nonce: '' })).toBe('binding not constructible: binding: nonce required');
  });
});

describe('differential: equalBytes length guard is redundant with Buffer.compare', () => {
  it('Buffer.compare of unequal-length inputs is never 0, so the length test only short-circuits', () => {
    for (const [a, b] of [[[1, 2], [1, 2, 3]], [[1, 2, 3], [1, 2]], [[], [0]], [[0], []]] as Array<[number[], number[]]>) {
      expect(Buffer.compare(Buffer.from(a), Buffer.from(b))).not.toBe(0);
    }
  });
});
