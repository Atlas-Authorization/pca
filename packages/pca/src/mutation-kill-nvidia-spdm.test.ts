/** Mutation-kill tests for attest-nvidia-spdm.ts: byte-exact parser edges (hand-assembled transcripts) and verifier outputs (forged scenario). */
import { createHash, X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createNvidiaSpdmVerifier, formatVbiosVersion, NVIDIA_OPAQUE, parseNvidiaSpdmEvidence, nvidiaSpdmChallenge } from './attest-nvidia-spdm';
import type { ExpectedAttestationBinding } from './attestation';
import { forgeNvidiaScenario, forgeSpdmTranscript, defaultOpaque, goldenDigest } from './test-support/forge-spdm';

// ── hand-assembled transcript ────────────────────────────────────────────────────────────────────
interface Raw { version?: number; param1?: number; param2?: number; slot?: number; numBlocks?: number; recLen?: number; records?: number[]; rnonce?: number; opaque?: number[]; opaqueLen?: number; respVersion?: number; respCode?: number; reqCode?: number }
function raw(o: Raw = {}): Uint8Array {
  const records = o.records ?? [];
  const opaque = o.opaque ?? [];
  const recLen = o.recLen ?? records.length;
  const opaqueLen = o.opaqueLen ?? opaque.length;
  const nonce = new Array(32).fill(0x70);
  const respNonce = new Array(32).fill(o.rnonce ?? 0x71);
  return Uint8Array.from([
    o.version ?? 0x12, o.reqCode ?? 0xe0, o.param1 ?? 0x03, o.param2 ?? 0x04, ...nonce, o.slot ?? 0x05,
    o.respVersion ?? 0x13, o.respCode ?? 0x60, 0, 0, o.numBlocks ?? 0, recLen & 255, (recLen >> 8) & 255, (recLen >> 16) & 255,
    ...records, ...respNonce, opaqueLen & 255, opaqueLen >> 8, ...opaque, ...new Array(96).fill(0x99),
  ]);
}
const blk = (index: number, valueType: number, digest: number[], sizeDelta = 0) => [index, 1, (3 + digest.length + sizeDelta) & 255, (3 + digest.length + sizeDelta) >> 8, valueType, digest.length & 255, digest.length >> 8, ...digest];

describe('parseNvidiaSpdmEvidence: field-exact', () => {
  it('parses the smallest legal transcript (175 bytes) with every header field distinct and non-zero', () => {
    const b = raw();
    expect(b.length).toBe(175);
    const p = parseNvidiaSpdmEvidence(b);
    expect(p.request).toEqual({ version: 0x12, code: 0xe0, param1: 3, param2: 4, nonce: new Uint8Array(32).fill(0x70), slot: 5 });
    expect(p.response.version).toBe(0x13);
    expect(p.response.code).toBe(0x60);
    expect(p.response.numBlocks).toBe(0);
    expect(p.response.measurements).toEqual([]);
    expect(p.response.responderNonce).toEqual(new Uint8Array(32).fill(0x71));
    expect(p.response.opaque.size).toBe(0);
    expect(p.response.signature).toEqual(new Uint8Array(96).fill(0x99));
    expect(p.signedBytes.length).toBe(175 - 96);
    expect(p.signedBytes).toEqual(b.slice(0, 175 - 96));
  });
  it('one byte short is "too short" with the length; non-Uint8Array is a TypeError', () => {
    expect(() => parseNvidiaSpdmEvidence(raw().slice(1))).toThrow(new RangeError('parseNvidiaSpdmEvidence: transcript too short (174)'));
    expect(() => parseNvidiaSpdmEvidence([] as never)).toThrow(new TypeError('parseNvidiaSpdmEvidence: expected Uint8Array'));
    expect(() => parseNvidiaSpdmEvidence(raw({ reqCode: 0xe1 }))).toThrow('request code 0xe1 is not GET_MEASUREMENTS');
    expect(() => parseNvidiaSpdmEvidence(raw({ respCode: 0x61 }))).toThrow('response code is not MEASUREMENTS');
  });
  it('record length: exact fit parses, one more overruns, and the third length byte counts', () => {
    const rec = blk(7, 2, [1, 2, 3]);
    const ok = parseNvidiaSpdmEvidence(raw({ records: rec, numBlocks: 1 }));
    expect(ok.response.measurements).toEqual([{ index: 7, valueType: 2, digest: Uint8Array.of(1, 2, 3) }]);
    expect(() => parseNvidiaSpdmEvidence(raw({ records: rec, numBlocks: 1, recLen: rec.length + 1 }))).toThrow('measurement record length overruns transcript');
    expect(() => parseNvidiaSpdmEvidence(raw({ records: rec, numBlocks: 1, recLen: rec.length + 65536 }))).toThrow('measurement record length overruns transcript');
    expect(() => parseNvidiaSpdmEvidence(raw({ records: rec, numBlocks: 1, recLen: rec.length + 256 }))).toThrow('measurement record length overruns transcript');
  });
  it('block header edge: a record that is exactly one 4-byte header with size 0 is an overrunning block, not a truncated header', () => {
    expect(() => parseNvidiaSpdmEvidence(raw({ records: [1, 1, 0, 0], numBlocks: 1 }))).toThrow('measurement block overruns record');
    expect(() => parseNvidiaSpdmEvidence(raw({ records: [1, 1, 0], numBlocks: 1 }))).toThrow('truncated measurement block header');
  });
  it('block size 3 (empty DMTF value) is legal, 2 is not; a DMTF value larger than its block is refused', () => {
    const p = parseNvidiaSpdmEvidence(raw({ records: [9, 1, 3, 0, 4, 0, 0], numBlocks: 1 }));
    expect(p.response.measurements[0]).toEqual({ index: 9, valueType: 4, digest: new Uint8Array(0) });
    expect(() => parseNvidiaSpdmEvidence(raw({ records: [9, 1, 2, 0, 4, 0], numBlocks: 1 }))).toThrow('measurement block overruns record');
    expect(() => parseNvidiaSpdmEvidence(raw({ records: blk(1, 1, [1, 2], -1), numBlocks: 1 }))).toThrow('DMTF value overruns measurement block');
  });
  it('block count must match the header; opaque TLVs and lengths are exact', () => {
    expect(() => parseNvidiaSpdmEvidence(raw({ records: blk(1, 1, [1]), numBlocks: 2 }))).toThrow('header says 2 blocks, parsed 1');
    const tlv = [6, 0, 2, 0, 0xaa, 0xbb, 3, 0, 1, 0, 0xcc];
    const p = parseNvidiaSpdmEvidence(raw({ opaque: tlv }));
    expect([...p.response.opaque.get(6)!]).toEqual([0xaa, 0xbb]);
    expect([...p.response.opaque.get(3)!]).toEqual([0xcc]);
    expect(() => parseNvidiaSpdmEvidence(raw({ opaque: tlv, opaqueLen: tlv.length + 1 }))).toThrow('opaque length + signature do not exactly fill the transcript');
    expect(() => parseNvidiaSpdmEvidence(raw({ opaque: [6, 0, 9, 0, 1], }))).toThrow('opaque TLV overruns opaque data');
    expect(() => parseNvidiaSpdmEvidence(raw({ opaque: [6, 0, 1] }))).toThrow('truncated opaque TLV header');
  });
});

describe('formatVbiosVersion', () => {
  it('byte-reverses and dots the hex', () => {
    expect(formatVbiosVersion(Uint8Array.from([0x00, 0x9f, 0x00, 0x96, 0x04, 0x00, 0x00, 0x00]))).toBe('96.00.9f.00.04');
  });
});

// ── verifier ────────────────────────────────────────────────────────────────────────────────────────
const EXPECTED: ExpectedAttestationBinding = { holderPub: 'holder-forged-gpu', grantRef: 'grant_forged_gpu', epoch: 3, nonce: 'srv-nonce-gpu-forged' };
const CHALLENGE = nvidiaSpdmChallenge(EXPECTED);
const S = forgeNvidiaScenario({ challenge: CHALLENGE });
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const tx = (over: Partial<Parameters<typeof forgeSpdmTranscript>[0]> = {}) => forgeSpdmTranscript({ signer: S.device.leafKey, challenge: CHALLENGE, opaque: defaultOpaque(), ...over });
const mk = (evidence: Uint8Array | undefined, policy: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) =>
  createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: { 1: hex(goldenDigest(1)) }, ...policy } as never, resolveEvidence: () => (evidence ? { evidence, certChainPem: S.device.chainPem } : undefined), ...extra } as never);
const run = (v: ReturnType<typeof mk>) => v.verify({ document: {} as never, ctx: {} as never, nowMs: S.nowMs, expected: EXPECTED });

describe('createNvidiaSpdmVerifier constructor', () => {
  const f = (o: unknown) => () => createNvidiaSpdmVerifier(o as never);
  const ROOT = 'createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)';
  it('requires a root pin list, with the exact message, for undefined / wrong type / empty', () => {
    expect(f(undefined)).toThrow(ROOT);
    expect(f({ policy: { measurements: { 1: 'a' } } })).toThrow(ROOT);
    expect(f({ rootSpkiSha256: 'x', policy: { measurements: { 1: 'a' } } })).toThrow(ROOT);
    expect(f({ rootSpkiSha256: [], policy: { measurements: { 1: 'a' } } })).toThrow(ROOT);
  });
  it('requires pinned measurements unless a postVerify hook supplies them (then a policy object is still required)', () => {
    expect(f({ rootSpkiSha256: ['a'], policy: {} })).toThrow('policy.measurements must be a NON-EMPTY pinned set');
    expect(f({ rootSpkiSha256: ['a'], policy: { measurements: {} } })).toThrow('NON-EMPTY pinned set');
    expect(f({ rootSpkiSha256: ['a'], policy: {}, postVerify: () => undefined })).not.toThrow();
    expect(f({ rootSpkiSha256: ['a'], postVerify: () => undefined })).toThrow(/deriveIdentity/);
  });
  it('measurement indices must be integers in 0..255', () => {
    const idx = (i: string) => f({ rootSpkiSha256: ['a'], policy: { measurements: { [i]: 'aa' } } });
    expect(idx('0')).not.toThrow();
    expect(idx('255')).not.toThrow();
    for (const bad of ['-1', '256', '1.5', 'x']) expect(idx(bad)).toThrow('measurement index out of range');
  });
});

describe('createNvidiaSpdmVerifier.verify', () => {
  it('success: identity is EMPTY by default, hostAsserted is exact (digest in index order, leaf subject comma-joined, driver / vbios decoded)', async () => {
    const t = tx({ blocks: 3 });
    const r = await run(mk(t.evidence));
    const leaf = new X509Certificate(S.device.certs[0]!.der);
    expect(r.reason).toBeUndefined();
    expect(r).toEqual({
      ok: true,
      bound: true,
      measured: { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: '', operator: '' },
      hostAsserted: {
        attestation_type: 'nvidia-gpu-cc',
        gpu_measurements_sha384: createHash('sha384').update(goldenDigest(1)).update(goldenDigest(2)).update(goldenDigest(3)).digest('hex'),
        leaf_subject: leaf.subject.replace(/\n/g, ', '),
        driver_version: '595.71.05',
        vbios_version: formatVbiosVersion(Uint8Array.from(Buffer.from('009f009604000000', 'hex'))),
      },
    });
    expect(leaf.subject).toContain('\n'); // the join is observable
  });
  it('measurement digest is taken in INDEX order, not transcript order', async () => {
    const t = tx({ measurements: [3, 1, 2].map((i) => ({ index: i, digest: goldenDigest(i) })) });
    const r = await run(mk(t.evidence));
    expect(r.ok).toBe(true);
    expect((r as { hostAsserted: Record<string, string> }).hostAsserted.gpu_measurements_sha384).toBe(createHash('sha384').update(goldenDigest(1)).update(goldenDigest(2)).update(goldenDigest(3)).digest('hex'));
  });
  it('driver version: trailing NULs (all of them) stripped, inner NULs kept; absent driver / vbios add no keys', async () => {
    const withDrv = (v: number[]) => run(mk(tx({ opaque: [[NVIDIA_OPAQUE.DRIVER_VERSION, Uint8Array.from(v)]] }).evidence));
    expect(((await withDrv([0x61, 0, 0x62, 0, 0, 0])) as { hostAsserted: Record<string, string> }).hostAsserted.driver_version).toBe('a\0b');
    const none = (await run(mk(tx({ opaque: [[NVIDIA_OPAQUE.GPU_INFO, Uint8Array.of(1)]] }).evidence))) as { ok: boolean; hostAsserted: Record<string, string> };
    expect(none.ok).toBe(true);
    expect(Object.keys(none.hostAsserted).sort()).toEqual(['attestation_type', 'gpu_measurements_sha384', 'leaf_subject']);
    const onlyDrv = (await run(mk(tx({ opaque: [[NVIDIA_OPAQUE.DRIVER_VERSION, Uint8Array.of(0x31)]] }).evidence))) as { hostAsserted: Record<string, string> };
    expect(onlyDrv.hostAsserted.driver_version).toBe('1');
    expect('vbios_version' in onlyDrv.hostAsserted).toBe(false);
    const onlyVb = (await run(mk(tx({ opaque: [[NVIDIA_OPAQUE.VBIOS_VERSION, Uint8Array.of(1, 2)]] }).evidence))) as { hostAsserted: Record<string, string> };
    expect(onlyVb.hostAsserted.vbios_version).toBe('01.02');
    expect('driver_version' in onlyVb.hostAsserted).toBe(false);
  });
  it('a custom deriveIdentity is used as is', async () => {
    const id = { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'o' };
    expect(((await run(mk(tx().evidence, { deriveIdentity: () => id }))) as { measured: unknown }).measured).toEqual(id);
  });
  it('failure results are whole {ok:false, reason}', async () => {
    const t = tx();
    expect(await run(mk(undefined))).toEqual({ ok: false, reason: 'no NVIDIA GPU evidence for this action' });
    const noPem = createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: { 1: 'aa' } }, resolveEvidence: () => ({ evidence: t.evidence } as never) });
    expect(await run(noPem as never)).toEqual({ ok: false, reason: 'no NVIDIA GPU evidence for this action' });
    expect(await run(mk(t.evidence, { leafSubjectIncludes: 'NOPE' }))).toEqual({ ok: false, reason: "device leaf subject does not contain 'NOPE'" });
    expect(await run(mk(t.evidence, { measurements: { 1: 'aa'.repeat(48) } }))).toEqual({ ok: false, reason: 'measurement block 1 does not match the pinned digest' });
    expect(await run(mk(t.evidence, { measurements: { 200: 'aa' } }))).toEqual({ ok: false, reason: 'measurement block 200 missing from report' });
    expect(await run(mk(tx({ signature: 'bad' }).evidence))).toEqual({ ok: false, reason: 'GPU attestation report signature does not verify under the device identity key' });
    expect(await run(mk(tx({ challenge: new Uint8Array(32) }).evidence))).toEqual({ ok: false, reason: 'SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)' });
    expect((await run(mk(new Uint8Array(10)))).reason).toMatch(/^GPU attestation report parse failed: parseNvidiaSpdmEvidence: transcript too short \(10\)$/);
    const noExp = await mk(t.evidence).verify({ document: {} as never, ctx: {} as never, nowMs: S.nowMs } as never);
    expect(noExp).toEqual({ ok: false, reason: 'no expected attestation binding supplied' });
    const badBinding = await mk(t.evidence).verify({ document: {} as never, ctx: {} as never, nowMs: S.nowMs, expected: { ...EXPECTED, nonce: '' } });
    expect(badBinding.ok).toBe(false);
    expect(badBinding.reason).toMatch(/^binding not constructible: /);
    expect(await mk(t.evidence, {}, { resolveEvidence: undefined }).verify({ document: {} as never, ctx: {} as never, nowMs: 1, expected: EXPECTED })).toEqual({ ok: false, reason: 'no NVIDIA GPU evidence resolver configured (fail closed)' });
    const thrower = createNvidiaSpdmVerifier({ rootSpkiSha256: ['a'], policy: { measurements: { 1: 'aa' } }, resolveEvidence: () => { throw new Error('boom'); } });
    expect(await run(thrower as never)).toEqual({ ok: false, reason: 'nvidia-spdm verification error (fail closed): boom' });
    const strThrower = createNvidiaSpdmVerifier({ rootSpkiSha256: ['a'], policy: { measurements: { 1: 'aa' } }, resolveEvidence: () => { throw 'str'; } });
    expect(await run(strThrower as never)).toEqual({ ok: false, reason: 'nvidia-spdm verification error (fail closed): unknown' });
  });
  it('postVerify rejection reason is returned verbatim, and receives the report, chain and clock', async () => {
    let seen: { nowMs?: number; hasLeaf?: boolean; blocks?: number } = {};
    const v = mk(tx().evidence, {}, { postVerify: (c: { nowMs: number; leaf: unknown; report: { response: { numBlocks: number } } }) => { seen = { nowMs: c.nowMs, hasLeaf: !!c.leaf, blocks: c.report.response.numBlocks }; return 'collateral says no'; } });
    expect(await run(v)).toEqual({ ok: false, reason: 'collateral says no' });
    expect(seen).toEqual({ nowMs: S.nowMs, hasLeaf: true, blocks: 64 });
  });
});
